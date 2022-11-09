use std::{
    ffi::CString,
    fmt,
    fs::{self, read},
    io::Read,
    mem::{size_of_val, zeroed},
    ptr::{null, null_mut},
    str::FromStr,
};

use glob::glob;

use anyhow::{anyhow, Result};
use pelite::{
    image::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_DESCRIPTOR, IMAGE_SUBSYSTEM_NATIVE},
    pe::*,
};

use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

use sha2::{Digest, Sha256};
use winapi::{
    shared::minwindef::{DWORD, LPVOID},
    um::{
        errhandlingapi::GetLastError,
        psapi::{EnumDeviceDrivers, GetDeviceDriverBaseNameA, GetDeviceDriverFileNameA},
    },
};
#[derive(Serialize, Deserialize, Debug)]
struct Import
{
    #[serde(with = "SerHex::<StrictPfx>")]
    va:   u64,
    hint: usize,
    name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Driver
{
    name:  String,
    hash:  String,
    found: Vec<Import>,
}
fn main() -> Result<()>
{
    let checked_imports = vec![
        "MmMapIoSpace",   //Outdated for win > 1803
        "MmMapIoSpaceEx", //Outdated for win > 1803
        "MmMapLockedPages",
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPagesWithReservedMapping",
        "ZwMapViewOfSection",
        //"IoCreateDevice",
        //"MmCopyVirtualMemory",
        "MmCopyMemory",
        "EnumerateDebuggingDevices",
    ];

    let mut hasher = Sha256::new();
    let drivers: Vec<_> = glob("drv/**/*.sys")?.filter_map(|file| file.ok()).collect();
    let mut found_drivers: Vec<Driver> = Vec::new();
    fs::create_dir("output");
    println!("Drivers found: {:#?}", drivers);

    for drv in drivers
    {
        let file = read(drv.clone())?;
        let pe_file = PeFile::from_bytes(&file);

        if pe_file.is_err()
        {
            println!("BadMagic for {:?}", drv);
            continue;
        }

        let pe_file = pe_file?;

        let nt_headers = pe_file.nt_headers();
        if nt_headers.OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE
        {
            println!("Subsystem not native");
            continue;
        }

        let imports = pe_file.imports();
        if imports.is_err()
        {
            println!("Couldnt get imports for {:?}", drv);
            continue;
        }

        let imports = imports.unwrap();
        for desc in imports
        {
            if desc.dll_name()?.to_str()? != "ntoskrnl.exe"
            {
                continue;
            }

            let mut found_imports: Vec<Import> = Vec::new();
            for (va, import) in Iterator::zip(desc.iat()?, desc.int()?)
            {
                if let Ok(import) = import
                {
                    match import
                    {
                        pelite::pe64::imports::Import::ByName { hint, name } =>
                        {
                            if checked_imports.contains(&name.to_str()?)
                            {
                                found_imports.push(Import {
                                    va:   *va,
                                    hint: hint,
                                    name: name.to_string(),
                                });
                            }
                        }
                        _ =>
                        {}
                    }
                }
            }

            if !found_imports.is_empty()
            {
                hasher.update(&file.clone());
                found_drivers.push(Driver {
                    name:  drv.to_string_lossy().to_string(),
                    hash:  String::from_str(&format!("{:x}", hasher.finalize_reset()))?,
                    found: found_imports,
                });
            }

            fs::write(
                format!("output/{}", drv.file_name().unwrap().to_str().unwrap()),
                file.to_owned(),
            )?;
        }
    }
    let json = serde_json::to_string_pretty(&found_drivers)?;
    fs::write("results.json", json)?;
    Ok(())
}

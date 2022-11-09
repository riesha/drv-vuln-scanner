# drv-vuln-scanner

Vulnerable driver scanning tool for win64, put drivers to scan in `drv/`.

# notes

`MmMapIoSpace` needs other functions like `MmMapLockedPages` to map physmem

`MmCopyMemory` lets you map physmem w `MM COPY MEMORY PHYSICAL` flags

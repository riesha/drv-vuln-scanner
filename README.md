# drv-vuln-scanner

Vulnerable driver scanning tool for win64, put drivers to scan in `drv/`. Finds imports that could be exploited, still requires manual analysis.

# notes

`checked_imports` is just what i was looking for, there's a lot of other potentially exploitable imports you can check for.

`MmMapIoSpace` needs other functions like `MmMapLockedPages` to map physmem

`MmCopyMemory` lets you map physmem w `MM COPY MEMORY PHYSICAL` flags

`results.json` is a scan of some drivers i could find.

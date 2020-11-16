# PETri
Portable Executable (PE) malware static analysis.

#### Description:

PETri is used to assist with Portable Executable (PE) binary (.exe, dll, etc) malware static analysis.

#### Artefacts Supported:

- Metadata
- PE Header
- File Properties
- Hashing
- COFF File Header
- Optional Header
- Sections
- Data Directories
- Imports
- Exports

#### Usage:

```
python PETri.py <binary>
```

#### Requirements:
- DateTime == 4.3
- hexdump == 3.3
- pefile == 2019.4.18

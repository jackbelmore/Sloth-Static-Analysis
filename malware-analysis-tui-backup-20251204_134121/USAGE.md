# Quick Start Guide

## Test Scripts Available

### `./test_pe.sh` - Default test with notepad.exe
```bash
./test_pe.sh
```

### Analyze a specific PE file
```bash
./test_pe.sh /path/to/file.exe
```

### Direct CLI usage
```bash
# Fast analysis
python cli.py /path/to/file.exe

# Full async analysis (requires capa rules)
python cli.py /path/to/file.exe --async

# JSON output
python cli.py /path/to/file.exe --json
```

### Interactive TUI
```bash
# Launch with default directory
python tui.py

# Launch with custom directory
python tui.py /mnt/c/Windows/System32
```

## About Boom3D.msi

**Important:** MSI files (Microsoft Installer packages) are **not PE executables**. They are OLE Compound Document files that *contain* PE files.

To analyze the executables inside Boom3D.msi, you would need to:

1. Extract the MSI contents:
```bash
# Install msitools if not available
sudo apt install msitools

# Extract MSI
msiextract /mnt/c/Users/Box/Desktop/Boom3D.msi -C /tmp/boom3d_extracted

# Find PE files inside
find /tmp/boom3d_extracted -name "*.exe" -o -name "*.dll"
```

2. Then analyze the extracted PE files:
```bash
./test_pe.sh /tmp/boom3d_extracted/some_file.exe
```

## Supported File Types

✅ **Supported (PE files):**
- `.exe` - Executables
- `.dll` - Dynamic Link Libraries
- `.sys` - System drivers
- `.ocx` - ActiveX controls
- `.scr` - Screen savers

❌ **Not Supported:**
- `.msi` - MSI installer packages (contains PE files)
- `.zip`, `.rar`, `.7z` - Archives (contains files)
- `.pdf`, `.doc`, `.xls` - Documents (may contain embedded objects)

## Examples

```bash
# Analyze Windows calculator
./test_pe.sh /mnt/c/Windows/System32/calc.exe

# Analyze a DLL
./test_pe.sh /mnt/c/Windows/System32/kernel32.dll

# Launch TUI to browse and analyze
python tui.py /mnt/c/Windows/System32
```

## Quick Feature Overview

- **Hashes**: MD5, SHA1, SHA256
- **Metadata**: Architecture, compile time, entry point
- **Sections**: Name, size, entropy, permissions (RWX), suspicious flags
- **Imports**: DLL dependencies, function names, suspicious API detection
- **Suspicious Indicators**:
  - Sections with W+X permissions
  - High entropy (>7.0) in executable sections
  - Dangerous APIs (VirtualAlloc, CreateRemoteThread, IsDebuggerPresent, etc.)

## Need Help?

- Read full documentation in `README.md`
- See architecture details in `ARCHITECTURE.md`
- Check the source code in `malview/` directory

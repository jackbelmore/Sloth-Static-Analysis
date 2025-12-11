# Malware Analysis TUI

A Text User Interface (TUI) for static analysis of Windows PE files, built with [Textual](https://textual.textualize.io/).

## Features

- **Fast Data Analysis** (synchronous via pefile):
  - File hashes (MD5, SHA1, SHA256)
  - PE metadata (architecture, compile time, entry point)
  - Section analysis with entropy calculation
  - Import table parsing with suspicious API detection

- **Slow Data Analysis** (asynchronous via external tools):
  - Capability detection (capa - FLARE capability detector)
  - Obfuscated string extraction (floss - FLARE obfuscated string solver)

- **Interactive TUI**:
  - File browser sidebar
  - Tabbed interface (Overview, Sections, Imports)
  - Real-time analysis

## Installation

### Windows (PowerShell)

```powershell
# Clone
git clone https://github.com/jackbelmore/Sloth-Static-Analysis.git
cd Sloth-Static-Analysis

# Create venv
py -3 -m venv venv-win

# Activate
.\venv-win\Scripts\activate

# Upgrade tooling (recommended)
python -m pip install --upgrade pip setuptools wheel

# Install core deps (binary wheels only; avoids needing build tools)
pip install --only-binary=:all: -r requirements.txt

# Optional async tools
# Try wheels first; if build fails, install Microsoft C++ Build Tools or skip
pip install --only-binary=:all: flare-capa flare-floss
```

### Linux (bash)

```bash
# Clone
git clone https://github.com/jackbelmore/Sloth-Static-Analysis.git
cd Sloth-Static-Analysis

# Create venv
python3 -m venv venv

# Activate
source venv/bin/activate

# Install deps
pip install -r requirements.txt

# Optional async tools
pip install flare-capa flare-floss
```

### Uninstall / Cleanup (Windows)

```powershell
deactivate  # if venv active
Remove-Item -Recurse -Force .\venv-win
```

### Uninstall / Cleanup (Linux)

```bash
deactivate  # if venv active
rm -rf venv
```

## Usage

### CLI Mode

```bash
# Fast analysis (pefile only)
python cli.py /path/to/file.exe

# Full async analysis (includes capa and floss)
python cli.py /path/to/file.exe --async

# JSON output
python cli.py /path/to/file.exe --json
```

### TUI Mode

```bash
# Launch TUI with default directory
python tui.py

# Launch TUI with custom start directory
python tui.py /mnt/c/Windows/System32
```

**TUI Controls:**
- Browse and select files from the left sidebar
- Click files ending in `.exe`, `.dll`, or `.sys` to analyze
- Switch between tabs to view different analysis sections
- Press `q` to quit
- Press `r` to refresh the file tree

## Architecture

This tool follows the **Hybrid Engine** pattern:

- **Fast Data** (synchronous): Extracted immediately using pefile
  - File hashes, metadata, sections, imports
  - Displayed instantly in TUI

- **Slow Data** (asynchronous): Extracted in background using external tools
  - Capabilities (capa), strings (floss)
  - Updates TUI progressively as data arrives

## External Tools

### Capa (Optional)

Capa requires rule files to function. To use capa:

```bash
# Download capa rules
wget https://github.com/mandiant/capa-rules/releases/latest/download/capa-rules.zip
unzip capa-rules.zip -d ~/.capa-rules

# Run analysis with rules
capa -r ~/.capa-rules /path/to/file.exe
```

### Floss (Optional)

Floss works out of the box but may not find strings in all files:
- Legitimate Windows binaries often have no obfuscated strings
- Packed malware will show decoded strings

## Project Structure

```
malware-analysis-tui/
├── cli.py                      # CLI entry point
├── tui.py                      # TUI entry point
├── requirements.txt            # Dependencies
├── malview/                    # Main package
│   ├── __init__.py            # Public API
│   ├── models.py              # Data classes
│   ├── engine.py              # PE analysis engine
│   ├── tools.py               # Async tool wrappers
│   ├── exceptions.py          # Custom exceptions
│   └── utils.py               # Utilities (entropy, hashing)
└── ARCHITECTURE.md            # Design documentation
```

## Development

The project is built in phases:

- **Phase 1**: Data engine with fast (sync) data ✓
- **Phase 2**: TUI skeleton + async tool integration (in progress)
- **Phase 3**: Advanced features (caching, batch analysis, reports)

## License

MIT License

## Credits

- Built with [Textual](https://textual.textualize.io/)
- Uses [pefile](https://github.com/erocarrera/pefile) for PE parsing
- Integrates with [FLARE capa](https://github.com/mandiant/capa) and [FLARE floss](https://github.com/mandiant/flare-floss)

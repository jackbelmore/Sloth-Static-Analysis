# Malware Analysis TUI - Architecture & Spec

## 1. Project Goal
Create a TUI (Textual) application for static analysis of Windows PE files.
It acts as an orchestrator: using Python libraries for fast analysis and wrapping external tools (capa, floss) for deep analysis.

## 2. Tech Stack
- **Language:** Python 3.11+
- **TUI:** Textual (Must be reactive and async)
- **Core Library:** `pefile` (Headers, sections, imports)
- **External Tools:** `capa` (Capabilities), `floss` (Strings). MUST use JSON output.

## 3. Hybrid Engine Pattern
The engine must support two speeds of data to prevent UI freezing:
1.  **Fast Data (Sync):** Available immediately via libraries (Hashes, Architecture, Sections, Imports).
2.  **Slow Data (Async):** Populated later via external tool execution (Capabilities, Strings).

## 4. Data Model (Guideline)
A single `ScanResult` object should hold the state.
- `hashes`: Dict[str, str]
- `sections`: List[SectionInfo] (Name, VA, Size, Entropy, RWX)
- `imports`: List[ImportInfo] (DLL, Functions)
- `capabilities`: List[Capability] (from capa)
- `strings`: List[StringFinding] (from floss)

## 5. UI Layout (Textual)
- **Sidebar:** File list.
- **Main Area:** `TabbedContent`.
    - *Overview:* Basic info + Suspicious Flags (Red).
    - *Sections:* DataTable of sections. High entropy/RWX highlighted.
    - *Imports:* Tree/Table of DLLs and APIs.
    - *Capabilities:* Async loader -> Table of findings.
    - *Strings:* Async loader -> Filterable list.

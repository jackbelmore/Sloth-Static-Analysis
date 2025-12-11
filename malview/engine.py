"""Core PE analysis engine using pefile."""

import asyncio
import os
from datetime import datetime
from typing import Dict, List, Optional

import pefile

from .models import (
    ScanResult,
    PEMetadata,
    SectionInfo,
    ImportInfo,
    Capability,
    StringFinding,
    YaraMatch,
)
from .exceptions import FileNotFoundError, InvalidPEFileError
from .utils import calculate_entropy, calculate_hashes
from .tools import run_capa_async, run_floss_async, ToolNotFoundError, ToolExecutionError
from .yara_scanner import YaraScanner


class PEEngine:
    """
    Stateless PE analysis engine.

    Implements the 'Fast Data' portion of the Hybrid Engine pattern,
    extracting synchronous data using pefile library.
    """

    def __init__(self):
        """Initialize PE engine with YARA scanner."""
        try:
            self.yara_scanner = YaraScanner()
        except Exception as e:
            print(f"Warning: YARA scanner initialization failed: {e}")
            self.yara_scanner = None

    def analyze(self, file_path: str) -> ScanResult:
        """
        Analyze a PE file and extract fast (synchronous) data.

        Args:
            file_path: Path to the PE file to analyze

        Returns:
            Complete ScanResult with all fast data populated

        Raises:
            FileNotFoundError: If file doesn't exist
            InvalidPEFileError: If file is not a valid PE
        """
        # Validate file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Load PE file
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError as e:
            raise InvalidPEFileError(f"Invalid PE file: {e}")

        # Extract all fast data
        hashes = self._extract_hashes(file_path)
        metadata = self._extract_metadata(pe, file_path)
        sections = self._extract_sections(pe, file_path)
        imports = self._extract_imports(pe)

        # Close PE file
        pe.close()

        # Run YARA scan (fast - pattern matching)
        yara_matches = None
        if self.yara_scanner:
            try:
                scanner_matches = self.yara_scanner.scan(file_path)
                if scanner_matches:
                    yara_matches = [
                        YaraMatch(
                            rule_name=match.rule_name,
                            namespace=match.namespace,
                            tags=match.tags,
                            meta=match.meta
                        )
                        for match in scanner_matches
                    ]
            except Exception as e:
                print(f"Warning: YARA scan failed: {e}")

        return ScanResult(
            file_path=file_path,
            hashes=hashes,
            metadata=metadata,
            sections=sections,
            imports=imports,
            capabilities=None,  # Async (capa)
            strings=None,  # Async (floss)
            yara_matches=yara_matches,  # Sync (fast pattern matching)
        )

    async def analyze_async(
        self,
        file_path: str,
        show_progress: bool = True,
        fast_capa: bool = False,
    ) -> ScanResult:
        """
        Analyze a PE file with both fast (sync) and slow (async) data.

        This method follows the Hybrid Engine pattern:
        1. Extract fast data synchronously (pefile)
        2. Extract slow data asynchronously (capa, floss)

        Args:
            file_path: Path to the PE file to analyze
            show_progress: Whether to show progress bar

        Returns:
            Complete ScanResult with all data populated

        Raises:
            FileNotFoundError: If file doesn't exist
            InvalidPEFileError: If file is not a valid PE
        """
        # First, get the fast data using synchronous analysis
        result = self.analyze(file_path)

        # Get file size for progress estimation
        file_size = os.path.getsize(file_path)

        # Rough phase timing hints to keep the bar moving realistically
        size_mb = max(file_size / 1_000_000, 1.0)
        # Phase timing hints and timeouts (seconds)
        if fast_capa:
            phase_time_hints = {
                "pe": 0.5,
                "yara": 1.0,
                "capa": max(10.0, size_mb * 3.0),
                "floss": max(12.0, size_mb * 3.0),
            }
            capa_timeout = max(90.0, size_mb * 20.0)
            floss_timeout = max(90.0, size_mb * 20.0)
        else:
            phase_time_hints = {
                "pe": 0.5,
                "yara": 1.0,
                "capa": max(30.0, size_mb * 8.0),   # give vivisect more breathing room
                "floss": max(20.0, size_mb * 5.0),
            }
            capa_timeout = max(300.0, size_mb * 40.0)
            floss_timeout = max(120.0, size_mb * 30.0)

        async def wrap_tool(phase_name: str, coro, progress=None):
            if progress:
                progress.start_phase(phase_name)
            try:
                return await coro
            except Exception as exc:
                return exc
            finally:
                if progress:
                    progress.mark_phase_completed(phase_name)

        # Run slow tools in parallel
        async def run_tools(progress=None):
            capabilities_data = []
            strings_data = []

            try:
                capa_task = asyncio.create_task(
                    wrap_tool(
                        "capa",
                        run_capa_async(
                            file_path,
                            timeout=capa_timeout,
                            allow_fallback=not fast_capa,  # fast mode skips fallbacks
                        ),
                        progress,
                    )
                )
                floss_task = asyncio.create_task(
                    wrap_tool("floss", run_floss_async(file_path, timeout=floss_timeout), progress)
                )

                # Wait for both to complete
                capa_results, floss_results = await asyncio.gather(capa_task, floss_task)

                # Process capa results
                if isinstance(capa_results, list):
                    capabilities_data = [
                        Capability(
                            namespace=cap["namespace"],
                            name=cap["name"],
                            description=cap["description"],
                            matches=cap["matches"],
                        )
                        for cap in capa_results
                    ]
                elif isinstance(capa_results, Exception):
                    # Log or handle capa failure
                    print(f"Warning: capa failed: {capa_results}")

                # Process floss results
                if isinstance(floss_results, list):
                    strings_data = [
                        StringFinding(
                            string=finding["string"],
                            type=finding["type"],
                            address=finding.get("address"),
                        )
                        for finding in floss_results
                    ]
                elif isinstance(floss_results, Exception):
                    # Log or handle floss failure
                    print(f"Warning: floss failed: {floss_results}")

            except Exception as e:
                print(f"Warning: async tool execution failed: {e}")

            return capabilities_data, strings_data

        # Run tools with or without progress bar
        if show_progress:
            from .progress import run_with_progress

            capabilities, strings = await run_with_progress(
                file_path,
                file_size,
                lambda progress: run_tools(progress),
                phase_time_hints=phase_time_hints,
            )
        else:
            capabilities, strings = await run_tools()

        # Update result with slow data
        result.capabilities = capabilities if capabilities else None
        result.strings = strings if strings else None

        return result

    def _extract_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes."""
        return calculate_hashes(file_path)

    def _extract_metadata(self, pe: pefile.PE, file_path: str) -> PEMetadata:
        """
        Extract basic PE metadata from headers.

        Args:
            pe: Loaded pefile.PE object
            file_path: Path to the file (for size calculation)

        Returns:
            PEMetadata with basic file information
        """
        file_size = os.path.getsize(file_path)

        # Determine architecture
        machine_type = pe.FILE_HEADER.Machine
        if machine_type == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            architecture = "x86"
            is_64bit = False
        elif machine_type == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            architecture = "x64"
            is_64bit = True
        else:
            architecture = f"unknown (0x{machine_type:x})"
            is_64bit = False

        # Parse compile time
        compile_time = None
        timestamp = pe.FILE_HEADER.TimeDateStamp
        if timestamp:
            try:
                compile_time = datetime.fromtimestamp(timestamp).isoformat()
            except (ValueError, OSError):
                compile_time = None

        # Check if DLL
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

        # Get entry point
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        return PEMetadata(
            file_size=file_size,
            architecture=architecture,
            compile_time=compile_time,
            is_dll=is_dll,
            is_64bit=is_64bit,
            entry_point=entry_point,
        )

    def _extract_sections(self, pe: pefile.PE, file_path: str) -> List[SectionInfo]:
        """
        Extract section information with entropy calculation.

        Args:
            pe: Loaded pefile.PE object
            file_path: Path to the file (for reading raw section data)

        Returns:
            List of SectionInfo objects
        """
        sections = []

        for section in pe.sections:
            # Parse section name (remove null bytes and decode)
            name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')

            # Get addresses and sizes
            virtual_address = section.VirtualAddress
            virtual_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData

            # Calculate entropy from raw section data
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)

            # Parse characteristics to R/W/X flags
            characteristics = []
            char_flags = section.Characteristics
            if char_flags & 0x40000000:  # IMAGE_SCN_MEM_READ
                characteristics.append("R")
            if char_flags & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                characteristics.append("W")
            if char_flags & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                characteristics.append("X")

            sections.append(SectionInfo(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_size=raw_size,
                entropy=entropy,
                characteristics=characteristics,
            ))

        return sections

    def _extract_imports(self, pe: pefile.PE) -> List[ImportInfo]:
        """
        Extract import table information.

        Args:
            pe: Loaded pefile.PE object

        Returns:
            List of ImportInfo objects grouped by DLL
        """
        imports = []

        # Check if PE has import directory
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            functions = []

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    functions.append(func_name)
                else:
                    # Import by ordinal
                    functions.append(f"Ordinal_{imp.ordinal}")

            imports.append(ImportInfo(
                dll_name=dll_name,
                functions=functions,
            ))

        return imports

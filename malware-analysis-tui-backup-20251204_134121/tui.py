#!/usr/bin/env python3
"""Textual TUI for PE malware analysis."""

from pathlib import Path
from textual.app import App, ComposeResult
from textual.widgets import (
    Header,
    Footer,
    Static,
    TabbedContent,
    TabPane,
    DataTable,
    DirectoryTree,
    Label,
)
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.binding import Binding
from textual.reactive import reactive

from malview import PEEngine, ScanResult, MalviewError


class OverviewPanel(ScrollableContainer):
    """Overview tab showing metadata and hashes."""

    result: reactive[ScanResult | None] = reactive(None)

    def compose(self) -> ComposeResult:
        yield Static("Select a PE file to analyze", id="overview-content")

    def watch_result(self, result: ScanResult | None) -> None:
        """Update overview when result changes."""
        if result is None:
            return

        content = self.query_one("#overview-content", Static)

        # Format overview text
        lines = []
        lines.append(f"[bold cyan]FILE:[/bold cyan] {result.file_path}")
        lines.append("")

        # Metadata
        lines.append("[bold yellow]METADATA[/bold yellow]")
        lines.append(f"  Size:         {result.metadata.file_size:,} bytes")
        lines.append(f"  Architecture: {result.metadata.architecture}")
        lines.append(f"  Compile Time: {result.metadata.compile_time or 'N/A'}")
        lines.append(f"  Type:         {'DLL' if result.metadata.is_dll else 'EXE'}")
        lines.append(f"  Entry Point:  0x{result.metadata.entry_point:08x}")
        lines.append("")

        # Hashes
        lines.append("[bold yellow]HASHES[/bold yellow]")
        lines.append(f"  MD5:    {result.hashes['md5']}")
        lines.append(f"  SHA1:   {result.hashes['sha1']}")
        lines.append(f"  SHA256: {result.hashes['sha256']}")
        lines.append("")

        # Suspicious indicators
        lines.append("[bold yellow]SUSPICIOUS INDICATORS[/bold yellow]")
        if not result.has_suspicious_indicators():
            lines.append("  [green]No suspicious indicators detected[/green]")
        else:
            suspicious_sections = result.get_suspicious_sections()
            suspicious_imports = result.get_suspicious_imports()

            if suspicious_sections:
                lines.append(f"  [red]⚠ {len(suspicious_sections)} suspicious section(s)[/red]")
            if suspicious_imports:
                lines.append(f"  [red]⚠ {len(suspicious_imports)} DLL(s) with suspicious APIs[/red]")

        content.update("\n".join(lines))


class SectionsPanel(Container):
    """Sections tab with DataTable."""

    result: reactive[ScanResult | None] = reactive(None)

    def compose(self) -> ComposeResult:
        yield DataTable(id="sections-table")

    def on_mount(self) -> None:
        """Set up the table columns."""
        table = self.query_one("#sections-table", DataTable)
        table.add_columns("Name", "VA", "VSize", "RawSize", "Entropy", "RWX", "Suspicious")

    def watch_result(self, result: ScanResult | None) -> None:
        """Update table when result changes."""
        if result is None:
            return

        table = self.query_one("#sections-table", DataTable)
        table.clear()

        for section in result.sections:
            rwx = "".join(section.characteristics) if section.characteristics else "---"
            suspicious = "⚠ YES" if section.is_suspicious() else ""

            table.add_row(
                section.name,
                f"0x{section.virtual_address:08x}",
                f"0x{section.virtual_size:08x}",
                f"0x{section.raw_size:08x}",
                f"{section.entropy:.4f}",
                rwx,
                suspicious,
            )


class ImportsPanel(ScrollableContainer):
    """Imports tab with import list."""

    result: reactive[ScanResult | None] = reactive(None)

    def compose(self) -> ComposeResult:
        yield Static("No imports loaded", id="imports-content")

    def watch_result(self, result: ScanResult | None) -> None:
        """Update imports when result changes."""
        if result is None:
            return

        content = self.query_one("#imports-content", Static)
        lines = []

        for imp in result.imports:
            marker = "[red]⚠[/red]" if imp.is_suspicious() else " "
            lines.append(f"{marker} [bold]{imp.dll_name}[/bold] ({len(imp.functions)} functions)")

            # Show first 10 functions
            for func in imp.functions[:10]:
                lines.append(f"    - {func}")

            if len(imp.functions) > 10:
                lines.append(f"    [dim]... and {len(imp.functions) - 10} more[/dim]")
            lines.append("")

        content.update("\n".join(lines) if lines else "No imports found")


class MalwareAnalysisTUI(App):
    """TUI for PE malware analysis."""

    CSS = """
    Screen {
        layout: horizontal;
    }

    #file-tree {
        width: 30%;
        border-right: solid $primary;
    }

    #main-panel {
        width: 70%;
    }

    #overview-content {
        padding: 1 2;
    }

    #imports-content {
        padding: 1 2;
    }

    #sections-table {
        height: 100%;
    }

    TabbedContent {
        height: 100%;
    }

    TabPane {
        padding: 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh_tree", "Refresh"),
    ]

    TITLE = "Malware Analysis TUI"
    SUB_TITLE = "PE File Static Analysis"

    def __init__(self, start_path: str = "/mnt/c/Windows/System32"):
        super().__init__()
        self.start_path = start_path
        self.engine = PEEngine()

    def compose(self) -> ComposeResult:
        yield Header()
        yield Horizontal(
            DirectoryTree(self.start_path, id="file-tree"),
            Vertical(
                TabbedContent(
                    TabPane("Overview", OverviewPanel()),
                    TabPane("Sections", SectionsPanel()),
                    TabPane("Imports", ImportsPanel()),
                    id="tabs",
                ),
                id="main-panel",
            ),
        )
        yield Footer()

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection from tree."""
        file_path = str(event.path)

        # Only analyze PE files
        if not file_path.lower().endswith(('.exe', '.dll', '.sys')):
            self.notify(f"Not a PE file: {Path(file_path).name}", severity="warning")
            return

        self.analyze_file(file_path)

    def analyze_file(self, file_path: str) -> None:
        """Analyze a PE file and update panels."""
        self.notify(f"Analyzing: {Path(file_path).name}...")

        try:
            result = self.engine.analyze(file_path)

            # Update all panels with the result
            overview = self.query_one(OverviewPanel)
            sections = self.query_one(SectionsPanel)
            imports = self.query_one(ImportsPanel)

            overview.result = result
            sections.result = result
            imports.result = result

            # Show success notification
            status = "⚠ SUSPICIOUS" if result.has_suspicious_indicators() else "✓ Clean"
            self.notify(f"{status}: {Path(file_path).name}", severity="information")

        except MalviewError as e:
            self.notify(f"Error: {e}", severity="error")
        except Exception as e:
            self.notify(f"Unexpected error: {e}", severity="error")

    def action_refresh_tree(self) -> None:
        """Refresh the file tree."""
        tree = self.query_one(DirectoryTree)
        tree.reload()
        self.notify("Tree refreshed", severity="information")


if __name__ == "__main__":
    import sys

    # Allow custom start path
    start_path = sys.argv[1] if len(sys.argv) > 1 else "/mnt/c/Windows/System32"

    app = MalwareAnalysisTUI(start_path=start_path)
    app.run()

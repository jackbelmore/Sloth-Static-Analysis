#!/usr/bin/env python3
"""CLI interface for PE analysis engine."""

import argparse
import asyncio
import sys

from malview import PEEngine, MalviewError


def format_simple(result):
    """Format scan result in simple mode with risk assessment and categorized info."""
    output = []
    risk = result.assess_risk()

    # Header
    output.append("=" * 80)
    output.append(f"PE MALWARE ANALYSIS: {result.file_path}")
    output.append("=" * 80)
    output.append("")

    # Risk Assessment (Executive Summary)
    output.append(f"{risk.get_emoji()} RISK ASSESSMENT")
    output.append("-" * 80)
    output.append(f"  Overall Risk: {risk.risk_level} (Score: {risk.score}/100)")
    output.append(f"  {risk.summary}")
    output.append("")

    # Anomalies (if any)
    if risk.anomalies:
        output.append(f"  {len(risk.anomalies)} Suspicious Indicators Found:")
        for anomaly in risk.anomalies:
            output.append(f"    {anomaly.emoji} {anomaly.description}")
        output.append("")

    # YARA Matches (if any - high priority)
    if result.yara_matches:
        output.append("🎯 YARA DETECTIONS")
        output.append("-" * 80)
        output.append(f"  {len(result.yara_matches)} YARA rule(s) matched:")
        for match in result.yara_matches[:10]:  # Show first 10
            namespace_emoji = {
                "malware": "🚨",
                "packer": "📦",
                "exploit": "💥",
                "antidebug": "🛡️",
                "crypto": "🔐"
            }.get(match.namespace, "⚠️")
            output.append(f"    {namespace_emoji} [{match.namespace}] {match.rule_name}")
            if match.meta:
                desc = match.meta.get("description", "")
                if desc:
                    output.append(f"        {desc}")
        if len(result.yara_matches) > 10:
            output.append(f"    ... and {len(result.yara_matches) - 10} more")
        output.append("")

    # File Overview
    output.append("📋 FILE OVERVIEW")
    output.append("-" * 80)
    output.append(f"  Size:         {result.metadata.file_size:,} bytes")
    output.append(f"  Type:         {result.metadata.architecture} {'DLL' if result.metadata.is_dll else 'EXE'}")

    # Highlight fake timestamp
    if result.metadata.has_fake_timestamp():
        output.append(f"  📅 Compile Time: {result.metadata.compile_time}  [SUSPICIOUS - Invalid timestamp]")
    else:
        output.append(f"  Compile Time: {result.metadata.compile_time or 'N/A'}")

    output.append("")
    output.append(f"  MD5:    {result.hashes['md5']}")
    output.append(f"  SHA256: {result.hashes['sha256'][:64]}...")
    output.append("")

    # Capabilities Summary (categorized)
    if result.capabilities:
        output.append("🎯 CAPABILITIES DETECTED")
        output.append("-" * 80)
        categories = result.categorize_capabilities()

        # Show summary with counts
        output.append(f"  Total: {len(result.capabilities)} capabilities across {len(categories)} categories")
        output.append("")

        for category, caps in sorted(categories.items()):
            emoji = {
                "File System": "📁",
                "Process Control": "⚙️",
                "Registry": "🗝️",
                "Network": "🌐",
                "Encoding/Crypto": "🔐",
                "Anti-Analysis": "🛡️",
                "Persistence": "📌",
                "Code Injection": "💉",
                "Data Collection": "📊",
                "PE Manipulation": "🔧",
                "Other": "❓"
            }.get(category, "•")

            output.append(f"  {emoji} {category} ({len(caps)}):")
            # Show first 3 capabilities in each category
            for cap in caps[:3]:
                output.append(f"      - {cap.name}")
            if len(caps) > 3:
                output.append(f"      ... and {len(caps) - 3} more")
            output.append("")

    # Sections Summary
    output.append("📦 SECTIONS")
    output.append("-" * 80)
    suspicious_sections = result.get_suspicious_sections()
    output.append(f"  Total: {len(result.sections)} sections, {len(suspicious_sections)} suspicious")
    if suspicious_sections:
        output.append("")
        output.append("  Suspicious sections:")
        for sec in suspicious_sections:
            reasons = []
            if "W" in sec.characteristics and "X" in sec.characteristics:
                reasons.append("W+X")
            if sec.entropy > 7.0:
                reasons.append(f"high entropy ({sec.entropy:.2f})")
            output.append(f"    🚨 {sec.name}: {', '.join(reasons)}")
    output.append("")

    # Imports Summary
    output.append("🔗 IMPORTS")
    output.append("-" * 80)
    suspicious_imports = result.get_suspicious_imports()
    output.append(f"  Total: {len(result.imports)} DLLs, {len(suspicious_imports)} with suspicious APIs")
    if suspicious_imports:
        output.append("")
        output.append("  Suspicious imports:")
        for imp in suspicious_imports[:5]:
            # Find specific suspicious functions
            suspicious_funcs = [f for f in imp.functions if any(
                api in f for api in ['VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory',
                                     'IsDebuggerPresent', 'LoadLibrary', 'GetProcAddress',
                                     'CreateProcess', 'RegSetValue', 'InternetOpen']
            )]
            if suspicious_funcs:
                output.append(f"    🔧 {imp.dll_name}: {', '.join(suspicious_funcs[:3])}")
            else:
                output.append(f"    ⚠️ {imp.dll_name}")
        if len(suspicious_imports) > 5:
            output.append(f"    ... and {len(suspicious_imports) - 5} more")
    output.append("")

    # VirusTotal enrichment (if available)
    if result.vt_report:
        vt = result.vt_report
        output.append("VT (VIRUSTOTAL)")
        output.append("-" * 80)
        output.append(
            f"  Detections - Malicious: {vt.malicious}, Suspicious: {vt.suspicious}, "
            f"Harmless: {vt.harmless}, Undetected: {vt.undetected}"
        )
        if vt.reputation is not None:
            output.append(f"  Reputation: {vt.reputation}")
        if vt.tags:
            output.append(f"  Tags: {', '.join(vt.tags[:15])}")
        output.append("")
    elif result.vt_status == "not_found":
        output.append("VT (VIRUSTOTAL)")
        output.append("-" * 80)
        output.append("  No VirusTotal record found for this hash.")
        output.append("")

    # Footer
    output.append("=" * 80)
    output.append("TIP: Use --verbose flag for detailed analysis with all capabilities and imports")
    output.append("=" * 80)

    return "\n".join(output)


def format_verbose(result):
    """Format scan result with full details (verbose mode)."""
    output = []
    risk = result.assess_risk()

    # Header
    output.append("=" * 80)
    output.append(f"PE ANALYSIS REPORT: {result.file_path}")
    output.append("=" * 80)
    output.append("")

    # Risk Assessment
    output.append(f"{risk.get_emoji()} RISK ASSESSMENT")
    output.append("-" * 80)
    output.append(f"  Overall Risk: {risk.risk_level} (Score: {risk.score}/100)")
    output.append(f"  {risk.summary}")
    if risk.anomalies:
        output.append(f"  Anomalies detected: {len(risk.anomalies)}")
    output.append("")

    # File Metadata
    output.append("FILE METADATA")
    output.append("-" * 80)
    output.append(f"  Size:         {result.metadata.file_size:,} bytes")
    output.append(f"  Architecture: {result.metadata.architecture}")

    # Highlight fake timestamp
    if result.metadata.has_fake_timestamp():
        output.append(f"  📅 Compile Time: {result.metadata.compile_time}  [⚠️ SUSPICIOUS - Invalid timestamp]")
    else:
        output.append(f"  Compile Time: {result.metadata.compile_time or 'N/A'}")

    output.append(f"  Type:         {'DLL' if result.metadata.is_dll else 'EXE'}")
    output.append(f"  Entry Point:  0x{result.metadata.entry_point:08x}")
    output.append("")

    # Hashes
    output.append("FILE HASHES")
    output.append("-" * 80)
    output.append(f"  MD5:    {result.hashes['md5']}")
    output.append(f"  SHA1:   {result.hashes['sha1']}")
    output.append(f"  SHA256: {result.hashes['sha256']}")
    output.append("")

    # VirusTotal (if available)
    if result.vt_report:
        vt = result.vt_report
        output.append("VIRUSTOTAL")
        output.append("-" * 80)
        output.append(
            f"  Detections - Malicious: {vt.malicious}, Suspicious: {vt.suspicious}, "
            f"Harmless: {vt.harmless}, Undetected: {vt.undetected}"
        )
        if vt.reputation is not None:
            output.append(f"  Reputation: {vt.reputation}")
        if vt.tags:
            output.append(f"  Tags: {', '.join(vt.tags[:20])}")
        output.append("")
    elif result.vt_status == "not_found":
        output.append("VIRUSTOTAL")
        output.append("-" * 80)
        output.append("  No VirusTotal record found for this hash.")
        output.append("")

    # YARA Detections (if any)
    if result.yara_matches:
        output.append("🎯 YARA DETECTIONS")
        output.append("-" * 80)
        output.append(f"Total matches: {len(result.yara_matches)}")
        output.append("")

        # Group by namespace
        by_namespace = {}
        for match in result.yara_matches:
            ns = match.namespace
            if ns not in by_namespace:
                by_namespace[ns] = []
            by_namespace[ns].append(match)

        for namespace, matches in sorted(by_namespace.items()):
            namespace_emoji = {
                "malware": "🚨",
                "packer": "📦",
                "exploit": "💥",
                "antidebug": "🛡️",
                "antivm": "🛡️",
                "crypto": "🔐",
                "capabilities": "🔧",
                "cve_rules": "💥",
                "exploit_kits": "💥",
                "packers": "📦"
            }.get(namespace.lower(), "⚠️")

            output.append(f"{namespace_emoji} [{namespace}] - {len(matches)} rule(s)")
            output.append("-" * 40)
            for match in matches:
                output.append(f"  • {match.rule_name}")
                if match.tags:
                    output.append(f"    Tags: {', '.join(match.tags)}")
                if match.meta:
                    # Show description if available
                    if "description" in match.meta:
                        output.append(f"    Description: {match.meta['description']}")
                    # Show other metadata
                    other_meta = {k: v for k, v in match.meta.items() if k != "description"}
                    if other_meta:
                        for key, value in list(other_meta.items())[:3]:  # Show first 3 meta fields
                            output.append(f"    {key}: {value}")
            output.append("")
    else:
        output.append("🎯 YARA DETECTIONS")
        output.append("-" * 80)
        output.append("  No YARA rules matched")
        output.append("")

    # Sections
    output.append("SECTIONS")
    output.append("-" * 80)
    output.append(f"{'Name':<12} {'VA':<12} {'VSize':<12} {'RawSize':<12} {'Entropy':<10} {'RWX':<8} {'Suspicious'}")
    output.append("-" * 80)

    for section in result.sections:
        rwx = "".join(section.characteristics) if section.characteristics else "---"
        suspicious = "⚠ YES" if section.is_suspicious() else ""

        output.append(
            f"{section.name:<12} "
            f"0x{section.virtual_address:08x}  "
            f"0x{section.virtual_size:08x}  "
            f"0x{section.raw_size:08x}  "
            f"{section.entropy:>8.4f}  "
            f"{rwx:<8} "
            f"{suspicious}"
        )
    output.append("")

    # Imports
    output.append("IMPORTS")
    output.append("-" * 80)
    suspicious_count = 0
    for imp in result.imports:
        marker = "⚠" if imp.is_suspicious() else " "
        if imp.is_suspicious():
            suspicious_count += 1

        output.append(f"{marker} {imp.dll_name} ({len(imp.functions)} functions)")

        # Show first 5 functions
        for func in imp.functions[:5]:
            output.append(f"    - {func}")

        if len(imp.functions) > 5:
            output.append(f"    ... and {len(imp.functions) - 5} more")
        output.append("")

    # Suspicious Indicators Summary
    output.append("SUSPICIOUS INDICATORS")
    output.append("-" * 80)

    suspicious_sections = result.get_suspicious_sections()
    suspicious_imports = result.get_suspicious_imports()

    if not result.has_suspicious_indicators():
        output.append("  No suspicious indicators detected.")
    else:
        if suspicious_sections:
            output.append(f"  ⚠ {len(suspicious_sections)} suspicious section(s):")
            for sec in suspicious_sections:
                reasons = []
                if "W" in sec.characteristics and "X" in sec.characteristics:
                    reasons.append("W+X")
                if sec.entropy > 7.0 and "X" in sec.characteristics:
                    reasons.append("high entropy + executable")
                output.append(f"    - {sec.name}: {', '.join(reasons)}")

        if suspicious_imports:
            output.append(f"  ⚠ {len(suspicious_imports)} DLL(s) with suspicious APIs:")
            for imp in suspicious_imports:
                output.append(f"    - {imp.dll_name}")

    # Capabilities (if available) - SHOW ALL in verbose mode
    if result.capabilities is not None:
        output.append("")
        output.append("CAPABILITIES (CAPA)")
        output.append("-" * 80)
        if result.capabilities:
            output.append(f"Total capabilities detected: {len(result.capabilities)}")
            output.append("")

            # Group by category for better organization
            categories = result.categorize_capabilities()
            for category, caps in sorted(categories.items()):
                output.append(f"[{category}] ({len(caps)} capabilities)")
                output.append("-" * 40)
                for cap in caps:
                    output.append(f"  • {cap.name}")
                    if cap.description:
                        output.append(f"    {cap.description}")
                output.append("")
        else:
            output.append("  No capabilities detected.")

    # Strings (if available)
    if result.strings is not None:
        output.append("")
        output.append("DECODED STRINGS (FLOSS)")
        output.append("-" * 80)
        if result.strings:
            for string in result.strings[:30]:  # Show first 30
                addr = f"0x{string.address:08x}" if string.address else "N/A"
                output.append(f"  [{string.type:>7}] {addr}: {string.string[:80]}")
            if len(result.strings) > 30:
                output.append(f"  ... and {len(result.strings) - 30} more strings")
        else:
            output.append("  No decoded strings found.")

    output.append("")
    output.append("=" * 80)

    return "\n".join(output)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze PE files for malware indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sample.exe                 # Human-readable report
  %(prog)s sample.exe --json          # JSON output
  %(prog)s sample.exe --json | jq .   # Pretty JSON with jq
        """
    )

    parser.add_argument(
        'file_path',
        help='Path to PE file to analyze'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )

    parser.add_argument(
        '-a', '--async',
        action='store_true',
        dest='use_async',
        help='Run async analysis (includes capa and floss)'
    )

    parser.add_argument(
        '--fast-capa',
        action='store_true',
        help='Use shorter timeouts for capa/floss and skip capa fallback on timeout (faster but may miss results)'
    )

    parser.add_argument(
        '--vt',
        action='store_true',
        help='Enrich results with VirusTotal (requires VT_API_KEY in environment)'
    )

    parser.add_argument(
        '--proc-events',
        action='store_true',
        help='Summarize recent process creation events for this binary (requires Windows event logs via PowerShell)'
    )

    parser.add_argument(
        '--proc-parent',
        help='Parent image name/path substring to filter process creation events (default: basename of analyzed file)'
    )

    parser.add_argument(
        '--proc-hours',
        type=int,
        default=24,
        help='Lookback window (hours) for process creation events when using --proc-events (default: 24)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output with full details (default: simple mode with risk assessment)'
    )

    args = parser.parse_args()

    # Initialize engine
    engine = PEEngine()

    try:
        # Analyze the file
        if args.use_async:
            # Run async analysis
            result = asyncio.run(engine.analyze_async(args.file_path, fast_capa=args.fast_capa))
        else:
            # Run fast (sync) analysis only
            result = engine.analyze(args.file_path)

        # Optional VirusTotal enrichment
        if args.vt:
            from malview.vt_client import fetch_vt_report
            sha256 = result.hashes.get("sha256") if result.hashes else None
            if sha256:
                vt_result = fetch_vt_report(sha256)
                result.vt_status = vt_result.status
                result.vt_report = vt_result.report

                if vt_result.status == "missing_key" and vt_result.message:
                    print(f"Warning: {vt_result.message}", file=sys.stderr)
                elif vt_result.status == "error" and vt_result.message:
                    print(f"Warning: VirusTotal lookup failed: {vt_result.message}", file=sys.stderr)
            else:
                print("Warning: Missing SHA256 hash; cannot query VirusTotal", file=sys.stderr)

        # Output results
        if args.json:
            print(result.to_json())
        elif args.verbose:
            print(format_verbose(result))
        else:
            print(format_simple(result))

        # Optional: process creation event summary (Sysmon/Security via PowerShell)
        if args.proc_events:
            from malview.proc_events import fetch_process_events
            parent_filter = args.proc_parent or Path(args.file_path).name
            events, source, err = fetch_process_events(
                parent_substring=parent_filter,
                hours=args.proc_hours,
                max_events=200
            )

            print("\nPROCESS CREATION EVENTS")
            print("-" * 80)
            print(f"  Source: {source} log | Parent filter: '{parent_filter}' | Window: last {args.proc_hours}h")
            if err:
                print(f"  Warning: {err}")

            if events:
                # Summarize by child image
                counts = {}
                for ev in events:
                    name = Path(ev.image).name if ev.image else "unknown"
                    counts[name] = counts.get(name, 0) + 1

                print(f"  Matches: {len(events)} event(s)")
                print("  Top child images:")
                for name, count in sorted(counts.items(), key=lambda x: -x[1])[:10]:
                    print(f"    - {name}: {count}")

                print("\n  Recent events:")
                for ev in events[-10:]:
                    child = ev.image or "unknown"
                    cmd = ev.command or ""
                    print(f"    {ev.time} | child: {child} (PID {ev.pid}) | parent PID {ev.ppid} | cmd: {cmd}")
            else:
                print("  No matching process creation events found in the selected window.")

    except MalviewError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

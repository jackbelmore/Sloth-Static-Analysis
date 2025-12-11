"""Data models for PE analysis results."""

import json
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict


@dataclass
class PEMetadata:
    """Basic PE file metadata."""
    file_size: int
    architecture: str  # "x86", "x64", "unknown"
    compile_time: Optional[str]  # ISO format timestamp
    is_dll: bool
    is_64bit: bool
    entry_point: int

    def has_fake_timestamp(self) -> bool:
        """Check if compilation timestamp is suspicious."""
        if not self.compile_time:
            return False
        try:
            compile_dt = datetime.fromisoformat(self.compile_time.replace('Z', '+00:00'))
            now = datetime.now()
            # Future date or before 1990 (early Windows era)
            return compile_dt.year > now.year or compile_dt.year < 1990
        except:
            return False


@dataclass
class Anomaly:
    """Detected anomaly in PE file."""
    severity: str  # "low", "medium", "high"
    category: str  # "timestamp", "entropy", "section", "import", etc.
    description: str
    emoji: str = "⚠️"


@dataclass
class RiskAssessment:
    """Overall risk assessment of the PE file."""
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    score: int  # 0-100
    anomalies: List[Anomaly]
    summary: str

    def get_emoji(self) -> str:
        """Get emoji for risk level."""
        mapping = {
            "LOW": "✅",
            "MEDIUM": "⚠️",
            "HIGH": "🔴",
            "CRITICAL": "🚨"
        }
        return mapping.get(self.risk_level, "❓")


@dataclass
class SectionInfo:
    """PE section information with suspicious detection."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: List[str]  # ["R", "W", "X"]

    def is_suspicious(self) -> bool:
        """
        Detect suspicious section characteristics.

        Returns:
            True if section has W+X or high entropy with executable flag
        """
        has_wx = "W" in self.characteristics and "X" in self.characteristics
        high_entropy = self.entropy > 7.0
        is_executable = "X" in self.characteristics
        return has_wx or (high_entropy and is_executable)


@dataclass
class ImportInfo:
    """DLL import information with suspicious API detection."""
    dll_name: str
    functions: List[str]

    def is_suspicious(self) -> bool:
        """
        Detect suspicious API imports.

        Returns:
            True if any imported function is commonly used in malware
        """
        suspicious_apis = {
            # Memory manipulation
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
            # Process injection
            'WriteProcessMemory', 'CreateRemoteThread', 'SetWindowsHookEx',
            # Code loading
            'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryEx',
            'GetProcAddress',
            # Cryptography (sometimes obfuscation)
            'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
            # Registry manipulation
            'RegSetValueEx', 'RegCreateKeyEx', 'RegDeleteKey',
            # Network
            'InternetOpen', 'InternetConnect', 'URLDownloadToFile',
            # Process manipulation
            'CreateProcess', 'ShellExecute', 'WinExec',
            # Anti-debugging
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        }

        return any(func in suspicious_apis for func in self.functions)


@dataclass
class Capability:
    """Capability detected by capa (FLARE capability detector)."""
    namespace: str  # e.g., "anti-analysis/anti-debugging"
    name: str  # e.g., "check for debugger"
    description: str
    matches: List[str]  # Addresses where capability was detected


@dataclass
class StringFinding:
    """String finding from floss (obfuscated string solver)."""
    string: str  # The decoded string
    type: str  # "static", "decoded", or "stack"
    address: Optional[int] = None  # Location in binary


@dataclass
class YaraMatch:
    """YARA rule match."""
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, str]


@dataclass
class VTReport:
    """VirusTotal enrichment (high level)."""
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: Optional[int] = None
    tags: Optional[List[str]] = None


@dataclass
class ScanResult:
    """
    Complete PE analysis result following the Hybrid Engine pattern.

    Fast data (sync): hashes, metadata, sections, imports
    Slow data (async): capabilities, strings, yara_matches
    """
    file_path: str
    hashes: Dict[str, str]
    metadata: PEMetadata
    sections: List[SectionInfo]
    imports: List[ImportInfo]
    capabilities: Optional[List[Capability]] = None  # Phase 2 (capa)
    strings: Optional[List[StringFinding]] = None  # Phase 2 (floss)
    yara_matches: Optional[List[YaraMatch]] = None  # YARA detections
    vt_report: Optional[VTReport] = None  # VirusTotal enrichment
    vt_status: Optional[str] = None  # VT lookup status ("ok", "not_found", etc.)

    def to_json(self) -> str:
        """
        Serialize to JSON string.

        Returns:
            Indented JSON representation of the scan result
        """
        return json.dumps(asdict(self), indent=2)

    def get_suspicious_sections(self) -> List[SectionInfo]:
        """Get all sections flagged as suspicious."""
        return [s for s in self.sections if s.is_suspicious()]

    def get_suspicious_imports(self) -> List[ImportInfo]:
        """Get all import DLLs with suspicious APIs."""
        return [i for i in self.imports if i.is_suspicious()]

    def has_suspicious_indicators(self) -> bool:
        """Check if any suspicious indicators are present."""
        return bool(self.get_suspicious_sections() or self.get_suspicious_imports())

    def categorize_capabilities(self) -> Dict[str, List[Capability]]:
        """Group capabilities by high-level category."""
        if not self.capabilities:
            return {}

        categories = defaultdict(list)

        for cap in self.capabilities:
            namespace = cap.namespace.lower()

            # Map namespaces to friendly categories
            if "file" in namespace or "filesystem" in namespace:
                categories["File System"].append(cap)
            elif "process" in namespace or "thread" in namespace:
                categories["Process Control"].append(cap)
            elif "registry" in namespace:
                categories["Registry"].append(cap)
            elif "network" in namespace or "socket" in namespace or "http" in namespace:
                categories["Network"].append(cap)
            elif "crypto" in namespace or "encoding" in namespace or "hash" in namespace:
                categories["Encoding/Crypto"].append(cap)
            elif "anti" in namespace or "debug" in namespace or "evasion" in namespace:
                categories["Anti-Analysis"].append(cap)
            elif "persistence" in namespace or "startup" in namespace:
                categories["Persistence"].append(cap)
            elif "inject" in namespace or "shellcode" in namespace:
                categories["Code Injection"].append(cap)
            elif "keylog" in namespace or "screen" in namespace or "clipboard" in namespace:
                categories["Data Collection"].append(cap)
            elif "pe" in namespace or "load" in namespace:
                categories["PE Manipulation"].append(cap)
            else:
                categories["Other"].append(cap)

        return dict(categories)

    def detect_anomalies(self) -> List[Anomaly]:
        """Detect anomalies in the PE file."""
        anomalies = []

        # Check for fake timestamp
        if self.metadata.has_fake_timestamp():
            compile_time = self.metadata.compile_time
            anomalies.append(Anomaly(
                severity="medium",
                category="timestamp",
                description=f"Suspicious compilation timestamp: {compile_time}",
                emoji="📅"
            ))

        # Check for high entropy sections
        for section in self.sections:
            if section.entropy > 7.5:
                anomalies.append(Anomaly(
                    severity="high",
                    category="entropy",
                    description=f"Section '{section.name}' has very high entropy ({section.entropy:.2f}) - possible packing/encryption",
                    emoji="🔒"
                ))
            elif section.entropy > 7.0 and "X" in section.characteristics:
                anomalies.append(Anomaly(
                    severity="medium",
                    category="entropy",
                    description=f"Executable section '{section.name}' has high entropy ({section.entropy:.2f})",
                    emoji="⚠️"
                ))

        # Check for W+X sections
        for section in self.sections:
            if "W" in section.characteristics and "X" in section.characteristics:
                anomalies.append(Anomaly(
                    severity="high",
                    category="section",
                    description=f"Section '{section.name}' is both writable and executable (W+X)",
                    emoji="🚨"
                ))

        # Check for suspicious imports
        for imp in self.get_suspicious_imports():
            suspicious_funcs = [f for f in imp.functions if any(
                api in f for api in ['VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory',
                                     'IsDebuggerPresent', 'LoadLibrary', 'GetProcAddress']
            )]
            if suspicious_funcs:
                anomalies.append(Anomaly(
                    severity="medium",
                    category="import",
                    description=f"{imp.dll_name} imports suspicious APIs: {', '.join(suspicious_funcs[:3])}",
                    emoji="🔧"
                ))

        # Check for anti-debugging capabilities
        if self.capabilities:
            anti_debug_caps = [cap for cap in self.capabilities
                               if "anti-debug" in cap.namespace.lower() or "anti-analysis" in cap.namespace.lower()]
            if anti_debug_caps:
                anomalies.append(Anomaly(
                    severity="high",
                    category="capability",
                    description=f"Detected {len(anti_debug_caps)} anti-debugging/anti-analysis techniques",
                    emoji="🛡️"
                ))

        return anomalies

    def assess_risk(self) -> RiskAssessment:
        """Calculate overall risk assessment with improved YARA-weighted scoring."""
        anomalies = self.detect_anomalies()
        score = 0

        # PRIORITY 1: YARA matches (HIGHEST confidence - 40-60 points)
        if self.yara_matches:
            malware_matches = [m for m in self.yara_matches
                             if "malware" in m.namespace.lower() or
                             any(tag in ["malware", "trojan", "ransomware", "apt"] for tag in m.tags)]
            packer_matches = [m for m in self.yara_matches
                            if "packer" in m.namespace.lower()]
            exploit_matches = [m for m in self.yara_matches
                             if "exploit" in m.namespace.lower() or "cve" in m.namespace.lower()]

            if malware_matches:
                score += 60  # Direct malware family match = very high confidence
                anomalies.append(Anomaly(
                    severity="high",
                    category="yara",
                    description=f"YARA detected malware family: {malware_matches[0].rule_name}",
                    emoji="🚨"
                ))
            if exploit_matches:
                score += 40  # Exploit kit detection
            if packer_matches:
                score += 20  # Packed executable (suspicious but not proof)

        # PRIORITY 2: Capability-based scoring (MEDIUM confidence - 10-25 points)
        if self.capabilities:
            categories = self.categorize_capabilities()
            if "Code Injection" in categories:
                score += 25
            if "Anti-Analysis" in categories:
                score += 20
            if "Persistence" in categories:
                score += 15
            if "Network" in categories:
                score += 10

        # PRIORITY 3: Anomalies (LOW-MEDIUM confidence - 5-30 points)
        severity_scores = {"low": 5, "medium": 15, "high": 30}
        for anomaly in anomalies:
            score += severity_scores.get(anomaly.severity, 0)

        # PRIORITY 4: Basic indicators (LOWEST confidence - 5-10 points)
        if self.get_suspicious_sections():
            score += 10
        if self.get_suspicious_imports():
            score += 10

        # Cap score at 100
        score = min(score, 100)

        # Determine risk level with YARA-aware thresholds
        if self.yara_matches and any("malware" in m.namespace.lower() for m in self.yara_matches):
            # If YARA directly identified malware, always HIGH or CRITICAL
            risk_level = "CRITICAL" if score >= 60 else "HIGH"
            summary = f"YARA identified as malware: {self.yara_matches[0].rule_name}"
        elif score < 20:
            risk_level = "LOW"
            summary = "File shows minimal suspicious indicators"
        elif score < 50:
            risk_level = "MEDIUM"
            summary = "File shows some suspicious indicators - warrants investigation"
        elif score < 75:
            risk_level = "HIGH"
            summary = "File shows multiple suspicious indicators - likely malicious"
        else:
            risk_level = "CRITICAL"
            summary = "File shows severe malicious indicators - high confidence malware"

        return RiskAssessment(
            risk_level=risk_level,
            score=score,
            anomalies=anomalies,
            summary=summary
        )

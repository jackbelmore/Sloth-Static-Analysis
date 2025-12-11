"""YARA scanner for malware detection."""

import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yara


@dataclass
class YaraMatch:
    """YARA rule match result."""
    rule_name: str
    namespace: str  # e.g., "malware", "packer", "antidebug"
    tags: List[str]
    meta: dict
    strings: List[tuple]  # Matched strings


class YaraScanner:
    """YARA rule scanner for PE files."""

    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA scanner.

        Args:
            rules_path: Path to YARA rules directory or index file.
                       If None, uses default yara_rules/ directory.
        """
        if rules_path is None:
            # Default to yara_rules directory
            rules_path = Path(__file__).parent.parent / "yara_rules"

        self.rules_path = Path(rules_path)
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from the rules directory."""
        if not self.rules_path.exists():
            print(f"Warning: YARA rules path not found: {self.rules_path}")
            return

        # Try to use index.yar if it exists (compiled index)
        index_file = self.rules_path / "index.yar"
        if index_file.exists():
            try:
                self.rules = yara.compile(filepath=str(index_file))
                print(f"Loaded YARA rules from {index_file}")
                return
            except Exception as e:
                print(f"Warning: Failed to load index.yar: {e}")

        # Otherwise, compile all .yar and .yara files individually (skip failures)
        try:
            rule_files = {}
            failed_count = 0

            # Collect all rule files
            all_rule_files = []
            for rule_file in self.rules_path.rglob("*.yar"):
                if "test" not in str(rule_file).lower() and "deprecated" not in str(rule_file).lower():
                    all_rule_files.append(rule_file)
            for rule_file in self.rules_path.rglob("*.yara"):
                if "test" not in str(rule_file).lower() and "deprecated" not in str(rule_file).lower():
                    all_rule_files.append(rule_file)

            # Try to compile each file individually
            for rule_file in all_rule_files:
                namespace = rule_file.stem
                try:
                    # Test compile this single file
                    yara.compile(filepath=str(rule_file))
                    rule_files[namespace] = str(rule_file)
                except Exception as e:
                    # Skip rules that fail (e.g., require unavailable modules)
                    failed_count += 1
                    if "cuckoo" in str(e) or "sync" in str(e):
                        # These rules require Cuckoo Sandbox integration
                        pass
                    else:
                        print(f"Skipping {rule_file.name}: {str(e)[:50]}")

            if rule_files:
                # Compile all valid rules together
                self.rules = yara.compile(filepaths=rule_files)
                print(f"Loaded {len(rule_files)} YARA rules ({failed_count} skipped)")
            else:
                print("Warning: No YARA rules could be loaded")

        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            self.rules = None

    def scan(self, file_path: str) -> List[YaraMatch]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of YaraMatch objects for matching rules
        """
        if self.rules is None:
            return []

        noisy_rules = {"PoetRat_Python", "domain"}  # overly chatty rules

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=".*too many matches for string.*",
                    category=RuntimeWarning,
                )
                matches = self.rules.match(
                    file_path,
                    timeout=60,
                    externals=None,
                )
        except Exception as e:
            # Ignore known noisy rules warnings; emit others
            msg = str(e)
            if any(name in msg for name in noisy_rules):
                return []
            print(f"Error scanning with YARA: {e}")
            return []

        results = []

        for match in matches:
            if match.rule in noisy_rules:
                continue

            yara_match = YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                tags=match.tags,
                meta=match.meta,
                strings=[(s.identifier, s.instances) for s in match.strings]
            )
            results.append(yara_match)

        return results

    def categorize_matches(self, matches: List[YaraMatch]) -> dict:
        """
        Categorize YARA matches by type.

        Args:
            matches: List of YaraMatch objects

        Returns:
            Dictionary mapping categories to lists of matches
        """
        categories = {
            "malware": [],
            "packer": [],
            "exploit": [],
            "antidebug": [],
            "capabilities": [],
            "crypto": [],
            "other": []
        }

        for match in matches:
            namespace = match.namespace.lower()
            rule_name = match.rule_name.lower()

            # Categorize based on namespace and rule name
            if "malware" in namespace or any(x in rule_name for x in ["trojan", "backdoor", "ransomware", "apt"]):
                categories["malware"].append(match)
            elif "packer" in namespace or any(x in rule_name for x in ["upx", "aspack", "themida", "vmprotect"]):
                categories["packer"].append(match)
            elif "exploit" in namespace or "cve" in namespace:
                categories["exploit"].append(match)
            elif "antidebug" in namespace or "antivm" in namespace:
                categories["antidebug"].append(match)
            elif "capabilities" in namespace:
                categories["capabilities"].append(match)
            elif "crypto" in namespace:
                categories["crypto"].append(match)
            else:
                categories["other"].append(match)

        return {k: v for k, v in categories.items() if v}  # Remove empty categories

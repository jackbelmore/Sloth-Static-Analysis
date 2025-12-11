"""Async wrappers for external malware analysis tools."""

import asyncio
import json
import shutil
from typing import List, Dict, Optional
from pathlib import Path


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not available."""
    pass


class ToolExecutionError(Exception):
    """Raised when tool execution fails."""
    pass


def _resolve_tool(name: str) -> Optional[str]:
    """Resolve tool path, preferring PATH then venv sibling."""
    import sys
    path = shutil.which(name)
    if path:
        return path
    # Fallback to venv/local bin next to the interpreter
    exe_dir = Path(sys.executable).parent
    candidate = exe_dir / name
    return str(candidate) if candidate.exists() else None


async def run_capa_async(
    file_path: str,
    timeout: Optional[float] = None,
    allow_fallback: bool = True,
) -> List[Dict]:
    """
    Run capa (FLARE capability detector) asynchronously.

    Args:
        file_path: Path to the PE file to analyze

    Returns:
        List of capability dictionaries with:
        - namespace: str (e.g., "anti-analysis/anti-debugging")
        - name: str (e.g., "check for debugger")
        - description: str
        - matches: List of address matches

    Raises:
        ToolNotFoundError: If capa is not installed
        ToolExecutionError: If capa execution fails
    """
    # Check if capa is available
    capa_path = _resolve_tool("capa")
    if not capa_path:
        raise ToolNotFoundError("capa not found in PATH. Install with: pip install flare-capa")

    # Determine rules path (check local first, then fall back to auto)
    rules_path = Path(__file__).parent.parent / "rules"
    if not rules_path.exists():
        rules_path = "auto"
    else:
        rules_path = str(rules_path)

    async def _run_once(extra_args: List[str], wait_timeout: float) -> List[Dict]:
        try:
            process = await asyncio.create_subprocess_exec(
                capa_path,
                *extra_args,
                "-r",
                rules_path,
                "-s",
                "/dev/null",  # No signatures (use -s /dev/null to bypass)
                "--json",
                file_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=wait_timeout)

            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                raise ToolExecutionError(f"capa failed: {error_msg}")

            raw_result = json.loads(stdout.decode('utf-8'))
            capabilities = []
            rules_json = raw_result.get("rules", {})

            for rule_name, rule_data in rules_json.items():
                meta = rule_data.get("meta", {})
                matches = rule_data.get("matches", [])
                capabilities.append({
                    "namespace": meta.get("namespace", "unknown"),
                    "name": rule_name,
                    "description": meta.get("description", ""),
                    "matches": [str(match) for match in matches] if matches else [],
                })

            return capabilities
        except asyncio.TimeoutError:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except Exception:
                pass
            raise ToolExecutionError("capa timed out")
        except json.JSONDecodeError as e:
            raise ToolExecutionError(f"Failed to parse capa output: {e}")

    def _run_file_scope_fallback() -> List[Dict]:
        """
        Run a file-scope-only capa pass using the Python API and pefile extractor.

        This avoids vivisect and only returns matches for FILE scope rules.
        """
        try:
            from capa.rules import Rule, RuleSet, Scope
            from capa.capabilities.common import find_file_capabilities
            from capa.features.extractors.pefile import PefileFeatureExtractor
        except Exception as exc:
            raise ToolExecutionError(f"capa fallback import failed: {exc}") from exc

        rules_dir = Path(rules_path)
        rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
        file_rules = []
        for rule_file in rule_files:
            try:
                rule = Rule.from_yaml_file(rule_file)
                if str(rule.meta.get("scope", "")).lower() == "file":
                    file_rules.append(rule)
            except Exception:
                # Skip non-rule YAML or malformed rules
                continue

        if not file_rules:
            raise ToolExecutionError("capa fallback found no file-scope rules")

        ruleset = RuleSet(file_rules)
        extractor = PefileFeatureExtractor(Path(file_path))
        file_caps = find_file_capabilities(ruleset, extractor, {})

        capabilities = []
        for rule_name, matches in file_caps.matches.items():
            rule = ruleset.rules.get(rule_name)
            meta = rule.meta if rule else {}
            capabilities.append({
                "namespace": meta.get("namespace", "unknown") if meta else "unknown",
                "name": rule_name,
                "description": meta.get("description", "") if meta else "",
                "matches": [str(m) for m in matches] if matches else [],
                "source": "capa-file-scope",
            })
        return capabilities

    # Primary attempt (vivisect backend by default)
    wait_timeout = timeout or 120
    try:
        return await _run_once([], wait_timeout)
    except ToolExecutionError as primary_err:
        err_msg = str(primary_err).lower()
        if "timed out" not in err_msg:
            raise

        if not allow_fallback:
            raise

        # Fallback to lightweight file-scope analysis via pefile extractor
        try:
            print("Warning: capa vivisect timed out, running file-scope fallback (pefile)")
            return _run_file_scope_fallback()
        except Exception as fallback_err:
            raise ToolExecutionError(f"capa vivisect timed out and fallback failed: {fallback_err}") from fallback_err


async def run_floss_async(file_path: str, timeout: Optional[float] = None) -> List[Dict]:
    """
    Run floss (FLARE obfuscated string solver) asynchronously.

    Args:
        file_path: Path to the PE file to analyze

    Returns:
        List of string finding dictionaries with:
        - string: str (the decoded string)
        - type: str ("static", "decoded", "stack")
        - address: Optional[int] (location in binary)

    Raises:
        ToolNotFoundError: If floss is not installed
        ToolExecutionError: If floss execution fails
    """
    # Check if floss is available
    floss_path = _resolve_tool("floss")
    if not floss_path:
        raise ToolNotFoundError("floss not found in PATH. Install with: pip install flare-floss")

    # Run floss with JSON output
    try:
        process = await asyncio.create_subprocess_exec(
            floss_path,
            "--only", "decoded", "stack",  # Focus on decoded and stack strings
            "-j",  # JSON output (short flag)
            file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        wait_timeout = timeout or 150
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=wait_timeout)
        except asyncio.TimeoutError:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except Exception:
                pass
            raise ToolExecutionError(f"floss timed out after {wait_timeout:.0f}s")

        if process.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='ignore')
            raise ToolExecutionError(f"floss failed: {error_msg}")

        # Parse JSON output
        raw_result = json.loads(stdout.decode('utf-8'))

        # Extract strings from floss's JSON format
        findings = []

        # floss JSON structure varies by version, handle common formats
        # Decoded strings (most interesting for malware)
        decoded_strings = raw_result.get("decoded_strings", [])
        for item in decoded_strings:
            findings.append({
                "string": item.get("string", ""),
                "type": "decoded",
                "address": item.get("address"),
            })

        # Stack strings (also interesting)
        stack_strings = raw_result.get("stack_strings", [])
        for item in stack_strings:
            findings.append({
                "string": item.get("string", ""),
                "type": "stack",
                "address": item.get("address"),
            })

        return findings

    except json.JSONDecodeError as e:
        raise ToolExecutionError(f"Failed to parse floss output: {e}")
    except Exception as e:
        raise ToolExecutionError(f"floss execution failed: {e}")


def check_tools_available() -> Dict[str, bool]:
    """
    Check which external tools are available.

    Returns:
        Dictionary mapping tool names to availability (True/False)
    """
    return {
        "capa": shutil.which("capa") is not None,
        "floss": shutil.which("floss") is not None,
    }

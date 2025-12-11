"""VirusTotal lookup client."""

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Optional

from .models import VTReport


@dataclass
class VTLookupResult:
    """Result wrapper for VT lookups."""
    status: str  # "ok", "not_found", "missing_key", "error"
    report: Optional[VTReport] = None
    message: Optional[str] = None


def fetch_vt_report(sha256: str) -> VTLookupResult:
    """
    Fetch a VirusTotal report by SHA256.

    Requires environment variable VT_API_KEY.
    Returns status codes so callers can surface "not found" vs. errors.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return VTLookupResult(status="missing_key", message="VT_API_KEY not set")

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # 404 means not found in VT
        if exc.code == 404:
            return VTLookupResult(status="not_found")
        return VTLookupResult(status="error", message=f"HTTP {exc.code}: {exc.reason}")
    except Exception as exc:
        return VTLookupResult(status="error", message=str(exc))

    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        tags = attrs.get("tags") or []
        return VTLookupResult(
            status="ok",
            report=VTReport(
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0),
                undetected=stats.get("undetected", 0),
                reputation=attrs.get("reputation"),
                tags=tags if tags else None,
            )
        )
    except Exception as exc:
        return VTLookupResult(status="error", message=f"parse failed: {exc}")

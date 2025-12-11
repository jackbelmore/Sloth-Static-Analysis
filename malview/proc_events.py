"""Lightweight process creation event fetcher via PowerShell.

Uses Get-WinEvent to pull Sysmon (Event ID 1) or Security (Event ID 4688)
process creation events, and filters client-side by parent image substring.

This is intended for quick, on-demand enrichment and avoids extra Python
dependencies by shelling out to PowerShell.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class ProcEvent:
    """Process creation event."""
    time: str
    image: Optional[str]
    command: Optional[str]
    parent_image: Optional[str]
    pid: Optional[int]
    ppid: Optional[int]


def _run_powershell(script: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    """Run PowerShell and return parsed JSON list or None on error."""
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - platform specific
        return None, f"PowerShell exec failed: {exc}"

    if completed.returncode != 0:
        return None, f"PowerShell exited {completed.returncode}: {completed.stderr.strip()}"

    raw = completed.stdout.strip()
    if not raw:
        return [], None

    try:
        data = json.loads(raw)
    except Exception as exc:
        return None, f"JSON parse failed: {exc}"

    # Normalise to list
    if isinstance(data, dict):
        data = [data]
    return data, None


def fetch_process_events(
    parent_substring: str,
    hours: int = 24,
    max_events: int = 200,
) -> Tuple[List[ProcEvent], str, Optional[str]]:
    """
    Fetch recent process creation events filtered by parent image substring.

    Returns:
        (events, source, error) where source is 'sysmon', 'security', or 'none'.
    """
    events: List[ProcEvent] = []
    source = "none"
    err: Optional[str] = None

    # PowerShell to pull Sysmon Event ID 1
    ps_sysmon = rf"""
$start = (Get-Date).AddHours(-{hours})
$evts = @()
try {{
  $evts = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$start}} -ErrorAction Stop |
    Select-Object TimeCreated,
      @{{
        n='Image';e={{ try {{ $_.Properties[4].Value }} catch {{ $null }} }}
      }},
      @{{
        n='CommandLine';e={{ try {{ $_.Properties[10].Value }} catch {{ $null }} }}
      }},
      @{{
        n='ParentImage';e={{ try {{ $_.Properties[1].Value }} catch {{ $null }} }}
      }},
      @{{
        n='ProcessId';e={{ try {{ $_.Properties[6].Value }} catch {{ $null }} }}
      }},
      @{{
        n='ParentProcessId';e={{ try {{ $_.Properties[2].Value }} catch {{ $null }} }}
      }}
}} catch {{ }}
if ($evts) {{ $evts | ConvertTo-Json -Depth 4 }}
"""

    # PowerShell to pull Security Event ID 4688 (process creation)
    ps_security = rf"""
$start = (Get-Date).AddHours(-{hours})
$evts = @()
try {{
  $evts = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688; StartTime=$start}} -ErrorAction Stop |
    Select-Object TimeCreated,
      @{{
        n='Image';e={{ try {{ $_.Properties[5].Value }} catch {{ $null }} }}
      }},
      @{{
        n='CommandLine';e={{ try {{ $_.Properties[8].Value }} catch {{ $null }} }}
      }},
      @{{
        n='ParentImage';e={{ try {{ $_.Properties[13].Value }} catch {{ $null }} }}
      }},
      @{{
        n='ProcessId';e={{ try {{ [int]$_.Properties[4].Value }} catch {{ $null }} }}
      }},
      @{{
        n='ParentProcessId';e={{ try {{ [int]$_.Properties[3].Value }} catch {{ $null }} }}
      }}
}} catch {{ }}
if ($evts) {{ $evts | ConvertTo-Json -Depth 4 }}
"""

    # Try Sysmon first
    data, err_sysmon = _run_powershell(ps_sysmon)
    if data is not None:
        source = "sysmon"
    else:
        # Fallback to Security log
        data, err_sec = _run_powershell(ps_security)
        source = "security" if data is not None else "none"
        if data is None:
            err = err_sec
    if data is None and err is None:
        err = err_sysmon

    if not data:
        return [], source, err

    parent_sub = parent_substring.lower()
    for item in data:
        parent_img = (item.get("ParentImage") or "").lower()
        if parent_sub not in parent_img:
            continue
        events.append(
            ProcEvent(
                time=item.get("TimeCreated"),
                image=item.get("Image"),
                command=item.get("CommandLine"),
                parent_image=item.get("ParentImage"),
                pid=item.get("ProcessId"),
                ppid=item.get("ParentProcessId"),
            )
        )

    # Limit results to keep output small
    events = sorted(events, key=lambda e: e.time or "")[-max_events:]
    return events, source, err

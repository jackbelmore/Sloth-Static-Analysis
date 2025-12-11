"""Phase-based progress tracking for async operations."""

import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

# Default weights for each analysis phase (sum should be 1.0)
DEFAULT_PHASES: Sequence[Tuple[str, float]] = [
    ("pe", 0.10),
    ("yara", 0.15),
    ("capa", 0.40),
    ("floss", 0.35),
]


class PhaseProgress:
    """Phase-aware progress bar that only reaches 100% when all phases finish."""

    def __init__(
        self,
        file_name: str,
        file_size: int,
        desc: str = "Analyzing",
        phases: Sequence[Tuple[str, float]] = DEFAULT_PHASES,
        phase_time_hints: Optional[Dict[str, float]] = None,
    ):
        self.file_name = file_name
        self.file_size = file_size
        self.desc = desc
        self.phases = list(phases)
        self._phase_state: Dict[str, str] = {name: "pending" for name, _ in self.phases}
        self._phase_started_at: Dict[str, float] = {}
        self._stop = False
        self._task: Optional[asyncio.Task] = None
        self._start_ts = time.monotonic()
        self._phase_time_hints = phase_time_hints or self._default_time_hints()
        self._total_weight = sum(weight for _, weight in self.phases) or 1.0

    def _default_time_hints(self) -> Dict[str, float]:
        """Rough per-phase durations scaled by file size so the bar keeps moving."""
        size_mb = max(self.file_size / 1_000_000, 1.0)
        return {
            "pe": 0.5,
            "yara": 1.0,
            "capa": max(12.0, size_mb * 3.0),
            "floss": max(10.0, size_mb * 2.5),
        }

    def mark_phase_completed(self, phase: str) -> None:
        self._phase_state[phase] = "completed"

    def start_phase(self, phase: str) -> None:
        if phase not in self._phase_state:
            return
        if self._phase_state[phase] == "completed":
            return
        self._phase_state[phase] = "running"
        self._phase_started_at.setdefault(phase, time.monotonic())

    def start(self) -> None:
        """Kick off the render loop."""
        self._stop = False
        self._task = asyncio.create_task(self._render_loop())

    async def finish(self) -> None:
        """Stop the render loop and clear the line."""
        self._stop = True
        if self._task:
            await self._task

    def _phase_fraction(self, phase: str) -> float:
        state = self._phase_state.get(phase, "pending")
        if state == "completed":
            return 1.0
        if state != "running":
            return 0.0

        elapsed = time.monotonic() - self._phase_started_at.get(phase, self._start_ts)
        hint = max(self._phase_time_hints.get(phase, 5.0), 1.0)

        # Normalized progress up to ~90% during expected duration
        if elapsed <= hint:
            return min(elapsed / hint, 0.9)

        # Overtime: slowly creep toward 0.98 so the bar keeps moving without falsely completing
        overtime = elapsed - hint
        creep = min(overtime / (hint * 2), 0.08)  # cap overtime contribution
        return min(0.9 + creep, 0.98)

    def _compute_progress(self) -> float:
        progress = 0.0
        for phase, weight in self.phases:
            progress += weight * self._phase_fraction(phase)

        # Only reach 100% when every phase is completed
        if all(state == "completed" for state in self._phase_state.values()):
            return 1.0

        return min(progress / self._total_weight, 0.995)

    def _active_phase_label(self) -> str:
        running = []
        for name, state in self._phase_state.items():
            if state == "running":
                frac = self._phase_fraction(name)
                suffix = "*" if frac >= 0.9 else ""
                running.append(f"{name}{suffix}")
        if running:
            return f"[{', '.join(running)}]"
        pending = [name for name, state in self._phase_state.items() if state == "pending"]
        if pending:
            return f"[waiting: {pending[0]}]"
        return "[finalizing]"

    async def _render_loop(self) -> None:
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        interval = 0.1

        while not self._stop:
            progress = self._compute_progress()
            bar_length = 40
            filled = int(bar_length * progress)
            bar = "█" * filled + "░" * (bar_length - filled)
            percent = int(progress * 100)
            spinner = chars[idx % len(chars)]
            phase_label = self._active_phase_label()

            sys.stderr.write(
                f"\r{spinner} {self.desc} {self.file_name}: [{bar}] {percent}% {phase_label}"
            )
            sys.stderr.flush()

            await asyncio.sleep(interval)
            idx += 1

        # Clear the line when done
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()


async def run_with_progress(
    file_path: str,
    file_size: int,
    coro_fn,
    phases: Sequence[Tuple[str, float]] = DEFAULT_PHASES,
    phase_time_hints: Optional[Dict[str, float]] = None,
):
    """
    Run a coroutine while showing phase-aware progress.

    The provided coro_fn should accept a PhaseProgress instance so it can
    mark phases started/completed.
    """
    file_name = Path(file_path).name
    progress = PhaseProgress(
        file_name=file_name,
        file_size=file_size,
        phases=phases,
        phase_time_hints=phase_time_hints,
    )

    # Fast phases already done before we enter async land
    progress.mark_phase_completed("pe")
    progress.mark_phase_completed("yara")
    progress.start()

    try:
        result = await coro_fn(progress)
    finally:
        await progress.finish()

    return result

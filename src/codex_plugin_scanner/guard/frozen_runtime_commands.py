"""Leaf command builders shared by frozen Guard harness adapters."""

from __future__ import annotations

import json
import sys
from pathlib import Path

FROZEN_DAEMON_RECOVER_ARG = "--_hol-guard-codex-daemon-recover"


def is_frozen_guard_runtime() -> bool:
    """Return whether this process is a PyInstaller-style frozen Guard binary."""

    return bool(getattr(sys, "frozen", False)) and Path(sys.executable).is_file()


def frozen_daemon_recovery_command(
    guard_home: Path,
    home_dir: Path,
    *,
    executable: str | None = None,
) -> tuple[str, ...]:
    """Build the authenticated frozen-Core daemon recovery command."""

    payload = json.dumps(
        {
            "guard_home": str(guard_home.resolve(strict=False)),
            "home_dir": str(home_dir.resolve(strict=False)),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (executable or sys.executable, FROZEN_DAEMON_RECOVER_ARG, payload)


__all__ = ["FROZEN_DAEMON_RECOVER_ARG", "frozen_daemon_recovery_command", "is_frozen_guard_runtime"]

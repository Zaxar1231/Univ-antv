"""Описание установленной программы."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstalledProgram:
    name: str
    version: str = ""
    publisher: str = ""
    uninstall_command: str = ""
    quiet_uninstall_command: str = ""
    install_location: Path | None = None
    registry_key: str = ""

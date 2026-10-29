"""Пути к данным программы. Значения можно переопределить переменными окружения."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """Папка с данными программы: карантин и журналы."""
    if sys.platform == "win32" and "ProgramData" in os.environ:
        return Path(os.environ["ProgramData"], "antv")
    return Path.home() / ".antv"


def quarantine_dir() -> Path:
    override = os.environ.get("ANTV_QUARANTINE_DIR")
    return Path(override) if override else data_dir() / "quarantine"


def database_dir() -> Path | None:
    """Папка с базами ClamAV. None означает базы по умолчанию, заданные при сборке ClamAV."""
    override = os.environ.get("ANTV_DATABASE_DIR")
    return Path(override) if override else None

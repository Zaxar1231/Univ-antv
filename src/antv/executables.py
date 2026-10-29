"""Проверка запускаемых файлов перед запуском."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from antv.clam import CLEAN, INFECTED, ClamAV, ScanResult

EXECUTABLE_SUFFIXES = frozenset(
    {
        ".exe", ".dll", ".msi", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
        ".appimage", ".sh", ".py", ".pl", ".rb",
    }
)

# Сигнатуры заголовков: PE (MZ), ELF, Mach-O (в обоих порядках байт и fat), Java class и скрипты с шебангом.
EXECUTABLE_MAGIC = (
    b"MZ",
    b"#!",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


class LaunchBlocked(RuntimeError):
    """Запуск запрещён проверкой."""


@dataclass(frozen=True)
class LaunchVerdict:
    allowed: bool
    reason: str


def is_executable(path: Path) -> bool:
    """Определяет программу по расширению или по заголовку файла."""
    path = Path(path)
    if path.suffix.lower() in EXECUTABLE_SUFFIXES:
        return True
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except OSError:
        return False
    return header.startswith(EXECUTABLE_MAGIC)


def check_before_launch(path: Path, clam: ClamAV) -> LaunchVerdict:
    path = Path(path)
    if not path.is_file():
        return LaunchVerdict(False, "файл не найден")
    if not is_executable(path):
        return LaunchVerdict(False, "файл не похож на программу")

    result: ScanResult = clam.scan_files([path])[0]
    if result.status == CLEAN:
        return LaunchVerdict(True, "угроз не найдено")
    if result.status == INFECTED:
        return LaunchVerdict(False, f"обнаружена угроза: {result.signature}")
    return LaunchVerdict(False, f"не удалось проверить: {result.message}")


def run_checked(path: Path, args: Sequence[str], clam: ClamAV) -> int:
    """Проверяет файл и запускает его только при положительном результате. Возвращает код выхода программы."""
    verdict = check_before_launch(path, clam)
    if not verdict.allowed:
        raise LaunchBlocked(f"Запуск {path} запрещён: {verdict.reason}")
    return subprocess.call([str(path), *args])

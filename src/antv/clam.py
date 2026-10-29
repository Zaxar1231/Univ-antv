"""Обёртка над ClamAV: clamscan и freshclam запускаются как внешние программы."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

CLEAN = "ok"
INFECTED = "infected"
ERROR = "error"

# Коды возврата clamscan: 0 — угроз нет, 1 — найдены угрозы, 2 — ошибка.
_SCAN_OK_CODES = (0, 1, 2)


class ClamError(RuntimeError):
    """ClamAV не найден или не смог выполнить задачу."""


@dataclass(frozen=True)
class ScanResult:
    path: Path
    status: str
    signature: str = ""
    message: str = ""

    @property
    def infected(self) -> bool:
        return self.status == INFECTED


def find_tool(name: str) -> str:
    """Ищет исполняемый файл ClamAV: сначала в ANTV_CLAMAV_DIR, затем в PATH и Program Files."""
    search_dirs = [os.environ.get("ANTV_CLAMAV_DIR")]
    if "ProgramFiles" in os.environ:
        search_dirs.append(str(Path(os.environ["ProgramFiles"], "ClamAV")))

    for directory in filter(None, search_dirs):
        found = shutil.which(name, path=directory)
        if found:
            return found

    found = shutil.which(name)
    if found:
        return found
    raise ClamError(f"{name} не найден. Установите ClamAV или укажите папку в ANTV_CLAMAV_DIR.")


def parse_output(stdout: str, files: Sequence[Path]) -> list[ScanResult]:
    """Разбирает вывод clamscan --no-summary --file-list в список результатов.

    Пути из вывода сопоставляются с переданными файлами, поэтому двоеточия
    внутри путей и сообщений об ошибках не ломают разбор.
    """
    known = {str(path): path for path in files}
    parsed: dict[Path, ScanResult] = {}

    for line in stdout.splitlines():
        path_text, status = _split_line(line, known)
        if path_text is None:
            continue
        path = known[path_text]
        if status.endswith(" FOUND"):
            result = ScanResult(path, INFECTED, signature=status[: -len(" FOUND")])
        elif status == "OK":
            result = ScanResult(path, CLEAN)
        else:
            result = ScanResult(path, ERROR, message=status)
        parsed[path] = result

    return [
        parsed.get(path, ScanResult(path, ERROR, message="нет результата проверки"))
        for path in files
    ]


def _split_line(line: str, known: dict[str, Path]) -> tuple[str | None, str]:
    index = line.find(": ")
    while index != -1:
        head = line[:index]
        if head in known:
            return head, line[index + 2 :]
        index = line.find(": ", index + 1)
    return None, ""


class ClamAV:
    """Проверка файлов и обновление баз через установленный ClamAV."""

    def __init__(self, database_dir: Path | None = None, timeout: float = 3600.0):
        self.database_dir = database_dir
        self.timeout = timeout

    def scan_files(self, files: Sequence[Path]) -> list[ScanResult]:
        if not files:
            return []

        clamscan = find_tool("clamscan")
        # Список файлов передаётся через файл, чтобы не упереться в лимит длины командной строки.
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as listing:
            listing.write("\n".join(str(path) for path in files))
            list_path = listing.name

        try:
            args = [clamscan, "--no-summary", f"--file-list={list_path}"]
            if self.database_dir is not None:
                args.append(f"--database={self.database_dir}")
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        finally:
            os.unlink(list_path)

        if completed.returncode not in _SCAN_OK_CODES:
            raise ClamError(f"clamscan завершился с кодом {completed.returncode}: {completed.stderr.strip()}")
        return parse_output(completed.stdout, files)

    def update(self) -> None:
        """Обновляет базы сигнатур через freshclam."""
        freshclam = find_tool("freshclam")
        args = [freshclam]
        if self.database_dir is not None:
            args.append(f"--datadir={self.database_dir}")
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise ClamError(f"freshclam завершился с кодом {completed.returncode}: {completed.stdout + completed.stderr}")

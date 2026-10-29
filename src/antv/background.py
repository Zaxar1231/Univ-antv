"""Фоновая проверка: следит за изменениями файлов в выбранных папках и проверяет их."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Iterable, Protocol

from antv.clam import ScanResult
from antv.quarantine import Quarantine
from antv.scanner import collect_files

log = logging.getLogger(__name__)

# Файл считается изменённым, если поменялись время изменения или размер.
FileState = tuple[int, int]


class FileScanner(Protocol):
    def scan_files(self, files: list[Path]) -> list[ScanResult]: ...


def take_snapshot(roots: Iterable[Path]) -> dict[Path, FileState]:
    snapshot: dict[Path, FileState] = {}
    for path in collect_files(roots):
        try:
            stat = path.stat()
        except OSError:
            # Файл удалили во время обхода — пропускаем.
            continue
        snapshot[path] = (stat.st_mtime_ns, stat.st_size)
    return snapshot


def changed_files(previous: dict[Path, FileState], current: dict[Path, FileState]) -> list[Path]:
    return [path for path, state in current.items() if previous.get(path) != state]


class BackgroundScanner:
    """Проверяет новые и изменённые файлы в отслеживаемых папках.

    При первом запуске проверяются все файлы, дальше — только те, что изменились.
    """

    def __init__(
        self,
        roots: Iterable[Path],
        clam: FileScanner,
        quarantine: Quarantine | None = None,
        interval: float = 300.0,
    ):
        self.roots = [Path(root) for root in roots]
        self.clam = clam
        self.quarantine = quarantine
        self.interval = interval
        self._previous: dict[Path, FileState] = {}
        self._stop = threading.Event()

    def scan_changes(self) -> list[ScanResult]:
        existing = [root for root in self.roots if root.exists()]
        for missing in set(self.roots) - set(existing):
            log.warning("Папка не найдена, пропускаем: %s", missing)

        current = take_snapshot(existing)
        pending = changed_files(self._previous, current)
        if not pending:
            self._previous = current
            return []

        results = self.clam.scan_files(pending)
        for result in results:
            if result.infected:
                log.warning("Угроза: %s (%s)", result.path, result.signature)
                if self.quarantine is not None:
                    self.quarantine.add(result.path, result.signature)
            elif result.status != "ok":
                log.error("Не удалось проверить %s: %s", result.path, result.message)

        # Состояние сохраняем только после успешной проверки: при сбое файлы проверим в следующий раз.
        self._previous = current
        return results

    def run(self) -> None:
        """Работает до вызова stop(). Ошибки одного цикла не останавливают наблюдение."""
        log.info("Фоновая проверка запущена, интервал %s с", self.interval)
        while not self._stop.is_set():
            try:
                self.scan_changes()
            except Exception:
                log.exception("Цикл фоновой проверки завершился с ошибкой")
            self._stop.wait(self.interval)
        log.info("Фоновая проверка остановлена")

    def stop(self) -> None:
        self._stop.set()

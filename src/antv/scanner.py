"""Сбор файлов из путей и их проверка через ClamAV."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from antv.clam import ClamAV, ScanResult
from antv.quarantine import Quarantine


def collect_files(paths: Iterable[Path]) -> list[Path]:
    """Возвращает файлы из путей; папки обходятся рекурсивно. Символические ссылки пропускаются."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"Нет такого файла или папки: {path}")
    return files


def scan_paths(
    paths: Iterable[Path],
    clam: ClamAV,
    quarantine: Quarantine | None = None,
) -> list[ScanResult]:
    results = clam.scan_files(collect_files(paths))
    if quarantine is not None:
        for result in results:
            if result.infected:
                quarantine.add(result.path, result.signature)
    return results

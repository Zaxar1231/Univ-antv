"""Карантин: изолированное хранение заражённых файлов с возможностью восстановления."""

from __future__ import annotations

import json
import shutil
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

_INDEX_NAME = "index.json"
_STORED_SUFFIX = ".quar"


@dataclass(frozen=True)
class QuarantineEntry:
    id: str
    original_path: str
    signature: str
    quarantined_at: float


class Quarantine:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def add(self, path: Path, signature: str) -> QuarantineEntry:
        """Перемещает файл в карантин и записывает его в индекс."""
        entry = QuarantineEntry(
            id=uuid.uuid4().hex,
            original_path=str(Path(path).resolve()),
            signature=signature,
            quarantined_at=time.time(),
        )
        shutil.move(str(path), self._stored_path(entry.id))
        entries = self._load()
        entries[entry.id] = entry
        self._save(entries)
        return entry

    def list(self) -> list[QuarantineEntry]:
        return sorted(self._load().values(), key=lambda entry: entry.quarantined_at)

    def restore(self, entry_id: str) -> Path:
        """Возвращает файл на исходное место. Существующий файл не перезаписывается."""
        entries = self._load()
        entry = self._get(entries, entry_id)
        destination = Path(entry.original_path)
        if destination.exists():
            raise FileExistsError(f"Файл уже существует: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self._stored_path(entry_id)), destination)
        del entries[entry_id]
        self._save(entries)
        return destination

    def delete(self, entry_id: str) -> None:
        """Безвозвратно удаляет файл из карантина."""
        entries = self._load()
        self._get(entries, entry_id)
        self._stored_path(entry_id).unlink(missing_ok=True)
        del entries[entry_id]
        self._save(entries)

    def _stored_path(self, entry_id: str) -> Path:
        return self.directory / f"{entry_id}{_STORED_SUFFIX}"

    def _index_path(self) -> Path:
        return self.directory / _INDEX_NAME

    def _load(self) -> dict[str, QuarantineEntry]:
        if not self._index_path().exists():
            return {}
        raw = json.loads(self._index_path().read_text(encoding="utf-8"))
        return {key: QuarantineEntry(**value) for key, value in raw.items()}

    def _save(self, entries: dict[str, QuarantineEntry]) -> None:
        payload = {key: asdict(value) for key, value in entries.items()}
        self._index_path().write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _get(entries: dict[str, QuarantineEntry], entry_id: str) -> QuarantineEntry:
        if entry_id not in entries:
            raise KeyError(f"Нет записи в карантине: {entry_id}")
        return entries[entry_id]

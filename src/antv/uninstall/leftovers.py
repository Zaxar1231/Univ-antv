"""Остатки программы после удаления: папки, ярлыки и ключи реестра.

Поиск осторожный: совпадение по точному имени, короткие имена не используются,
а удалять можно только внутри известных корневых папок.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from antv.uninstall.models import InstalledProgram

# Имена короче этого порога слишком похожи на чужие папки, поэтому по ним не ищем.
MIN_NAME_LENGTH = 3


@dataclass
class Leftovers:
    directories: list[Path] = field(default_factory=list)
    shortcuts: list[Path] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.directories or self.shortcuts or self.registry_keys)


def _normalize(text: str) -> str:
    return "".join(ch for ch in text.casefold() if ch.isalnum())


def default_search_roots() -> list[Path]:
    """Папки, где программы обычно оставляют файлы."""
    if sys.platform != "win32":
        return []
    names = ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "APPDATA", "LOCALAPPDATA"]
    return [Path(os.environ[name]) for name in names if os.environ.get(name)]


def default_shortcut_roots() -> list[Path]:
    """Папки меню «Пуск», где лежат ярлыки программ."""
    if sys.platform != "win32":
        return []
    roots = []
    if os.environ.get("ProgramData"):
        roots.append(Path(os.environ["ProgramData"], "Microsoft", "Windows", "Start Menu", "Programs"))
    if os.environ.get("APPDATA"):
        roots.append(Path(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs"))
    return roots


def find_leftover_directories(program: InstalledProgram, search_roots: Iterable[Path]) -> list[Path]:
    found: list[Path] = []
    if program.install_location is not None and program.install_location.is_dir():
        found.append(program.install_location)

    wanted = _normalize(program.name)
    if len(wanted) < MIN_NAME_LENGTH:
        return found

    for root in search_roots:
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and _normalize(child.name) == wanted and child not in found:
                found.append(child)
    return found


def find_leftover_shortcuts(program: InstalledProgram, shortcut_roots: Iterable[Path]) -> list[Path]:
    wanted = _normalize(program.name)
    if len(wanted) < MIN_NAME_LENGTH:
        return []
    found: list[Path] = []
    for root in shortcut_roots:
        if not root.is_dir():
            continue
        found.extend(path for path in root.rglob("*.lnk") if _normalize(path.stem) == wanted)
    return found


def is_safe_to_delete(path: Path, roots: Iterable[Path]) -> bool:
    """Разрешает удалять только то, что лежит внутри корневой папки, но не сами корни и не диски."""
    target = Path(path).resolve()
    if target.parent == target:
        return False  # корень диска
    resolved_roots = [Path(root).resolve() for root in roots]
    if target in resolved_roots:
        return False
    return any(root in target.parents for root in resolved_roots)


def find_leftovers(
    program: InstalledProgram,
    search_roots: Iterable[Path],
    shortcut_roots: Iterable[Path],
    registry_keys: Iterable[str] = (),
) -> Leftovers:
    return Leftovers(
        directories=find_leftover_directories(program, search_roots),
        shortcuts=find_leftover_shortcuts(program, shortcut_roots),
        registry_keys=list(registry_keys),
    )


def delete_leftovers(
    leftovers: Leftovers,
    directory_roots: Iterable[Path],
    shortcut_roots: Iterable[Path],
) -> list[str]:
    """Удаляет найденные остатки. Возвращает список выполненных действий.

    Пути вне разрешённых корней пропускаются с пометкой, ничего не удаляется «на всякий случай».
    """
    directory_roots = list(directory_roots)
    shortcut_roots = list(shortcut_roots)
    actions: list[str] = []

    for directory in leftovers.directories:
        if not is_safe_to_delete(directory, directory_roots):
            actions.append(f"пропущено (вне разрешённых папок): {directory}")
            continue
        shutil.rmtree(directory)
        actions.append(f"удалена папка: {directory}")

    for shortcut in leftovers.shortcuts:
        if not is_safe_to_delete(shortcut, shortcut_roots):
            actions.append(f"пропущено (вне меню «Пуск»): {shortcut}")
            continue
        shortcut.unlink(missing_ok=True)
        actions.append(f"удалён ярлык: {shortcut}")

    if leftovers.registry_keys:
        from antv.uninstall.registry import delete_registry_tree

        for key in leftovers.registry_keys:
            delete_registry_tree(key)
            actions.append(f"удалён ключ реестра: {key}")

    return actions

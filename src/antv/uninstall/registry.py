"""Список установленных программ из реестра Windows.

Разбор записей (parse_entry) работает на любой ОС, а обращение к реестру выполняется только в Windows.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping

from antv.uninstall.models import InstalledProgram

UNINSTALL_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
UNINSTALL_SUBKEY_32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"


class UnsupportedPlatformError(RuntimeError):
    """Функция работает только в Windows."""


def _require_windows() -> None:
    if sys.platform != "win32":
        raise UnsupportedPlatformError("Эта функция доступна только в Windows")


def parse_entry(values: Mapping[str, Any], registry_key: str = "") -> InstalledProgram | None:
    """Превращает значения записи реестра в программу. Возвращает None для записей, которые не нужны."""
    name = str(values.get("DisplayName") or "").strip()
    uninstall = str(values.get("UninstallString") or "").strip()
    if not name or not uninstall:
        return None
    # Системные компоненты и обновления удаляются через основную программу, поэтому их пропускаем.
    if values.get("SystemComponent") == 1 or values.get("ParentKeyName"):
        return None

    location = str(values.get("InstallLocation") or "").strip()
    return InstalledProgram(
        name=name,
        version=str(values.get("DisplayVersion") or "").strip(),
        publisher=str(values.get("Publisher") or "").strip(),
        uninstall_command=uninstall,
        quiet_uninstall_command=str(values.get("QuietUninstallString") or "").strip(),
        install_location=Path(location) if location else None,
        registry_key=registry_key,
    )


def list_installed_programs() -> list[InstalledProgram]:
    _require_windows()
    import winreg

    sources = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", UNINSTALL_SUBKEY),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", UNINSTALL_SUBKEY_32),
        (winreg.HKEY_CURRENT_USER, "HKCU", UNINSTALL_SUBKEY),
    ]
    programs: list[InstalledProgram] = []
    for hive, hive_name, subkey in sources:
        try:
            root = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        with root:
            for child in _enum_subkeys(root):
                try:
                    with winreg.OpenKey(root, child) as key:
                        values = _read_values(key)
                except OSError:
                    continue
                program = parse_entry(values, registry_key=f"{hive_name}\\{subkey}\\{child}")
                if program is not None:
                    programs.append(program)
    return sorted(programs, key=lambda program: program.name.casefold())


def find_registry_leftovers(name: str, publisher: str) -> list[str]:
    """Ищет ключи SOFTWARE\\<издатель>\\<программа>, которые могли остаться после удаления."""
    _require_windows()
    import winreg

    if not name:
        return []
    paths = [name] if not publisher else [f"{publisher}\\{name}", name]
    found: list[str] = []
    for hive, hive_name in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for relative in paths:
            full = f"SOFTWARE\\{relative}"
            if _key_exists(hive, full):
                found.append(f"{hive_name}\\{full}")
    return found


def delete_registry_tree(full_key: str) -> None:
    """Удаляет ключ реестра вместе со всеми вложенными. Принимает строку вида HKLM\\SOFTWARE\\..."""
    _require_windows()
    import winreg

    hive_name, _, subkey = full_key.partition("\\")
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    _delete_tree(hives[hive_name], subkey)


def _delete_tree(hive: int, subkey: str) -> None:
    import winreg

    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
        for child in _enum_subkeys(key):
            _delete_tree(hive, f"{subkey}\\{child}")
    winreg.DeleteKey(hive, subkey)


def _key_exists(hive: int, subkey: str) -> bool:
    import winreg

    try:
        winreg.OpenKey(hive, subkey).Close()
    except OSError:
        return False
    return True


def _enum_subkeys(key: Any) -> list[str]:
    import winreg

    count = winreg.QueryInfoKey(key)[0]
    return [winreg.EnumKey(key, index) for index in range(count)]


def _read_values(key: Any) -> dict[str, Any]:
    import winreg

    count = winreg.QueryInfoKey(key)[1]
    values: dict[str, Any] = {}
    for index in range(count):
        name, data, _ = winreg.EnumValue(key, index)
        values[name] = data
    return values

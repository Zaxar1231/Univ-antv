"""Тихое удаление: приводит команду деинсталлятора к беззвучному виду для MSI, Inno Setup и NSIS."""

from __future__ import annotations

import re
from pathlib import PureWindowsPath

# Тихая установка в Inno Setup: без окон, без подтверждений, без перезагрузки.
INNO_SILENT = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
# MSI: /qn — без интерфейса, /norestart — не перезагружать систему.
MSI_SILENT = ["/qn", "/norestart"]
# NSIS: /S — тихий режим.
NSIS_SILENT = ["/S"]

_MSI_PRODUCT = re.compile(r"/[IX](\{[0-9A-Fa-f-]+\})", re.IGNORECASE)
_INNO_NAME = re.compile(r"^unins\d*\.exe$", re.IGNORECASE)
_NSIS_NAMES = {"uninstall.exe", "uninst.exe"}


def split_command(command: str) -> list[str]:
    """Делит строку команды на аргументы. Кавычки снимаются, пути с пробелами сохраняются."""
    return [quoted if quoted else bare for quoted, bare in re.findall(r'"([^"]*)"|(\S+)', command)]


def silent_arguments(command: str) -> tuple[list[str], str]:
    """Возвращает аргументы для тихого удаления и тип деинсталлятора.

    Тип: "msi", "inno", "nsis" или "unknown". Для unknown аргументы возвращаются без изменений.
    """
    parts = split_command(command)
    if not parts:
        return [], "unknown"

    program, args = parts[0], parts[1:]
    file_name = PureWindowsPath(program).name.lower()

    if file_name in {"msiexec", "msiexec.exe"}:
        return _msi(program, args), "msi"
    if _INNO_NAME.match(file_name):
        return [program, *_with_flags(args, INNO_SILENT)], "inno"
    if file_name in _NSIS_NAMES:
        return [program, *_with_flags(args, NSIS_SILENT)], "nsis"
    return parts, "unknown"


def _msi(program: str, args: list[str]) -> list[str]:
    match = _MSI_PRODUCT.search(" ".join(args))
    if match is None:
        return [program, *args]
    # /I (установка) заменяем на /X (удаление), чтобы MSI удалил продукт.
    # Если уровень интерфейса уже задан (/qb, /quiet и т.п.), сохраняем его, иначе ставим /qn.
    ui_level = [arg for arg in args if arg.lower().startswith("/q")]
    return [program, f"/X{match.group(1)}", *(ui_level or MSI_SILENT)]


def _with_flags(args: list[str], flags: list[str]) -> list[str]:
    present = {arg.lower() for arg in args}
    return [*args, *(flag for flag in flags if flag.lower() not in present)]

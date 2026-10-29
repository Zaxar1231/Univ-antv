"""Запуск деинсталлятора программы."""

from __future__ import annotations

import subprocess
from typing import Callable

from antv.uninstall.models import InstalledProgram
from antv.uninstall.silent import silent_arguments, split_command

# 0 — успех; 3010 и 1641 — успех, но нужна перезагрузка (коды MSI).
SUCCESS_CODES = frozenset({0, 1641, 3010})

Runner = Callable[..., subprocess.CompletedProcess]


class UninstallError(RuntimeError):
    """Не удалось подготовить или запустить деинсталлятор."""


def prepare_uninstall(program: InstalledProgram, quiet: bool) -> tuple[list[str], str]:
    """Возвращает аргументы для запуска и способ, которым они получены.

    Способ: "quiet-string" — готовая тихая команда из реестра, "silent-<тип>" — подобрана автоматически,
    "interactive" — обычное удаление с окнами.
    """
    if quiet and program.quiet_uninstall_command:
        return split_command(program.quiet_uninstall_command), "quiet-string"
    if quiet:
        args, kind = silent_arguments(program.uninstall_command)
        return args, f"silent-{kind}"
    return split_command(program.uninstall_command), "interactive"


def run_uninstaller(
    program: InstalledProgram,
    quiet: bool = True,
    runner: Runner = subprocess.run,
    timeout: float = 1800.0,
) -> int:
    args, _ = prepare_uninstall(program, quiet)
    if not args:
        raise UninstallError(f"У программы {program.name} нет команды удаления")
    completed = runner(args, capture_output=True, text=True, timeout=timeout, check=False)
    return completed.returncode


def is_success(return_code: int) -> bool:
    return return_code in SUCCESS_CODES

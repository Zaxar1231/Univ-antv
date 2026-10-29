"""Полное удаление программ: деинсталлятор, поиск и очистка остатков."""

from antv.uninstall.engine import UninstallError, is_success, prepare_uninstall, run_uninstaller
from antv.uninstall.leftovers import Leftovers, delete_leftovers, find_leftovers
from antv.uninstall.models import InstalledProgram
from antv.uninstall.registry import UnsupportedPlatformError, list_installed_programs
from antv.uninstall.silent import silent_arguments, split_command

__all__ = [
    "InstalledProgram",
    "Leftovers",
    "UninstallError",
    "UnsupportedPlatformError",
    "delete_leftovers",
    "find_leftovers",
    "is_success",
    "list_installed_programs",
    "prepare_uninstall",
    "run_uninstaller",
    "silent_arguments",
    "split_command",
]

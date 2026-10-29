"""Командная строка Univ-antv."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Sequence

from antv import __version__
from antv.background import BackgroundScanner
from antv.clam import ERROR, ClamAV, ClamError
from antv.config import database_dir, quarantine_dir
from antv.executables import LaunchBlocked, run_checked
from antv.quarantine import Quarantine
from antv.scanner import scan_paths
from antv.uninstall import (
    UnsupportedPlatformError,
    delete_leftovers,
    find_leftovers,
    is_success,
    list_installed_programs,
    run_uninstaller,
)
from antv.uninstall.leftovers import default_search_roots, default_shortcut_roots

EXIT_CLEAN = 0
EXIT_INFECTED = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antv",
        description="Univ-antv — бесплатный антивирус с автоматической проверкой обновлений.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный журнал")
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("update", help="обновить базы сигнатур ClamAV")

    scan = commands.add_parser("scan", help="проверить файлы и папки")
    scan.add_argument("paths", nargs="+", type=Path)
    scan.add_argument("--quarantine", action="store_true", help="заражённые файлы перемещать в карантин")

    watch = commands.add_parser("watch", help="фоновая проверка новых и изменённых файлов")
    watch.add_argument("paths", nargs="+", type=Path)
    watch.add_argument("--interval", type=float, default=300.0, help="пауза между циклами, секунды")
    watch.add_argument("--quarantine", action="store_true")

    run = commands.add_parser("run", help="проверить программу и запустить её, если угроз нет")
    run.add_argument("program", type=Path)
    run.add_argument("args", nargs=argparse.REMAINDER)

    commands.add_parser("programs", help="список установленных программ (Windows)")

    uninstall = commands.add_parser("uninstall", help="удалить программу вместе с остатками (Windows)")
    uninstall.add_argument("name", help="часть названия программы")
    uninstall.add_argument("--interactive", action="store_true", help="запустить деинсталлятор с окнами")
    uninstall.add_argument("--delete-leftovers", action="store_true", help="удалить найденные остатки")
    uninstall.add_argument("--yes", action="store_true", help="подтвердить удаление остатков")

    quarantine = commands.add_parser("quarantine", help="управление карантином")
    actions = quarantine.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="показать файлы в карантине")
    restore = actions.add_parser("restore", help="вернуть файл из карантина")
    restore.add_argument("entry_id")
    delete = actions.add_parser("delete", help="удалить файл из карантина навсегда")
    delete.add_argument("entry_id")

    return parser


def _clam() -> ClamAV:
    return ClamAV(database_dir=database_dir())


def cmd_update(_: argparse.Namespace) -> int:
    _clam().update()
    print("Базы сигнатур обновлены.")
    return EXIT_CLEAN


def cmd_scan(args: argparse.Namespace) -> int:
    quarantine = Quarantine(quarantine_dir()) if args.quarantine else None
    results = scan_paths(args.paths, _clam(), quarantine)

    for result in results:
        if result.infected:
            print(f"ЗАРАЖЁН  {result.path}  ({result.signature})")
        elif result.status == ERROR:
            print(f"ОШИБКА   {result.path}  ({result.message})")

    infected = sum(result.infected for result in results)
    errors = sum(result.status == ERROR for result in results)
    print(f"Проверено файлов: {len(results)}, угроз: {infected}, ошибок: {errors}")

    if infected:
        return EXIT_INFECTED
    return EXIT_ERROR if errors else EXIT_CLEAN


def cmd_watch(args: argparse.Namespace) -> int:
    quarantine = Quarantine(quarantine_dir()) if args.quarantine else None
    scanner = BackgroundScanner(args.paths, _clam(), quarantine, interval=args.interval)
    try:
        scanner.run()
    except KeyboardInterrupt:
        scanner.stop()
    return EXIT_CLEAN


def cmd_run(args: argparse.Namespace) -> int:
    try:
        return run_checked(args.program, args.args, _clam())
    except LaunchBlocked as error:
        print(str(error), file=sys.stderr)
        return EXIT_INFECTED


def cmd_programs(_: argparse.Namespace) -> int:
    try:
        programs = list_installed_programs()
    except UnsupportedPlatformError as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR
    for program in programs:
        print(f"{program.name}  {program.version}  [{program.publisher}]")
    print(f"Всего: {len(programs)}")
    return EXIT_CLEAN


def cmd_uninstall(args: argparse.Namespace) -> int:
    try:
        programs = list_installed_programs()
    except UnsupportedPlatformError as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR

    matches = [program for program in programs if args.name.casefold() in program.name.casefold()]
    if len(matches) != 1:
        print(f"Найдено программ: {len(matches)}. Уточните название.", file=sys.stderr)
        for program in matches:
            print(f"  {program.name}", file=sys.stderr)
        return EXIT_ERROR

    program = matches[0]
    print(f"Удаляем: {program.name} {program.version}".rstrip())
    return_code = run_uninstaller(program, quiet=not args.interactive)
    if not is_success(return_code):
        print(f"Деинсталлятор завершился с кодом {return_code}.", file=sys.stderr)
        return EXIT_ERROR
    print("Деинсталлятор отработал.")

    leftovers = find_leftovers(
        program,
        search_roots=default_search_roots(),
        shortcut_roots=default_shortcut_roots(),
        registry_keys=_registry_leftovers(program),
    )
    if leftovers.is_empty:
        print("Остатков не найдено.")
        return EXIT_CLEAN

    print("Найдены остатки:")
    for directory in leftovers.directories:
        print(f"  папка:   {directory}")
    for shortcut in leftovers.shortcuts:
        print(f"  ярлык:   {shortcut}")
    for key in leftovers.registry_keys:
        print(f"  реестр:  {key}")

    if not args.delete_leftovers:
        print("Чтобы удалить остатки, запустите команду с --delete-leftovers --yes.")
        return EXIT_CLEAN
    if not args.yes:
        print("Удаление не выполнено: добавьте --yes, чтобы подтвердить удаление остатков.", file=sys.stderr)
        return EXIT_ERROR

    for action in delete_leftovers(leftovers, default_search_roots(), default_shortcut_roots()):
        print(action)
    return EXIT_CLEAN


def _registry_leftovers(program) -> list[str]:
    if sys.platform != "win32":
        return []
    from antv.uninstall.registry import find_registry_leftovers

    return find_registry_leftovers(program.name, program.publisher)


def cmd_quarantine(args: argparse.Namespace) -> int:
    quarantine = Quarantine(quarantine_dir())
    try:
        if args.action == "list":
            for entry in quarantine.list():
                print(f"{entry.id}  {entry.signature}  {entry.original_path}")
        elif args.action == "restore":
            print(f"Восстановлено: {quarantine.restore(args.entry_id)}")
        elif args.action == "delete":
            quarantine.delete(args.entry_id)
            print("Файл удалён из карантина.")
    except (KeyError, FileExistsError) as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


_HANDLERS = {
    "update": cmd_update,
    "scan": cmd_scan,
    "watch": cmd_watch,
    "run": cmd_run,
    "programs": cmd_programs,
    "uninstall": cmd_uninstall,
    "quarantine": cmd_quarantine,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.command is None:
        parser.print_help()
        return EXIT_CLEAN
    try:
        return _HANDLERS[args.command](args)
    except ClamError as error:
        print(f"Ошибка ClamAV: {error}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR

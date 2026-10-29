"""Точка входа: ``python -m antv``."""

import argparse
import sys

from antv import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antv",
        description="Univ-antv — бесплатный антивирус с автоматической проверкой обновлений.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    # Функции сканирования и обновлений будут добавляться по плану из docs/ROADMAP.md.
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

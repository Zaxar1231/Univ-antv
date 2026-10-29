import sys

import pytest

from antv.clam import CLEAN, ERROR, INFECTED, ScanResult
from antv.executables import LaunchBlocked, check_before_launch, is_executable, run_checked


class FakeClam:
    def __init__(self, status=CLEAN, signature="", message=""):
        self.status = status
        self.signature = signature
        self.message = message

    def scan_files(self, files):
        return [ScanResult(f, self.status, self.signature, self.message) for f in files]


@pytest.mark.parametrize("name", ["setup.exe", "lib.DLL", "install.msi", "run.ps1", "app.jar"])
def test_executable_by_suffix(tmp_path, name):
    path = tmp_path / name
    path.write_text("not really a program")
    assert is_executable(path)


def test_executable_by_magic_bytes(tmp_path):
    elf = tmp_path / "tool"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 16)
    pe = tmp_path / "renamed.bin"
    pe.write_bytes(b"MZ" + b"\x00" * 30)
    assert is_executable(elf)
    assert is_executable(pe)


def test_plain_text_is_not_executable(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("hello")
    assert not is_executable(path)


def test_clean_program_is_allowed(tmp_path):
    program = tmp_path / "app.exe"
    program.write_bytes(b"MZ" + b"\x00" * 30)

    verdict = check_before_launch(program, FakeClam(CLEAN))

    assert verdict.allowed


def test_infected_program_is_blocked(tmp_path):
    program = tmp_path / "app.exe"
    program.write_bytes(b"MZ" + b"\x00" * 30)

    verdict = check_before_launch(program, FakeClam(INFECTED, signature="Win.Trojan"))

    assert not verdict.allowed
    assert "Win.Trojan" in verdict.reason


def test_scan_error_blocks_launch(tmp_path):
    program = tmp_path / "app.exe"
    program.write_bytes(b"MZ" + b"\x00" * 30)

    verdict = check_before_launch(program, FakeClam(ERROR, message="Access denied"))

    assert not verdict.allowed


def test_missing_file_is_blocked(tmp_path):
    assert not check_before_launch(tmp_path / "gone.exe", FakeClam()).allowed


def test_non_executable_is_refused_without_scanning(tmp_path):
    text = tmp_path / "readme.txt"
    text.write_text("hi")

    verdict = check_before_launch(text, FakeClam(CLEAN))

    assert not verdict.allowed
    assert "не похож на программу" in verdict.reason


def test_run_checked_does_not_start_blocked_program(tmp_path):
    program = tmp_path / "app.exe"
    program.write_bytes(b"MZ" + b"\x00" * 30)

    with pytest.raises(LaunchBlocked):
        run_checked(program, [], FakeClam(INFECTED, signature="X"))


@pytest.mark.skipif(sys.platform == "win32", reason="тест использует shell-скрипт с шебангом")
def test_run_checked_starts_clean_program(tmp_path):
    script = tmp_path / "ok.sh"
    script.write_text("#!/bin/sh\nexit 3\n")
    script.chmod(0o755)

    assert run_checked(script, [], FakeClam(CLEAN)) == 3

import subprocess
from pathlib import Path

import pytest

from antv.uninstall import (
    InstalledProgram,
    delete_leftovers,
    find_leftovers,
    is_success,
    prepare_uninstall,
    run_uninstaller,
    silent_arguments,
    split_command,
)
from antv.uninstall.leftovers import MIN_NAME_LENGTH, find_leftover_directories, is_safe_to_delete
from antv.uninstall.registry import parse_entry


# --- разбор реестра ---------------------------------------------------------

def test_parse_entry_reads_fields():
    program = parse_entry(
        {
            "DisplayName": "Example Tool",
            "DisplayVersion": "1.2.3",
            "Publisher": "Example Corp",
            "UninstallString": '"C:\\Example\\unins000.exe"',
            "QuietUninstallString": '"C:\\Example\\unins000.exe" /SILENT',
            "InstallLocation": "C:\\Example",
        },
        registry_key="HKLM\\SOFTWARE\\...\\Uninstall\\Example",
    )
    assert program is not None
    assert program.name == "Example Tool"
    assert program.install_location == Path("C:\\Example")
    assert program.quiet_uninstall_command.endswith("/SILENT")


@pytest.mark.parametrize(
    "values",
    [
        {"UninstallString": "x.exe"},  # нет имени
        {"DisplayName": "No Command"},  # нет команды удаления
        {"DisplayName": "Sys", "UninstallString": "x.exe", "SystemComponent": 1},
        {"DisplayName": "Patch", "UninstallString": "x.exe", "ParentKeyName": "Office"},
    ],
)
def test_parse_entry_skips_unusable_records(values):
    assert parse_entry(values) is None


# --- тихое удаление ---------------------------------------------------------

def test_split_command_keeps_quoted_paths():
    assert split_command('"C:\\Program Files\\App\\unins.exe" /S') == ["C:\\Program Files\\App\\unins.exe", "/S"]


def test_msi_uninstall_becomes_silent_removal():
    args, kind = silent_arguments("MsiExec.exe /I{12345678-AAAA-BBBB-CCCC-123456789ABC}")
    assert kind == "msi"
    assert args == ["MsiExec.exe", "/X{12345678-AAAA-BBBB-CCCC-123456789ABC}", "/qn", "/norestart"]


def test_msi_keeps_user_chosen_ui_level():
    args, _ = silent_arguments("MsiExec.exe /X{12345678-AAAA-BBBB-CCCC-123456789ABC} /qb")
    assert args[-1] == "/qb"
    assert "/qn" not in args


def test_inno_setup_gets_silent_flags():
    args, kind = silent_arguments('"C:\\App\\unins000.exe"')
    assert kind == "inno"
    assert args[1:] == ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]


def test_nsis_gets_s_flag_once():
    args, kind = silent_arguments('"C:\\App\\uninstall.exe" /S')
    assert kind == "nsis"
    assert args.count("/S") == 1


def test_unknown_uninstaller_is_left_unchanged():
    args, kind = silent_arguments('"C:\\App\\remove.exe" --all')
    assert kind == "unknown"
    assert args == ["C:\\App\\remove.exe", "--all"]


def test_prepare_prefers_vendor_quiet_string():
    program = InstalledProgram(
        name="App",
        uninstall_command='"C:\\App\\unins000.exe"',
        quiet_uninstall_command='"C:\\App\\unins000.exe" /SILENT',
    )
    args, how = prepare_uninstall(program, quiet=True)
    assert how == "quiet-string"
    assert args[-1] == "/SILENT"


def test_prepare_interactive_uses_original_command():
    program = InstalledProgram(name="App", uninstall_command='"C:\\App\\unins000.exe"')
    args, how = prepare_uninstall(program, quiet=False)
    assert how == "interactive"
    assert args == ["C:\\App\\unins000.exe"]


def test_run_uninstaller_passes_args_to_runner():
    calls = []

    def fake_runner(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 3010)

    program = InstalledProgram(name="App", uninstall_command='"C:\\App\\uninstall.exe"')
    code = run_uninstaller(program, quiet=True, runner=fake_runner)

    assert calls == [["C:\\App\\uninstall.exe", "/S"]]
    assert is_success(code)  # 3010 — успех с требованием перезагрузки


def test_run_uninstaller_rejects_empty_command():
    from antv.uninstall import UninstallError

    with pytest.raises(UninstallError):
        run_uninstaller(InstalledProgram(name="App"), runner=lambda *a, **k: None)


# --- остатки ----------------------------------------------------------------

def test_leftover_directories_match_exact_name_only(tmp_path):
    root = tmp_path / "Programs"
    (root / "Example Tool").mkdir(parents=True)
    (root / "Example Tool Pro").mkdir()
    (root / "Other").mkdir()
    program = InstalledProgram(name="Example Tool")

    found = find_leftover_directories(program, [root])

    assert found == [root / "Example Tool"]


def test_short_names_do_not_match_anything(tmp_path):
    root = tmp_path / "Programs"
    (root / "R").mkdir(parents=True)
    program = InstalledProgram(name="R")
    assert len("R") < MIN_NAME_LENGTH
    assert find_leftover_directories(program, [root]) == []


def test_is_safe_to_delete_protects_roots_and_outsiders(tmp_path):
    root = tmp_path / "Programs"
    inside = root / "App"
    inside.mkdir(parents=True)
    outside = tmp_path / "Documents"
    outside.mkdir()

    assert is_safe_to_delete(inside, [root])
    assert not is_safe_to_delete(root, [root])
    assert not is_safe_to_delete(outside, [root])
    assert not is_safe_to_delete(Path(inside.anchor), [root])


def test_delete_leftovers_removes_only_allowed(tmp_path):
    root = tmp_path / "Programs"
    app = root / "Example Tool"
    app.mkdir(parents=True)
    (app / "data.bin").write_text("x")
    outside = tmp_path / "Documents" / "Example Tool"
    outside.mkdir(parents=True)

    program = InstalledProgram(name="Example Tool")
    leftovers = find_leftovers(program, search_roots=[root], shortcut_roots=[])
    leftovers.directories.append(outside)

    actions = delete_leftovers(leftovers, directory_roots=[root], shortcut_roots=[])

    assert not app.exists()
    assert outside.exists()
    assert any("пропущено" in action for action in actions)

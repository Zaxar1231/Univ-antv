import pytest

from antv import __version__
from antv.cli import EXIT_CLEAN, EXIT_ERROR, main


def test_version_is_defined():
    assert __version__ == "0.1.0"


def test_version_flag_prints_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_arguments_prints_help(capsys):
    assert main([]) == EXIT_CLEAN
    assert "usage" in capsys.readouterr().out.lower()


def test_programs_reports_unsupported_platform_outside_windows(capsys, monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    assert main(["programs"]) == EXIT_ERROR
    assert "Windows" in capsys.readouterr().err


def test_scan_missing_path_is_error(capsys, tmp_path):
    assert main(["scan", str(tmp_path / "missing")]) == EXIT_ERROR


def test_quarantine_list_on_empty_store(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTV_QUARANTINE_DIR", str(tmp_path / "q"))
    assert main(["quarantine", "list"]) == EXIT_CLEAN
    assert capsys.readouterr().out == ""

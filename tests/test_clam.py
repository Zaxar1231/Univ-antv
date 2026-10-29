import os
from pathlib import Path

import pytest

from antv.clam import CLEAN, ERROR, INFECTED, ClamAV, ClamError, find_tool, parse_output
from conftest import requires_clamav


def test_parse_clean_infected_and_error_lines():
    files = [Path("/data/a.txt"), Path("/data/b.exe"), Path("/data/c.bin")]
    stdout = (
        "/data/a.txt: OK\n"
        "/data/b.exe: Eicar-Test-Signature FOUND\n"
        "/data/c.bin: No such file or directory\n"
    )

    results = parse_output(stdout, files)

    assert [r.status for r in results] == [CLEAN, INFECTED, ERROR]
    assert results[1].signature == "Eicar-Test-Signature"
    assert results[2].message == "No such file or directory"


def test_parse_handles_colon_inside_path_and_message():
    files = [Path("/data/my: file.txt")]
    stdout = "/data/my: file.txt: Can't open: denied\n"

    results = parse_output(stdout, files)

    assert results[0].status == ERROR
    assert results[0].message == "Can't open: denied"


def test_missing_result_is_reported_as_error():
    files = [Path("/data/a.txt")]

    results = parse_output("", files)

    assert results[0].status == ERROR
    assert "нет результата" in results[0].message


def test_empty_file_list_does_not_run_clamscan():
    assert ClamAV().scan_files([]) == []


def test_find_tool_reports_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTV_CLAMAV_DIR", str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("ProgramFiles", raising=False)
    with pytest.raises(ClamError):
        find_tool("definitely-not-clamscan")


@requires_clamav
def test_real_clamscan_detects_eicar(tmp_path, eicar_bytes):
    database = os.environ.get("ANTV_DATABASE_DIR")
    if not database:
        pytest.skip("задайте ANTV_DATABASE_DIR с базами ClamAV")
    infected = tmp_path / "eicar.txt"
    clean = tmp_path / "clean.txt"
    infected.write_bytes(eicar_bytes)
    clean.write_text("hello")

    results = ClamAV(database_dir=Path(database)).scan_files([infected, clean])

    assert results[0].infected
    assert results[0].signature == "Eicar-Test-Signature"
    assert results[1].status == CLEAN

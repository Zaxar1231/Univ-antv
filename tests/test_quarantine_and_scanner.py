import os

import pytest

from antv.clam import CLEAN, INFECTED, ScanResult
from antv.quarantine import Quarantine
from antv.scanner import collect_files, scan_paths


class FakeClam:
    def __init__(self, infected=()):
        self.infected = {str(p) for p in infected}

    def scan_files(self, files):
        return [
            ScanResult(f, INFECTED, signature="Fake.Virus") if str(f) in self.infected else ScanResult(f, CLEAN)
            for f in files
        ]


def test_collect_files_recurses_and_skips_symlinks(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.txt").write_text("x")
    (tmp_path / "top.txt").write_text("y")
    if hasattr(os, "symlink"):
        try:
            os.symlink(tmp_path / "top.txt", tmp_path / "link.txt")
        except (OSError, NotImplementedError):
            pass

    names = sorted(p.name for p in collect_files([tmp_path]))

    assert "deep.txt" in names and "top.txt" in names
    assert "link.txt" not in names


def test_collect_files_rejects_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        collect_files([tmp_path / "nope"])


def test_quarantine_add_list_restore(tmp_path):
    source = tmp_path / "virus.exe"
    source.write_bytes(b"MZ payload")
    quarantine = Quarantine(tmp_path / "q")

    entry = quarantine.add(source, "Fake.Virus")

    assert not source.exists()
    assert quarantine.list()[0].id == entry.id

    restored = quarantine.restore(entry.id)
    assert restored == source.resolve()
    assert source.read_bytes() == b"MZ payload"
    assert quarantine.list() == []


def test_quarantine_restore_does_not_overwrite(tmp_path):
    source = tmp_path / "file.bin"
    source.write_text("1")
    quarantine = Quarantine(tmp_path / "q")
    entry = quarantine.add(source, "Fake.Virus")
    source.write_text("someone else's file")

    with pytest.raises(FileExistsError):
        quarantine.restore(entry.id)
    assert source.read_text() == "someone else's file"


def test_quarantine_delete_removes_stored_file(tmp_path):
    source = tmp_path / "file.bin"
    source.write_text("1")
    quarantine = Quarantine(tmp_path / "q")
    entry = quarantine.add(source, "Fake.Virus")

    quarantine.delete(entry.id)

    assert quarantine.list() == []
    assert not any((tmp_path / "q").glob("*.quar"))


def test_unknown_quarantine_id_raises(tmp_path):
    with pytest.raises(KeyError):
        Quarantine(tmp_path / "q").restore("missing")


def test_scan_paths_quarantines_only_infected(tmp_path):
    bad = tmp_path / "bad.txt"
    good = tmp_path / "good.txt"
    bad.write_text("bad")
    good.write_text("good")
    quarantine = Quarantine(tmp_path / "q")

    results = scan_paths([tmp_path], FakeClam(infected=[bad]), quarantine)

    assert sum(r.infected for r in results) == 1
    assert good.exists()
    assert not bad.exists()

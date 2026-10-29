from pathlib import Path

from antv.background import BackgroundScanner, changed_files, take_snapshot
from antv.clam import CLEAN, INFECTED, ScanResult
from antv.quarantine import Quarantine


class FakeClam:
    """Подменяет ClamAV: все файлы чистые, кроме тех, что названы в infected."""

    def __init__(self, infected=()):
        self.infected = {Path(p) for p in infected}
        self.calls: list[list[Path]] = []

    def scan_files(self, files):
        self.calls.append(list(files))
        return [
            ScanResult(f, INFECTED, signature="Fake.Virus") if f in self.infected else ScanResult(f, CLEAN)
            for f in files
        ]


def test_first_cycle_scans_everything_then_only_changes(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    clam = FakeClam()
    scanner = BackgroundScanner([tmp_path], clam)

    scanner.scan_changes()
    assert len(clam.calls[0]) == 2

    scanner.scan_changes()
    assert len(clam.calls) == 1  # второй цикл без изменений ничего не проверяет


def test_modified_file_is_rescanned(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("a")
    clam = FakeClam()
    scanner = BackgroundScanner([tmp_path], clam)
    scanner.scan_changes()

    target.write_text("changed content, different size")
    scanner.scan_changes()

    assert clam.calls[-1] == [target]


def test_infected_file_goes_to_quarantine(tmp_path):
    target = tmp_path / "bad.exe"
    target.write_bytes(b"MZ-bad")
    quarantine = Quarantine(tmp_path / "quarantine")
    scanner = BackgroundScanner([tmp_path], FakeClam(infected=[target]), quarantine)

    results = scanner.scan_changes()

    assert results[0].infected
    assert not target.exists()
    assert [entry.signature for entry in quarantine.list()] == ["Fake.Virus"]


def test_failed_scan_is_retried_next_cycle(tmp_path):
    (tmp_path / "a.txt").write_text("a")

    class FailingClam:
        def __init__(self):
            self.fail = True
            self.calls = 0

        def scan_files(self, files):
            self.calls += 1
            if self.fail:
                raise RuntimeError("clamscan недоступен")
            return [ScanResult(f, CLEAN) for f in files]

    clam = FailingClam()
    scanner = BackgroundScanner([tmp_path], clam)

    try:
        scanner.scan_changes()
    except RuntimeError:
        pass
    clam.fail = False
    scanner.scan_changes()

    assert clam.calls == 2


def test_missing_root_is_skipped(tmp_path):
    scanner = BackgroundScanner([tmp_path / "missing"], FakeClam())
    assert scanner.scan_changes() == []


def test_snapshot_and_diff(tmp_path):
    keep = tmp_path / "keep.txt"
    keep.write_text("1")
    before = take_snapshot([tmp_path])
    new = tmp_path / "new.txt"
    new.write_text("2")
    after = take_snapshot([tmp_path])

    assert changed_files(before, after) == [new]
    assert keep not in changed_files(before, after)

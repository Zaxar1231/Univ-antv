import pytest

from antv import __version__
from antv.__main__ import main


def test_version_is_defined():
    assert __version__ == "0.1.0"


def test_version_flag_prints_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_arguments_prints_help(capsys):
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out.lower()

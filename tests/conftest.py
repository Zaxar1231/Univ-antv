import pytest

from antv.clam import ClamError, find_tool

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _clamscan_installed() -> bool:
    try:
        find_tool("clamscan")
    except ClamError:
        return False
    return True


requires_clamav = pytest.mark.skipif(not _clamscan_installed(), reason="clamscan не установлен")


@pytest.fixture
def eicar_bytes() -> bytes:
    return EICAR

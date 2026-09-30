"""H7 regression: Transport safety and port conflict detection.

Verifies:
- Two UdpReceiver instances bound to the same port without reuse_addr fail with OSError.
- When the first receiver is closed, a subsequent receiver can bind without error.
"""

import pytest
from securelink.transport.udp import UdpReceiver


def test_port_conflict_raises_oserror():
    """Attempting to bind a second UdpReceiver to the same port raises OSError."""
    port = 34567
    rx1 = UdpReceiver("127.0.0.1", port=port)
    try:
        with pytest.raises(OSError):
            _rx2 = UdpReceiver("127.0.0.1", port=port)
    finally:
        rx1.close()


def test_port_rebind_succeeds_after_close():
    """Closing the first UdpReceiver immediately frees the port for rebinding."""
    port = 34568
    rx1 = UdpReceiver("127.0.0.1", port=port)
    rx1.close()

    rx2 = UdpReceiver("127.0.0.1", port=port)
    try:
        assert rx2._sock is not None
    finally:
        rx2.close()

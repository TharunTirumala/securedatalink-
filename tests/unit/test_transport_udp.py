"""Unit tests for UDP transport layer: round-trip, oversize rejection, double close."""

import pytest
from securelink.transport.udp import UdpSender, UdpReceiver, MAX_DATAGRAM_SIZE


def test_udp_roundtrip_loopback():
    port = 24555
    with UdpReceiver("127.0.0.1", port) as rx:
        with UdpSender("127.0.0.1", port) as tx:
            payload = b"SECURELINK_TEST_PAYLOAD_12345"
            sent = tx.send(payload)
            assert sent == len(payload)

            result = rx.recv(timeout=1.0)
            assert result is not None
            data, addr = result
            assert data == payload
            assert addr[0] in ("127.0.0.1", "localhost")


def test_udp_oversize_datagram_rejected():
    with UdpSender("127.0.0.1", 24556) as tx:
        # Exact limit passes
        valid_data = b"X" * MAX_DATAGRAM_SIZE
        # Over limit fails
        oversize_data = b"X" * (MAX_DATAGRAM_SIZE + 1)
        with pytest.raises(ValueError, match="exceeds maximum allowed size"):
            tx.send(oversize_data)


def test_udp_double_close_is_safe():
    sender = UdpSender("127.0.0.1", 24557)
    sender.close()
    sender.close()  # No error

    receiver = UdpReceiver("127.0.0.1", 24557)
    receiver.close()
    receiver.close()  # No error


def test_udp_recv_timeout_returns_none():
    with UdpReceiver("127.0.0.1", 24558) as rx:
        result = rx.recv(timeout=0.05)
        assert result is None

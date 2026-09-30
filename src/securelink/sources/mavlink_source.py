"""UDP listener and queue for incoming MAVLink 2 datagrams."""

import time
import logging
from typing import Optional, Tuple, Iterator
from securelink.transport.udp import UdpReceiver

logger = logging.getLogger("securelink.sources.mavlink")


class MavlinkSource:
    """Listens on a UDP port for raw MAVLink 2 packets and yields them sequentially."""

    def __init__(self, host: str = "127.0.0.1", port: int = 14550):
        self.host = host
        self.port = int(port)
        self.receiver = UdpReceiver(self.host, self.port)
        self._msg_seq = 0
        self._closed = False

    def recv_packet(self, timeout: float = 0.5) -> Optional[Tuple[float, bytes, int]]:
        """Receive one MAVLink datagram. Returns (timestamp, raw_bytes, msg_seq) or None."""
        if self._closed:
            return None
        res = self.receiver.recv(timeout=timeout)
        if res is None:
            return None
        raw_bytes, _ = res
        ts = time.time()
        self._msg_seq += 1

        # Extract sequence number from MAVLink 2 header if possible (byte 4)
        seq_val = self._msg_seq
        if len(raw_bytes) >= 10 and raw_bytes[0] == 0xFD:
            seq_val = raw_bytes[4]

        return ts, raw_bytes, seq_val

    def stream_payloads(self, timeout: float = 0.5) -> Iterator[Tuple[float, bytes, int]]:
        """Stream packets until closed or stopped."""
        while not self._closed:
            pkt = self.recv_packet(timeout=timeout)
            if pkt is not None:
                yield pkt

    def close(self):
        self._closed = True
        self.receiver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

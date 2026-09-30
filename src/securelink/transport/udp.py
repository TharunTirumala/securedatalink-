"""UDP sender and receiver implementations enforcing 1200B max datagram size."""

import socket
import logging
from typing import Optional, Tuple
from securelink.transport.base import BaseSender, BaseReceiver

logger = logging.getLogger("securelink.transport")

MAX_DATAGRAM_SIZE: int = 1200


class UdpSender(BaseSender):
    """UDP datagram sender enforcing frame size limits."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = int(port)
        self._sock: Optional[socket.socket] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._closed = False

    def send(self, data: bytes) -> int:
        if self._closed or self._sock is None:
            raise RuntimeError("Cannot send on closed UdpSender")
        if len(data) > MAX_DATAGRAM_SIZE:
            raise ValueError(
                f"Datagram exceeds maximum allowed size of {MAX_DATAGRAM_SIZE} bytes (got {len(data)} bytes)"
            )
        return self._sock.sendto(data, (self.host, self.port))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class UdpReceiver(BaseReceiver):
    """UDP datagram receiver with configurable buffer and clean timeout exits."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9999,
        rcvbuf: int = 1048576,
        reuse_addr: bool = False,
    ):
        self.host = host
        self.port = int(port)
        self._sock: Optional[socket.socket] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._closed = False

        if reuse_addr:
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
        else:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                try:
                    self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                except OSError:
                    pass

        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except OSError:
            pass

        self._sock.bind((self.host, self.port))
        self.drain_buffer()

    def drain_buffer(self) -> int:
        """Discard any residual datagrams queued in the socket buffer."""
        if self._sock is None:
            return 0
        drained = 0
        prev_timeout = self._sock.gettimeout()
        self._sock.settimeout(0.0)
        try:
            while True:
                try:
                    self._sock.recvfrom(65535)
                    drained += 1
                except (BlockingIOError, socket.error):
                    break
        finally:
            self._sock.settimeout(prev_timeout)
        return drained

    def recv(self, timeout: float = 0.5) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        if self._closed or self._sock is None:
            return None
        self._sock.settimeout(timeout)
        try:
            data, addr = self._sock.recvfrom(65535)
            return data, addr
        except (socket.timeout, TimeoutError):
            return None
        except OSError as e:
            if self._closed:
                return None
            logger.debug("Socket error during recv: %s", e)
            return None

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

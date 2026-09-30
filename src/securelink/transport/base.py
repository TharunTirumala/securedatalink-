"""Abstract base classes for SecureLink network transport."""

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class Transport(ABC):
    """Abstract bidirectional transport interface."""

    @abstractmethod
    def send(self, data: bytes) -> int:
        """Send raw bytes over the transport. Returns bytes sent."""
        pass

    @abstractmethod
    def recv(self, timeout: float = 0.5) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """Receive bytes with timeout. Returns (data, (host, port)) or None on timeout."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close transport socket and release OS resources safely."""
        pass


class BaseSender(ABC):
    """Abstract unidirectional sender interface."""

    @abstractmethod
    def send(self, data: bytes) -> int:
        """Send raw bytes to the configured destination."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close underlying socket safely."""
        pass


class BaseReceiver(ABC):
    """Abstract unidirectional receiver interface."""

    @abstractmethod
    def recv(self, timeout: float = 0.5) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """Receive a datagram. Returns (data, remote_addr) or None on timeout."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close underlying socket safely."""
        pass

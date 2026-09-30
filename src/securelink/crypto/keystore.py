"""Cryptographic Keystore managing master secret, derived keys, and sender asymmetric keypairs."""

import os
from pathlib import Path
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from securelink.core.errors import UnknownSenderError
from securelink.crypto.kdf import derive


class KeyStore:
    def __init__(
        self,
        session_salt: bytes,
        aes_keys: Optional[Dict[int, bytes]] = None,
        sender_priv_keys: Optional[Dict[int, ec.EllipticCurvePrivateKey]] = None,
        sender_pub_keys: Optional[Dict[int, ec.EllipticCurvePublicKey]] = None,
        master_secret: Optional[bytes] = None,
    ):
        # Cache key: (epoch, sender_id, session_id)
        self._derived_cache: Dict[Tuple[int, int, int], Tuple[bytes, bytes]] = {}
        self._session_salt = session_salt
        self.session_salt = session_salt
        self.master_secret = (
            master_secret
            if master_secret is not None
            else (aes_keys.get(1) if aes_keys else os.urandom(32))
        )
        self.aes_keys = aes_keys or {1: self.master_secret}
        self.sender_priv_keys = sender_priv_keys or {}
        self.sender_pub_keys = sender_pub_keys or {}

        # Populate public keys from private keys if missing
        for sender_id, priv in self.sender_priv_keys.items():
            if sender_id not in self.sender_pub_keys:
                self.sender_pub_keys[sender_id] = priv.public_key()

    @property
    def session_salt(self) -> bytes:
        return self._session_salt

    @session_salt.setter
    def session_salt(self, salt: bytes):
        if len(salt) != 4:
            raise ValueError(f"Session salt must be exactly 4 bytes, got {len(salt)}")
        self._session_salt = salt
        self._derived_cache.clear()

    def get_session_salt(
        self,
        epoch: Optional[int] = None,
        sender_id: Optional[int] = None,
        session_id: int = 0,
    ) -> bytes:
        """Return session salt. If epoch is provided, derive per-epoch salt via HKDF."""
        if epoch is not None and self.master_secret is not None:
            sid = sender_id if sender_id is not None else 1
            return self._get_derived(epoch, sid, session_id)[1]
        return self.session_salt

    def set_session_salt(self, salt: bytes):
        self.session_salt = salt

    def _get_derived(self, epoch: int, sender_id: int, session_id: int = 0) -> Tuple[bytes, bytes]:
        cache_key = (epoch, sender_id, session_id)
        if cache_key in self._derived_cache:
            return self._derived_cache[cache_key]
        aes_key, salt = derive(self.master_secret, sender_id, epoch, session_id=session_id)
        self._derived_cache[cache_key] = (aes_key, salt)
        return aes_key, salt

    def to_public_keystore(self) -> "KeyStore":
        """Return a copy with private keys stripped, appropriate for receiver (RX) nodes."""
        return KeyStore(
            session_salt=self.session_salt,
            aes_keys=dict(self.aes_keys),
            sender_priv_keys={},
            sender_pub_keys=dict(self.sender_pub_keys),
            master_secret=self.master_secret,
        )

    def has_aes_key(self, epoch: int = 1, sender_id: Optional[int] = None, session_id: int = 0) -> bool:
        if self.master_secret is not None:
            return True
        return epoch in self.aes_keys

    def get_aes_key(self, epoch: int = 1, sender_id: Optional[int] = None, session_id: int = 0) -> bytes:
        if sender_id is None:
            if self.master_secret is not None:
                return self.master_secret
            if epoch in self.aes_keys:
                return self.aes_keys[epoch]
            raise KeyError(f"No AES key configured for epoch {epoch}")

        if self.master_secret is not None:
            return self._get_derived(epoch, sender_id, session_id)[0]
        if epoch not in self.aes_keys:
            raise KeyError(f"No AES key configured for epoch {epoch}")
        base_key = self.aes_keys[epoch]
        return derive(base_key, sender_id, epoch, session_id=session_id)[0]

    def is_sender_known(self, sender_id: int) -> bool:
        return sender_id in self.sender_pub_keys

    def get_sender_public_key(self, sender_id: int) -> ec.EllipticCurvePublicKey:
        if sender_id not in self.sender_pub_keys:
            raise UnknownSenderError(f"Sender ID {sender_id} is not recognized in keystore")
        return self.sender_pub_keys[sender_id]

    def get_sender_private_key(self, sender_id: int) -> ec.EllipticCurvePrivateKey:
        if sender_id not in self.sender_priv_keys:
            raise KeyError(f"Sender ID {sender_id} private key not available on this node")
        return self.sender_priv_keys[sender_id]

    def get_key_id(self, epoch: int = 1, sender_id: int = 1, session_id: int = 0) -> str:
        """Return the 8-character hex Key ID for (sender_id, epoch[, session_id])."""
        from securelink.crypto.kdf import key_id
        if self.master_secret is not None:
            return key_id(self.master_secret, sender_id, epoch, session_id=session_id)
        return "00000000"

    @classmethod
    def generate_ephemeral(cls, sender_ids=(1,), default_epoch: int = 1) -> "KeyStore":
        """Generate a fresh in-memory keystore for tests and simulations."""
        salt = os.urandom(4)
        master_secret = os.urandom(32)
        priv_keys = {}
        pub_keys = {}
        for sid in sender_ids:
            priv = ec.generate_private_key(ec.SECP256R1())
            priv_keys[sid] = priv
            pub_keys[sid] = priv.public_key()
        return cls(
            session_salt=salt,
            aes_keys={default_epoch: master_secret},
            sender_priv_keys=priv_keys,
            sender_pub_keys=pub_keys,
            master_secret=master_secret,
        )

    @classmethod
    def load_from_dir(cls, keys_dir: str | Path) -> "KeyStore":
        """Load keys from a filesystem directory."""
        dir_path = Path(keys_dir)
        salt_file = dir_path / "session_salt.bin"
        master_file = dir_path / "master.key"
        aes_file = dir_path / "shared_aes256.key"

        if not salt_file.exists():
            raise FileNotFoundError(f"Missing required session_salt.bin in {dir_path}")

        session_salt = salt_file.read_bytes()
        if len(session_salt) != 4:
            raise ValueError(f"session_salt.bin must be exactly 4 bytes, got {len(session_salt)}")

        if master_file.exists():
            master_secret = master_file.read_bytes()
            if len(master_secret) != 32:
                raise ValueError(f"master.key must be exactly 32 bytes, got {len(master_secret)}")
        elif aes_file.exists():
            master_secret = aes_file.read_bytes()
            if len(master_secret) != 32:
                raise ValueError(f"shared_aes256.key must be exactly 32 bytes, got {len(master_secret)}")
        else:
            raise FileNotFoundError(f"Missing required master.key (or shared_aes256.key) in {dir_path}")

        priv_keys = {}
        pub_keys = {}

        # Look for uav_sender_{id}_priv.pem and pub.pem
        for item in dir_path.glob("uav_sender_*_priv.pem"):
            parts = item.stem.split("_")
            if len(parts) >= 3 and parts[2].isdigit():
                sid = int(parts[2])
                priv = serialization.load_pem_private_key(item.read_bytes(), password=None)
                priv_keys[sid] = priv

        for item in dir_path.glob("uav_sender_*_pub.pem"):
            parts = item.stem.split("_")
            if len(parts) >= 3 and parts[2].isdigit():
                sid = int(parts[2])
                pub = serialization.load_pem_public_key(item.read_bytes())
                pub_keys[sid] = pub

        return cls(
            session_salt=session_salt,
            aes_keys={1: master_secret},
            sender_priv_keys=priv_keys,
            sender_pub_keys=pub_keys,
            master_secret=master_secret,
        )

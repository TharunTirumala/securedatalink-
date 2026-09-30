"""Transmitter cryptographic pipeline: telemetry -> header -> sign -> encrypt -> pack."""

import time
from typing import Tuple, Optional, Union, Callable
from securelink.core.types import Header, SecureFrame, TelemetryData
from securelink.core.errors import EpochExhausted
from securelink.protocol.constants import (
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_V1,
    PROTOCOL_VERSION_V2,
    PROTOCOL_VERSION_V3,
    DEFAULT_KEY_EPOCH,
    MAX_EPOCH_V1V2,
)
from securelink.protocol.codec import pack_header, pack_frame
from securelink.crypto.nonce import build_nonce
from securelink.crypto.aead import encrypt_gcm
from securelink.crypto.signer import sign_p256
from securelink.crypto.keystore import KeyStore


class TxPipeline:
    def __init__(
        self,
        keystore: KeyStore,
        sender_id: int = 1,
        key_epoch: int = DEFAULT_KEY_EPOCH,
        initial_seq: int = 1,
        rekey_every_packets: Optional[int] = None,
        on_rekey: Optional[Callable[[int, int, str], None]] = None,
        clock: Optional[Callable[[], float]] = None,
        session_id: int = 0,
    ):
        self.keystore = keystore
        self.sender_id = sender_id
        self.key_epoch = key_epoch
        self.current_seq = initial_seq
        self.highest_seq = initial_seq - 1
        self.rekey_every_packets = rekey_every_packets
        self.packets_in_epoch = 0
        self.on_rekey = on_rekey
        self.clock = clock or time.time
        self.session_id = session_id


    def rotate(self, reason: str = "auto"):
        """Bump key epoch, reset sequence counter to 0 and epoch packet count."""
        prev = self.key_epoch
        new_epoch = self.key_epoch + 1
        # V1/V2 use 1-byte epoch: guard against struct.error
        if self.session_id == 0 and new_epoch > MAX_EPOCH_V1V2:
            raise EpochExhausted(
                f"V1 key_epoch {new_epoch} exceeds 255. Use session_id != 0 for V3 (16-bit epoch)."
            )
        self.key_epoch = new_epoch
        self.highest_seq = 0
        self.packets_in_epoch = 0
        if self.on_rekey:
            self.on_rekey(prev, self.key_epoch, reason)

    def set_rekey_interval(self, n: int):
        self.rekey_every_packets = n

    def reset(self, initial_seq: int = 1):
        self.current_seq = initial_seq
        self.highest_seq = initial_seq - 1
        self.packets_in_epoch = 0


    def transmit(
        self,
        payload: Union[bytes, TelemetryData],
        timestamp: Optional[float] = None,
        seq: Optional[int] = None,
    ) -> Tuple[bytes, SecureFrame]:
        """Pack, sign, and encrypt outgoing telemetry data into a wire-ready frame."""
        # Auto-rotate if rekey threshold reached
        if self.rekey_every_packets is not None and self.packets_in_epoch >= self.rekey_every_packets:
            self.rotate()

        if isinstance(payload, TelemetryData):
            plaintext = payload.to_bytes()
        else:
            plaintext = payload

        if seq is None:
            self.highest_seq += 1
            frame_seq = self.highest_seq
        else:
            if seq <= self.highest_seq:
                raise ValueError(
                    f"Sequence number {seq} must be strictly greater than highest sequence {self.highest_seq} in epoch {self.key_epoch}"
                )
            self.highest_seq = seq
            frame_seq = seq

        self.packets_in_epoch += 1
        frame_ts = self.clock() if timestamp is None else timestamp
        # V3 uses 2-byte epoch when session_id is set; V1 uses 1-byte epoch (session_id=0)
        version = PROTOCOL_VERSION_V3 if self.session_id else PROTOCOL_VERSION_V1

        header = Header(
            version=version,
            sender_id=self.sender_id,
            key_epoch=self.key_epoch,
            seq=frame_seq,
            timestamp=frame_ts,
            session_id=self.session_id,
        )

        header_bytes = pack_header(header)
        session_salt = self.keystore.get_session_salt(epoch=self.key_epoch, sender_id=self.sender_id, session_id=self.session_id)
        nonce = build_nonce(session_salt, frame_seq)

        # 1. Digital Signature: ECDSA P-256 over (Header || Plaintext)
        priv_key = self.keystore.get_sender_private_key(self.sender_id)
        data_to_sign = header_bytes + plaintext
        signature = sign_p256(priv_key, data_to_sign)

        # 2. Authenticated Encryption: AES-256-GCM with per-sender derived key
        aes_key = self.keystore.get_aes_key(self.key_epoch, sender_id=self.sender_id, session_id=self.session_id)
        ciphertext_with_tag = encrypt_gcm(aes_key, nonce, plaintext, header_bytes)

        # 3. Assemble and serialize frame
        frame = SecureFrame(
            header=header,
            ciphertext_with_tag=ciphertext_with_tag,
            signature=signature,
        )
        wire_bytes = pack_frame(frame)
        return wire_bytes, frame

"""Receiver cryptographic verification pipeline implementing the strict 8-step check order."""

import time
from typing import Tuple, Optional, Dict, Any, Callable
from securelink.core.types import Verdict, Reason, Header
from securelink.core.errors import (
    FrameMalformedError,
    AeadDecryptionError,
    SignatureVerificationError,
)
from securelink.protocol.constants import (
    MIN_FRAME_SIZE,
    HEADER_SIZE_V1,
    HEADER_SIZE_V2,
    HEADER_SIZE_V3,
    PROTOCOL_VERSION_V1,
    PROTOCOL_VERSION_V2,
    PROTOCOL_VERSION_V3,
)
from securelink.protocol.codec import unpack_frame
from securelink.crypto.nonce import build_nonce
from securelink.crypto.aead import decrypt_gcm
from securelink.crypto.signer import verify_p256
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.pipeline.classifier import map_reason_to_verdict


class RxPipeline:
    def __init__(
        self,
        keystore: KeyStore,
        replay_guard: Optional[ReplayGuard] = None,
        rekey_grace_epochs: int = 1,
        rekey_max_jump: int = 8,
        operator_state: Optional[Any] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.keystore = keystore
        self.replay_guard = replay_guard or ReplayGuard(clock=clock)
        self.rekey_grace_epochs = rekey_grace_epochs
        self.rekey_max_jump = rekey_max_jump
        self.operator_state = operator_state
        self.highest_auth_epoch: Dict[int, int] = {}
        self.clock = clock or time.time

    def verify_frame(
        self,
        raw_frame_bytes: bytes,
        current_time: Optional[float] = None,
    ) -> Tuple[Reason, Optional[bytes], Optional[Header]]:
        """Verify and decrypt incoming wire frame, returning low-level verification Reason.

        Returns (Reason, Plaintext, Header).
        """
        now = self.clock() if current_time is None else current_time

        # Step 1: Parse the frame & validate length and protocol version
        if len(raw_frame_bytes) < MIN_FRAME_SIZE:
            return Reason.FRAME_TOO_SHORT, None, None
        if len(raw_frame_bytes) > 65535:
            return Reason.FRAME_MALFORMED, None, None

        try:
            frame = unpack_frame(raw_frame_bytes)
        except FrameMalformedError:
            return Reason.FRAME_MALFORMED, None, None

        header = frame.header
        if header.version not in (PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V2, PROTOCOL_VERSION_V3):
            return Reason.FRAME_MALFORMED, None, None

        # Authenticate the exact received wire bytes for AAD, avoiding repack round-trip
        if header.version == PROTOCOL_VERSION_V3:
            hdr_size = HEADER_SIZE_V3
        elif header.version == PROTOCOL_VERSION_V2:
            hdr_size = HEADER_SIZE_V2
        else:
            hdr_size = HEADER_SIZE_V1
        header_bytes = raw_frame_bytes[:hdr_size]

        # Step 2: Check operator blocked senders & sender is known
        if self.operator_state and self.operator_state.is_blocked(header.sender_id):
            return Reason.SENDER_BLOCKED, None, header

        if not self.keystore.is_sender_known(header.sender_id):
            return Reason.UNKNOWN_SENDER, None, header

        # Step 3: Epoch lookahead check (pre-auth)
        # If sender has been seen before, enforce max_jump forward window.
        # If sender is NEW (no prior state), skip the pre-auth check entirely:
        # attempt decrypt+verify first; only advance epoch after both pass.
        if header.sender_id in self.highest_auth_epoch:
            highest_epoch = self.highest_auth_epoch[header.sender_id]
            if header.key_epoch > highest_epoch + self.rekey_max_jump:
                return Reason.UNKNOWN_EPOCH, None, header

        if not self.keystore.has_aes_key(header.key_epoch, sender_id=header.sender_id, session_id=header.session_id):
            return Reason.UNKNOWN_EPOCH, None, header

        # Step 4: Decrypt with GCM (AAD = Header)
        session_salt = self.keystore.get_session_salt(
            epoch=header.key_epoch,
            sender_id=header.sender_id,
            session_id=header.session_id,
        )
        nonce = build_nonce(session_salt, header.seq)
        try:
            aes_key = self.keystore.get_aes_key(header.key_epoch, sender_id=header.sender_id, session_id=header.session_id)
            plaintext = decrypt_gcm(aes_key, nonce, frame.ciphertext_with_tag, header_bytes)
        except AeadDecryptionError:
            return Reason.GCM_TAG_MISMATCH, None, header

        # Step 5: Verify ECDSA signature over (Header || Plaintext)
        try:
            pub_key = self.keystore.get_sender_public_key(header.sender_id)
            data_to_verify = header_bytes + plaintext
            verify_p256(pub_key, frame.signature, data_to_verify)
        except SignatureVerificationError:
            return Reason.INVALID_SIGNATURE, None, header

        # Step 6: Post-authentication epoch grace check
        if header.sender_id in self.highest_auth_epoch:
            highest_epoch = self.highest_auth_epoch[header.sender_id]
            if header.key_epoch < highest_epoch - self.rekey_grace_epochs:
                return Reason.EPOCH_EXPIRED, None, header

        # Advance highest authenticated epoch for this sender (only after full auth)
        if header.key_epoch > self.highest_auth_epoch.get(header.sender_id, 0):
            self.highest_auth_epoch[header.sender_id] = header.key_epoch

        # Step 7: Check timestamp window and sequence number with ReplayGuard
        is_fresh, replay_reason = self.replay_guard.check_and_update(
            sender_id=header.sender_id,
            seq=header.seq,
            timestamp=header.timestamp,
            current_time=now,
            epoch=header.key_epoch,
            session_id=header.session_id,
        )
        if not is_fresh:
            return replay_reason, None, header

        # Step 8: All checks passed -> OK
        return Reason.OK, plaintext, header

    def process_frame(
        self,
        raw_frame_bytes: bytes,
        current_time: Optional[float] = None,
    ) -> Tuple[Verdict, Reason, Optional[bytes], Optional[Header]]:
        """Verify and classify incoming wire frame, returning high-level Verdict and Reason."""
        reason, plaintext, header = self.verify_frame(raw_frame_bytes, current_time)
        verdict = map_reason_to_verdict(reason)
        return verdict, reason, plaintext, header

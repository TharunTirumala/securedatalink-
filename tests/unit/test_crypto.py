"""Unit tests for SecureLink cryptographic components."""

import os
import pytest
from securelink.crypto.nonce import build_nonce
from securelink.crypto.aead import encrypt_gcm, decrypt_gcm
from securelink.crypto.signer import sign_p256, verify_p256
from securelink.crypto.keystore import KeyStore
from securelink.core.errors import (
    AeadDecryptionError,
    SignatureVerificationError,
    UnknownSenderError,
)


def flip_single_bit(data: bytes, byte_idx: int = 0) -> bytes:
    """Helper to flip the lowest bit of a byte at index."""
    b = bytearray(data)
    b[byte_idx] ^= 0x01
    return bytes(b)


def test_nonce_generation():
    salt = b"\x01\x02\x03\x04"
    seq = 42
    nonce = build_nonce(salt, seq)
    assert len(nonce) == 12
    assert nonce[:4] == salt
    assert nonce[4:] == b"\x00\x00\x00\x00\x00\x00\x00\x2a"


def test_aead_gcm_roundtrip_and_bit_flips():
    key = os.urandom(32)
    salt = os.urandom(4)
    seq = 100
    nonce = build_nonce(salt, seq)
    aad = b"header_aad_data_20b!"
    plaintext = b'{"telemetry": "sample_gps_data", "lat": 17.385}'

    # Encrypt
    ct_with_tag = encrypt_gcm(key, nonce, plaintext, aad)
    assert len(ct_with_tag) == len(plaintext) + 16

    # Decrypt
    decrypted = decrypt_gcm(key, nonce, ct_with_tag, aad)
    assert decrypted == plaintext

    # Flipped bit in ciphertext
    corrupted_ct = flip_single_bit(ct_with_tag, byte_idx=2)
    with pytest.raises(AeadDecryptionError):
        decrypt_gcm(key, nonce, corrupted_ct, aad)

    # Flipped bit in tag (last 16 bytes)
    corrupted_tag = flip_single_bit(ct_with_tag, byte_idx=len(ct_with_tag) - 1)
    with pytest.raises(AeadDecryptionError):
        decrypt_gcm(key, nonce, corrupted_tag, aad)

    # Flipped bit in AAD
    corrupted_aad = flip_single_bit(aad, byte_idx=0)
    with pytest.raises(AeadDecryptionError):
        decrypt_gcm(key, nonce, ct_with_tag, corrupted_aad)

    # Flipped bit in nonce
    corrupted_nonce = flip_single_bit(nonce, byte_idx=0)
    with pytest.raises(AeadDecryptionError):
        decrypt_gcm(key, corrupted_nonce, ct_with_tag, aad)


def test_ecdsa_p256_roundtrip_and_bit_flips():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    priv = keystore.get_sender_private_key(1)
    pub = keystore.get_sender_public_key(1)

    message = b"header_data_and_plaintext_payload"
    sig = sign_p256(priv, message)
    assert len(sig) == 64

    # Verify succeeds
    assert verify_p256(pub, sig, message) is True

    # Flipped bit in signature
    corrupted_sig = flip_single_bit(sig, byte_idx=5)
    with pytest.raises(SignatureVerificationError):
        verify_p256(pub, corrupted_sig, message)

    # Flipped bit in message
    corrupted_msg = flip_single_bit(message, byte_idx=0)
    with pytest.raises(SignatureVerificationError):
        verify_p256(pub, sig, corrupted_msg)


def test_keystore_known_senders():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1, 2])
    assert keystore.is_sender_known(1) is True
    assert keystore.is_sender_known(2) is True
    assert keystore.is_sender_known(99) is False

    with pytest.raises(UnknownSenderError):
        keystore.get_sender_public_key(99)


def test_multi_sender_derived_keys_different():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1, 2])
    key1 = keystore.get_aes_key(epoch=1, sender_id=1)
    key2 = keystore.get_aes_key(epoch=1, sender_id=2)
    base_key = keystore.get_aes_key(epoch=1, sender_id=None)

    assert key1 != key2
    assert key1 != base_key
    assert key2 != base_key
    assert len(key1) == 32
    assert len(key2) == 32


def test_epoch_and_sender_kdf_derivation():
    """Verify different epochs and senders yield distinct keys and salts with valid AEAD round-trips."""
    from securelink.crypto.nonce import build_nonce
    from securelink.crypto.aead import encrypt_gcm, decrypt_gcm
    keystore = KeyStore.generate_ephemeral(sender_ids=[1, 2])

    k_e1 = keystore.get_aes_key(epoch=1, sender_id=1)
    s_e1 = keystore.get_session_salt(epoch=1, sender_id=1)

    k_e2 = keystore.get_aes_key(epoch=2, sender_id=1)
    s_e2 = keystore.get_session_salt(epoch=2, sender_id=1)

    k_s2 = keystore.get_aes_key(epoch=1, sender_id=2)
    s_s2 = keystore.get_session_salt(epoch=1, sender_id=2)

    # 1. Different epochs produce distinct keys and salts
    assert k_e1 != k_e2
    assert s_e1 != s_e2

    # 2. Different senders produce distinct keys and salts
    assert k_e1 != k_s2
    assert s_e1 != s_s2

    # 3. Round-trip per epoch works
    plaintext = b"Tactical Waypoint 123.456"
    aad = b"HeaderBytesEpoch2"
    nonce_e2 = build_nonce(s_e2, seq=1)
    ct_tag = encrypt_gcm(k_e2, nonce_e2, plaintext, aad)

    decrypted = decrypt_gcm(k_e2, nonce_e2, ct_tag, aad)
    assert decrypted == plaintext

    # Decrypting with epoch 1 keys fails
    nonce_e1 = build_nonce(s_e1, seq=1)
    with pytest.raises(AeadDecryptionError):
        decrypt_gcm(k_e1, nonce_e1, ct_tag, aad)



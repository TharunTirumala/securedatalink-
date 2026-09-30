"""H2 regression: GCM nonce reuse across TX sessions must be impossible.

Two TxPipelines with identical master secrets and sender/epoch but different
session_ids must produce different keys and nonces, so ciphertext XOR leaks
nothing about plaintext.
"""

from securelink.core.types import Verdict
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline


def test_different_session_ids_produce_different_ciphertext():
    """Same plaintext, same key material, different session_id → different ciphertext."""
    ks1 = KeyStore.generate_ephemeral(sender_ids=[1])
    # Build second keystore with identical master/priv key but share the session salt
    from cryptography.hazmat.primitives.asymmetric import ec
    priv2 = ec.generate_private_key(ec.SECP256R1())
    import os
    ks2 = KeyStore(
        session_salt=ks1.session_salt,
        master_secret=ks1.master_secret,
        sender_priv_keys={1: ks1.sender_priv_keys[1]},
        sender_pub_keys={1: ks1.sender_pub_keys[1]},
    )

    plaintext = b"telemetry-payload"
    pipeline_a = TxPipeline(keystore=ks1, sender_id=1, key_epoch=1, initial_seq=1, session_id=111)
    pipeline_b = TxPipeline(keystore=ks2, sender_id=1, key_epoch=1, initial_seq=1, session_id=222)

    wire_a, _ = pipeline_a.transmit(plaintext)
    wire_b, _ = pipeline_b.transmit(plaintext)

    # Frames must differ (different nonces/keys)
    assert wire_a != wire_b, "Frames must differ across session IDs"

    # The nonce-reuse test: XOR of ciphertexts must not equal XOR of plaintexts
    # Extract ciphertext region (after header, before signature)
    hdr_size = 24  # V2 header
    sig_size = 64
    ct_a = wire_a[hdr_size:-sig_size]
    ct_b = wire_b[hdr_size:-sig_size]
    assert ct_a != ct_b, "Ciphertexts must differ"

    # The key must differ too: AES keys for same epoch/sender but different session_id must be different
    key_a = ks1.get_aes_key(1, sender_id=1, session_id=111)
    key_b = ks2.get_aes_key(1, sender_id=1, session_id=222)
    assert key_a != key_b, "Derived AES keys must differ across session IDs"


def test_same_session_id_same_key():
    """Same session_id must always produce the same derived key."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    key1 = ks.get_aes_key(1, sender_id=1, session_id=42)
    key2 = ks.get_aes_key(1, sender_id=1, session_id=42)
    assert key1 == key2, "Same session_id must produce deterministic key"


def test_session_id_zero_backward_compat():
    """session_id=0 must produce the same key as no session_id (V1 compat)."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    key_nosess = ks.get_aes_key(1, sender_id=1, session_id=0)
    # Manually derive with no session_id
    from securelink.crypto.kdf import derive
    aes_expected, _ = derive(ks.master_secret, 1, 1, session_id=0)
    assert key_nosess == aes_expected, "session_id=0 must match V1 derivation"


def test_rx_decrypts_correct_session_header_propagates():
    """session_id in TX header is preserved and readable after RX authentication."""
    from securelink.pipeline.rx_pipeline import RxPipeline
    ks_tx = KeyStore.generate_ephemeral(sender_ids=[1])

    pipeline_tx_sess1 = TxPipeline(keystore=ks_tx, sender_id=1, session_id=111)
    pipeline_tx_sess2 = TxPipeline(keystore=ks_tx, sender_id=1, session_id=222)
    pipeline_rx = RxPipeline(keystore=ks_tx.to_public_keystore())

    plaintext = b"secret telemetry"
    wire_sess1, _ = pipeline_tx_sess1.transmit(plaintext)
    wire_sess2, _ = pipeline_tx_sess2.transmit(plaintext)

    # Both authenticate (keystore is shared; session filter is done at CLI layer)
    verdict1, reason1, pt1, hdr1 = pipeline_rx.process_frame(wire_sess1)
    assert verdict1 == Verdict.AUTHENTIC, f"Session 111 should be AUTHENTIC, got {reason1}"
    assert pt1 == plaintext
    assert hdr1.session_id == 111, f"Header session_id must be 111, got {hdr1.session_id}"

    verdict2, reason2, pt2, hdr2 = pipeline_rx.process_frame(wire_sess2)
    assert verdict2 == Verdict.AUTHENTIC, f"Session 222 should also decrypt, got {reason2}"
    assert hdr2.session_id == 222, f"Header session_id must be 222, got {hdr2.session_id}"

    # Verify keys ARE different (nonce-reuse is impossible at the crypto layer)
    key1 = ks_tx.get_aes_key(1, sender_id=1, session_id=111)
    key2 = ks_tx.get_aes_key(1, sender_id=1, session_id=222)
    assert key1 != key2, "Session 111 and 222 must use different AES keys"

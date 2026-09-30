"""H4 regression: Epoch byte overflow at 256 must be caught before struct.error.

V1 pipeline (session_id=0) must raise EpochExhausted when epoch > 255.
V3 pipeline (session_id != 0) must support epochs up to 65535.
"""

import pytest
from securelink.core.errors import EpochExhausted
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline


def test_v1_epoch_255_ok():
    """Epoch 255 must succeed on V1 pipeline.
    
    With rekey_every=1, first transmit sends epoch=254 and increments packets_in_epoch to 1.
    Second transmit auto-rotates to epoch=255 (still within 1-byte range).
    """
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=ks, sender_id=1, key_epoch=254, rekey_every_packets=1, session_id=0)
    tx.transmit(b"data-1")  # sends epoch=254, increments counter
    wire, frame = tx.transmit(b"data-2")  # rotates to 255 at start, sends epoch=255
    assert frame.header.key_epoch == 255


def test_v1_epoch_256_raises():
    """Epoch 256 must raise EpochExhausted on V1 pipeline (session_id=0).
    
    Third transmit attempts to rotate to 256 which overflows the 1-byte field.
    """
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=ks, sender_id=1, key_epoch=254, rekey_every_packets=1, session_id=0)
    tx.transmit(b"data-1")  # epoch=254
    tx.transmit(b"data-2")  # rotate to 255, send at 255
    with pytest.raises(EpochExhausted):
        tx.transmit(b"data-3")  # attempts rotate to 256 → raises


def test_v3_epoch_256_ok():
    """Epoch 256 must succeed on V3 pipeline (session_id != 0)."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=ks, sender_id=1, key_epoch=254, rekey_every_packets=1, session_id=42)
    tx.transmit(b"data-1")  # epoch=254
    tx.transmit(b"data-2")  # epoch=255
    wire, frame = tx.transmit(b"data-3")  # rotates to 256 (valid in V3)
    assert frame.header.key_epoch == 256
    assert frame.header.version == 3  # V3


def test_v3_epoch_65535_max():
    """Epoch 65535 is within V3 range."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=ks, sender_id=1, key_epoch=65534, rekey_every_packets=1, session_id=42)
    tx.transmit(b"data-1")  # epoch=65534
    wire, frame = tx.transmit(b"data-2")  # rotates to 65535
    assert frame.header.key_epoch == 65535


def test_v3_epoch_and_rx_authenticate():
    """V3 frames (epoch 256) can be authenticated by RxPipeline."""
    from securelink.pipeline.rx_pipeline import RxPipeline
    from securelink.core.types import Verdict
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=ks, sender_id=1, key_epoch=254, rekey_every_packets=1, session_id=99)
    rx = RxPipeline(keystore=ks.to_public_keystore())

    wire_254, f254 = tx.transmit(b"epoch-254")
    v, r, pt, hdr = rx.process_frame(wire_254)
    assert v == Verdict.AUTHENTIC, f"Epoch 254 frame failed: {r}"

    wire_255, f255 = tx.transmit(b"epoch-255")  # auto-rotates to 255
    assert f255.header.key_epoch == 255
    v2, r2, _, _ = rx.process_frame(wire_255)
    assert v2 == Verdict.AUTHENTIC, f"Epoch 255 frame failed: {r2}"

    wire_256, f256 = tx.transmit(b"epoch-256")  # auto-rotates to 256 (V3 only)
    assert f256.header.key_epoch == 256
    assert f256.header.version == 3
    v3, r3, pt3, hdr3 = rx.process_frame(wire_256)
    assert v3 == Verdict.AUTHENTIC, f"Epoch 256 frame failed: {r3}"

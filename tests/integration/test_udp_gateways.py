"""Integration tests for TX and RX gateways over real UDP sockets."""

import time
import json
import socket
import threading
from pathlib import Path
import pytest

from securelink.transport.udp import UdpSender, UdpReceiver
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.core.types import Verdict, Reason


def test_tx_rx_direct_protect_on(tmp_path):
    port = 25101
    keys_dir = Path("keys")
    keystore = KeyStore.load_from_dir(keys_dir)

    rx_pipeline = RxPipeline(keystore=keystore)
    receiver = UdpReceiver("127.0.0.1", port)
    sender = UdpSender("127.0.0.1", port)
    tx_pipeline = TxPipeline(keystore=keystore, sender_id=1, session_id=12345)

    try:
        # Transmit 10 frames
        for seq in range(1, 11):
            raw_payload = f"DATALINK_MSG_{seq}".encode("utf-8")
            wire_bytes, frame = tx_pipeline.transmit(raw_payload)
            sender.send(wire_bytes)

            res = receiver.recv(timeout=1.0)
            assert res is not None
            rx_data, _ = res
            verdict, reason, pt, hdr = rx_pipeline.process_frame(rx_data)
            assert verdict == Verdict.AUTHENTIC
            assert reason == Reason.OK
            assert pt == raw_payload
            assert hdr.seq == seq
            assert hdr.session_id == 12345
    finally:
        sender.close()
        receiver.close()


def test_tx_restart_clean_rx_and_cross_session_replay(tmp_path):
    port = 25102
    keys_dir = Path("keys")
    keystore = KeyStore.load_from_dir(keys_dir)

    # One single running RX throughout test
    rx_pipeline = RxPipeline(keystore=keystore)
    receiver = UdpReceiver("127.0.0.1", port)
    sender = UdpSender("127.0.0.1", port)

    try:
        # --- TX RUN 1 (Session A) ---
        tx1 = TxPipeline(keystore=keystore, sender_id=1, session_id=11111)
        sess1_frames = []
        for seq in range(1, 6):
            wb, _ = tx1.transmit(f"RUN1_MSG_{seq}".encode("utf-8"))
            sess1_frames.append(wb)
            sender.send(wb)
            res = receiver.recv(timeout=1.0)
            assert res is not None
            verdict, reason, _, _ = rx_pipeline.process_frame(res[0])
            assert verdict == Verdict.AUTHENTIC

        # --- TX RUN 2 (Session B) - RX NOT RESTARTED ---
        tx2 = TxPipeline(keystore=keystore, sender_id=1, session_id=22222)
        for seq in range(1, 6):
            wb, _ = tx2.transmit(f"RUN2_MSG_{seq}".encode("utf-8"))
            sender.send(wb)
            res = receiver.recv(timeout=1.0)
            assert res is not None
            verdict, reason, _, hdr = rx_pipeline.process_frame(res[0])
            # Must NOT be marked REPLAYED despite starting at seq 1 again!
            assert verdict == Verdict.AUTHENTIC
            assert reason == Reason.OK
            assert hdr.session_id == 22222

        # --- Replaying frame from Session 1 during Session 2 ---
        sender.send(sess1_frames[0])  # Frame seq 1 from Session 1
        res = receiver.recv(timeout=1.0)
        assert res is not None
        verdict, reason, _, hdr = rx_pipeline.process_frame(res[0])
        assert verdict == Verdict.REPLAYED
        assert reason == Reason.DUPLICATE_SEQ
        assert hdr.session_id == 11111
    finally:
        sender.close()
        receiver.close()


def test_random_bytes_rejected_without_crash():
    port = 25103
    keys_dir = Path("keys")
    keystore = KeyStore.load_from_dir(keys_dir)
    rx_pipeline = RxPipeline(keystore=keystore)

    receiver = UdpReceiver("127.0.0.1", port)
    sender = UdpSender("127.0.0.1", port)
    try:
        # Send garbage packet
        garbage = b"\xFF\x00\xAA\x55" * 30
        sender.send(garbage)
        res = receiver.recv(timeout=1.0)
        assert res is not None
        verdict, reason, pt, hdr = rx_pipeline.process_frame(res[0])
        assert verdict in (Verdict.TAMPERED, Verdict.SPOOFED)
        assert pt is None
    finally:
        sender.close()
        receiver.close()

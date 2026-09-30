"""Integration tests for SimulationRunner seed handling, reproducibility, and metrics."""

import pytest
from securelink.simulation.runner import SimulationRunner
from securelink.core.config import AppConfig, AttackConfig
from securelink.crypto.keystore import KeyStore


def test_same_explicit_seed_reproducibility():
    """Requirement 5: Same explicit seed twice gives identical verdict sequences and counts."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    config = AppConfig()

    hostile_attacks = AttackConfig(tamper_prob=0.2, replay_prob=0.2, spoof_prob=0.1, drop_prob=0.1)

    verdicts1, verdicts2 = [], []
    r1 = SimulationRunner(config=config, keystore=keystore, event_callback=lambda e: verdicts1.append(e.verdict))
    stats1 = r1.run(count=80, rate_pps=0, seed=777, attack_config=hostile_attacks)

    r2 = SimulationRunner(config=config, keystore=keystore, event_callback=lambda e: verdicts2.append(e.verdict))
    stats2 = r2.run(count=80, rate_pps=0, seed=777, attack_config=hostile_attacks)

    assert stats1.seed == 777
    assert stats2.seed == 777
    assert verdicts1 == verdicts2
    assert stats1.authentic == stats2.authentic
    assert stats1.tampered == stats2.tampered
    assert stats1.replayed == stats2.replayed
    assert stats1.spoofed == stats2.spoofed
    assert stats1.dropped == stats2.dropped


def test_seed_none_gives_different_seeds_and_outputs():
    """Requirement 5: seed=None twice gives different seeds and different attack positions."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    config = AppConfig()
    attacks = AttackConfig(tamper_prob=0.25, replay_prob=0.25, spoof_prob=0.1, drop_prob=0.1)

    verdicts1, verdicts2 = [], []
    r1 = SimulationRunner(config=config, keystore=keystore, event_callback=lambda e: verdicts1.append(e.verdict))
    stats1 = r1.run(count=100, rate_pps=0, seed=None, attack_config=attacks)

    r2 = SimulationRunner(config=config, keystore=keystore, event_callback=lambda e: verdicts2.append(e.verdict))
    stats2 = r2.run(count=100, rate_pps=0, seed=None, attack_config=attacks)

    assert stats1.seed is not None
    assert stats2.seed is not None
    assert stats1.seed != stats2.seed
    assert verdicts1 != verdicts2


def test_zero_attack_probabilities_100_percent_authentic():
    """Requirement 5: All attack probabilities = 0 gives 100% AUTHENTIC for any seed."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    config = AppConfig()
    clean_attacks = AttackConfig(tamper_prob=0.0, replay_prob=0.0, spoof_prob=0.0, drop_prob=0.0)

    for test_seed in (None, 42, 999999):
        runner = SimulationRunner(config=config, keystore=keystore)
        stats = runner.run(count=50, rate_pps=0, seed=test_seed, attack_config=clean_attacks)
        assert stats.total == 50
        assert stats.authentic == 50
        assert stats.false_rejects == 0
        assert stats.false_accepts == 0


def test_tamper_probability_one_zero_false_accepts():
    """Requirement 5: Tamper probability = 1.0 gives 0 false accepts for any seed."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    config = AppConfig()
    all_tamper = AttackConfig(tamper_prob=1.0, replay_prob=0.0, spoof_prob=0.0, drop_prob=0.0)

    for test_seed in (None, 1234):
        runner = SimulationRunner(config=config, keystore=keystore)
        stats = runner.run(count=50, rate_pps=0, seed=test_seed, attack_config=all_tamper)
        assert stats.total == 50
        assert stats.false_accepts == 0
        assert stats.authentic == 0
        assert stats.correctly_rejected == 50


def test_rate_pps_zero_runs_unthrottled():
    """Verify rate_pps=0 executes without artificial delays."""
    import time
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    config = AppConfig()
    runner = SimulationRunner(config=config, keystore=keystore)
    t0 = time.perf_counter()
    stats = runner.run(count=100, rate_pps=0, seed=42)
    elapsed = time.perf_counter() - t0
    assert stats.total == 100
    # 100 packets at default 20 pps would take ~5.0s; unthrottled must finish in under 1.0s
    assert elapsed < 1.0


def test_stop_before_run_aborts_immediately():
    """Verify calling stop() before run() starts results in immediate exit."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    config = AppConfig()
    runner = SimulationRunner(config=config, keystore=keystore)
    runner.stop()
    stats = runner.run(count=100, rate_pps=0, seed=42)
    assert stats.total == 0


def test_500_packet_run_with_rekeying_zero_false_rates():
    """Requirement 1: 500-packet run with rekey_every_packets=50 yields 0 FA and 0 FR."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    cfg = AppConfig()
    cfg.simulation.rekey_every_packets = 50
    clean_attacks = AttackConfig(tamper_prob=0.0, replay_prob=0.0, spoof_prob=0.0, drop_prob=0.0)

    runner = SimulationRunner(config=cfg, keystore=keystore)
    stats = runner.run(count=500, rate_pps=0, seed=42, attack_config=clean_attacks)
    assert stats.total == 500
    assert stats.authentic == 500
    assert stats.false_accepts == 0
    assert stats.false_rejects == 0


def test_blocked_sender_classified_as_spoofed_without_false_rejects():
    """Requirement 4: Blocked sender yields SPOOFED/SENDER_BLOCKED and is not counted as false reject."""
    from securelink.pipeline.operator_state import OperatorState
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    cfg = AppConfig()
    clean_attacks = AttackConfig(tamper_prob=0.0, replay_prob=0.0, spoof_prob=0.0, drop_prob=0.0)
    op_state = OperatorState()
    op_state.block_sender(1)

    runner = SimulationRunner(config=cfg, keystore=keystore, operator_state=op_state)
    stats = runner.run(count=20, rate_pps=0, seed=42, attack_config=clean_attacks)
    assert stats.total == 20
    assert stats.spoofed == 20
    assert stats.operator_blocked == 20
    assert stats.false_rejects == 0


def test_multi_epoch_reproducibility_with_fixed_master_secret():
    """Requirement 5: Same explicit seed produces identical stats across multi-epoch runs."""
    from cryptography.hazmat.primitives.asymmetric import ec
    master = b"\x77" * 32
    salt = b"\x11\x22\x33\x44"
    priv = ec.generate_private_key(ec.SECP256R1())
    k1 = KeyStore(session_salt=salt, master_secret=master, sender_priv_keys={1: priv})
    k2 = KeyStore(session_salt=salt, master_secret=master, sender_priv_keys={1: priv})

    cfg = AppConfig()
    cfg.simulation.rekey_every_packets = 25
    attacks = AttackConfig(tamper_prob=0.1, replay_prob=0.1, spoof_prob=0.05, drop_prob=0.05)

    r1 = SimulationRunner(config=cfg, keystore=k1)
    s1 = r1.run(count=100, rate_pps=0, seed=999, attack_config=attacks, run_id="fixed_test")

    r2 = SimulationRunner(config=cfg, keystore=k2)
    s2 = r2.run(count=100, rate_pps=0, seed=999, attack_config=attacks, run_id="fixed_test")

    deterministic_keys = [
        "seed", "run_id", "total", "authentic", "tampered", "replayed", "spoofed", "dropped",
        "operator_blocked", "false_accepts", "false_rejects", "attacks_injected",
        "correctly_rejected", "correctly_rejected_pct", "exact_label_matches", "exact_label_match_pct"
    ]
    for k in deterministic_keys:
        assert s1.to_dict()[k] == s2.to_dict()[k]




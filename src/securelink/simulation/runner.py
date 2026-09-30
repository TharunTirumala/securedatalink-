"""Simulation Runner coordinating synthetic source, TX, adversarial channel, RX, and metrics."""

import time
import argparse
import secrets
import random
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Union
from securelink.core.config import AppConfig, AttackConfig
from securelink.core.types import Event, Verdict, Reason
from securelink.crypto.nonce import generate_session_salt
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.sources.synthetic import SyntheticTelemetrySource
from securelink.simulation.channel import AdversarialChannel
from securelink.audit.threat_log import ThreatLogger


@dataclass
class SimulationStats:
    seed: Optional[int] = None
    run_id: Optional[str] = None
    total: int = 0
    authentic: int = 0
    tampered: int = 0
    replayed: int = 0
    spoofed: int = 0
    dropped: int = 0
    operator_blocked: int = 0
    false_accepts: int = 0
    false_rejects: int = 0
    attacks_injected: int = 0
    correctly_rejected: int = 0
    exact_label_matches: int = 0
    latencies_us: List[float] = field(default_factory=list)
    epoch_stats: Dict[int, Dict[str, Any]] = field(default_factory=dict)

    def calculate_percentiles(self) -> Dict[str, float]:
        if not self.latencies_us:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
        s, n = sorted(self.latencies_us), len(self.latencies_us)
        return {"p50": s[int(n * 0.50)], "p95": s[min(n - 1, int(n * 0.95))], "p99": s[min(n - 1, int(n * 0.99))]}


    def to_dict(self) -> Dict[str, Any]:
        pct = self.calculate_percentiles()
        c_pct = ((self.correctly_rejected / self.attacks_injected * 100.0) if self.attacks_injected > 0 else 100.0)
        e_pct = ((self.exact_label_matches / self.total * 100.0) if self.total > 0 else 100.0)
        return {
            "seed": self.seed, "run_id": self.run_id, "total": self.total,
            "authentic": self.authentic, "tampered": self.tampered,
            "replayed": self.replayed, "spoofed": self.spoofed, "dropped": self.dropped,
            "operator_blocked": self.operator_blocked, "false_accepts": self.false_accepts,
            "false_rejects": self.false_rejects, "attacks_injected": self.attacks_injected,
            "correctly_rejected": self.correctly_rejected, "correctly_rejected_pct": round(c_pct, 2),
            "exact_label_matches": self.exact_label_matches, "exact_label_match_pct": round(e_pct, 2),
            "p50_us": pct["p50"], "p95_us": pct["p95"], "p99_us": pct["p99"],
            "epoch_stats": self.epoch_stats,
        }




class SimulationRunner:
    def __init__(
        self,
        config: Optional[AppConfig] = None,
        keystore: Optional[KeyStore] = None,
        event_callback: Optional[Callable[[Event], None]] = None,
        threat_logger: Optional[ThreatLogger] = None,
        operator_state: Optional[Any] = None,
    ):
        self.config = config or AppConfig.load()
        sid = self.config.simulation.sender_id
        if keystore is not None:
            self.keystore = keystore
        else:
            try:
                self.keystore = KeyStore.load_from_dir("keys")
                if not self.keystore.is_sender_known(sid):
                    self.keystore = KeyStore.generate_ephemeral(sender_ids=[sid])
            except (FileNotFoundError, ValueError, KeyError):
                self.keystore = KeyStore.generate_ephemeral(sender_ids=[sid])

        self.event_callback = event_callback
        self.threat_logger = threat_logger or ThreatLogger(self.config.threat_log_path)
        self.operator_state = operator_state
        self.stats = SimulationStats()
        self.stop_event = threading.Event()
        self._epoch_wire_frames: Dict[int, bytes] = {}
        self._frame_lock = threading.Lock()
        self._pending_injections: List[Tuple[bytes, str]] = []
        self._pending_rekey_interval: Optional[int] = None

    def stop(self):
        self.stop_event.set()

    def set_rekey_interval(self, n: int):
        if not (10 <= n <= 10000):
            raise ValueError(f"Rekey interval must be between 10 and 10000, got {n}")
        with self._frame_lock:
            self._pending_rekey_interval = n

    def inject_replay_old_epoch(self, epochs_back: int) -> bool:
        if not (1 <= epochs_back <= 5):
            return False
        with self._frame_lock:
            if not self.is_running:
                return False
            cur = self.operator_state.current_epoch if self.operator_state else 1
            target = cur - epochs_back
            if target not in self._epoch_wire_frames:
                return False
            self._pending_injections.append((self._epoch_wire_frames[target], "REPLAYED"))
            return True

    @property
    def is_running(self) -> bool:
        return not self.stop_event.is_set()

    def run(
        self,
        count: Optional[int] = None,
        rate_pps: Optional[int] = None,
        seed: Optional[Union[int, str]] = None,
        attack_config: Optional[AttackConfig] = None,
        run_id: Optional[str] = None,
    ) -> SimulationStats:
        total_packets = count if count is not None else self.config.simulation.count
        rate = rate_pps if rate_pps is not None else self.config.simulation.rate_pps

        raw_seed = seed if seed is not None else self.config.simulation.seed
        if raw_seed in (None, "", "null", "random", "none"):
            resolved_seed = secrets.randbits(32)
        else:
            try:
                resolved_seed = int(raw_seed)
            except (ValueError, TypeError):
                resolved_seed = hash(str(raw_seed)) & 0xFFFFFFFF

        resolved_run_id = run_id or secrets.token_hex(4)
        attacks = attack_config or self.config.attacks
        delay_sec = (1.0 / rate) if rate > 0 else 0.0
        self.keystore.session_salt = secrets.token_bytes(4)

        current_seq = 0
        def on_tx_rekey(from_ep, to_ep, reason):
            if self.operator_state:
                self.operator_state.record_rekey(from_ep, to_ep, reason, at_packet=current_seq)

        source = SyntheticTelemetrySource(
            seed=random.Random(f"{resolved_seed}:source"),
            sender_id=self.config.simulation.sender_id,
        )
        tx = TxPipeline(
            keystore=self.keystore,
            sender_id=self.config.simulation.sender_id,
            key_epoch=self.config.simulation.key_epoch,
            rekey_every_packets=self.config.simulation.rekey_every_packets,
            on_rekey=on_tx_rekey,
        )
        replay_guard = ReplayGuard(
            window_size=self.config.replay_guard.window_size,
            max_clock_skew=self.config.replay_guard.max_clock_skew_sec,
            enforce_timestamp=self.config.replay_guard.enforce_timestamp,
        )
        rx = RxPipeline(
            keystore=self.keystore.to_public_keystore(),
            replay_guard=replay_guard,
            rekey_grace_epochs=self.config.simulation.rekey_grace_epochs,
            operator_state=self.operator_state,
        )
        channel = AdversarialChannel(attack_config=attacks, seed=(resolved_seed ^ 0x5EED))
        self.stats = SimulationStats(seed=resolved_seed, run_id=resolved_run_id)

        for seq in range(1, total_packets + 1):
            if self.stop_event.is_set():
                break
            current_seq = seq

            with self._frame_lock:
                if self._pending_rekey_interval is not None:
                    tx.set_rekey_interval(self._pending_rekey_interval)
                    self._pending_rekey_interval = None

            if self.operator_state and self.operator_state.consume_rekey():
                tx.rotate(reason="manual")
            if self.operator_state:
                self.operator_state.update_epoch(tx.key_epoch)

            # Process pending command queue injections (e.g. old-epoch replay)
            with self._frame_lock:
                injections = list(self._pending_injections)
                self._pending_injections.clear()

            for inj_frame, inj_truth in injections:
                inj_t0 = time.perf_counter_ns()
                inj_v, inj_r, _, _ = rx.process_frame(inj_frame, current_time=time.time())
                inj_lat = round((time.perf_counter_ns() - inj_t0) / 1000.0, 1)
                inj_ev = Event(
                    seq=seq, verdict=inj_v.value, reason=inj_r.value, truth=inj_truth,
                    latency_us=inj_lat, sender_id=self.config.simulation.sender_id,
                    ts=time.time(), run_id=resolved_run_id, seed=resolved_seed,
                    epoch=tx.key_epoch, incident_id=f"inc-{resolved_run_id}-{seq}-inj",
                )
                self._update_stats(inj_ev)
                self.threat_logger.log_event(inj_ev)
                if self.event_callback:
                    self.event_callback(inj_ev)

            telemetry = source.generate_packet(seq)
            t0 = time.perf_counter_ns()
            wire_bytes, _ = tx.transmit(telemetry, timestamp=telemetry.timestamp, seq=seq)
            channel_output, truth = channel.transmit(wire_bytes)

            if channel_output is None:
                verdict, reason = Verdict.DROPPED, Reason.PACKET_DROPPED
            else:
                verdict, reason, _, _ = rx.process_frame(channel_output, current_time=telemetry.timestamp)

            latency_us = round((time.perf_counter_ns() - t0) / 1000.0, 1)

            if verdict == Verdict.AUTHENTIC:
                with self._frame_lock:
                    self._epoch_wire_frames[tx.key_epoch] = wire_bytes
                    if len(self._epoch_wire_frames) > 6:
                        del self._epoch_wire_frames[min(self._epoch_wire_frames.keys())]

            event = Event(
                seq=seq, verdict=verdict.value, reason=reason.value, truth=truth,
                latency_us=latency_us, sender_id=self.config.simulation.sender_id,
                ts=telemetry.timestamp, run_id=resolved_run_id, seed=resolved_seed,
                epoch=tx.key_epoch, incident_id=f"inc-{resolved_run_id}-{seq}",
            )
            self._update_stats(event)
            self.threat_logger.log_event(event)
            if self.event_callback:
                self.event_callback(event)
            if delay_sec > 0:
                time.sleep(delay_sec)

        self.stop_event.set()
        return self.stats

    def _update_stats(self, event: Event):
        s = self.stats
        s.total += 1
        s.latencies_us.append(event.latency_us)

        ep = event.epoch or 1
        if ep not in s.epoch_stats:
            s.epoch_stats[ep] = {"packets": 0, "authentic": 0, "rejected": 0, "first_ts": event.ts, "last_ts": event.ts}
        st = s.epoch_stats[ep]
        st["packets"] += 1
        st["last_ts"] = event.ts
        if event.verdict == Verdict.AUTHENTIC.value:
            st["authentic"] += 1
        else:
            st["rejected"] += 1

        attr = event.verdict.lower()
        if hasattr(s, attr):
            setattr(s, attr, getattr(s, attr) + 1)

        if event.truth in ("TAMPERED", "REPLAYED", "SPOOFED"):
            s.attacks_injected += 1
            if event.verdict != Verdict.AUTHENTIC.value:
                s.correctly_rejected += 1
            else:
                s.false_accepts += 1
        elif event.truth == "AUTHENTIC":
            if event.reason == Reason.SENDER_BLOCKED.value:
                s.operator_blocked += 1
            elif event.verdict != Verdict.AUTHENTIC.value:
                s.false_rejects += 1

        if event.truth == event.verdict:
            s.exact_label_matches += 1


def print_summary(stats: SimulationStats):
    d = stats.to_dict()
    print(f"\nSECURELINK SUMMARY | Seed: {d.get('seed')} | Total: {d['total']} | AUTH: {d['authentic']} | TAMP: {d['tampered']} | REPL: {d['replayed']} | SPOOF: {d['spoofed']}")
    print(f"Attacks: {d['attacks_injected']} | Rejected: {d['correctly_rejected']} ({d['correctly_rejected_pct']}%) | FA: {d['false_accepts']} | FR: {d['false_rejects']}")
    print(f"Latency: p50={d['p50_us']:.1f}us, p95={d['p95_us']:.1f}us, p99={d['p99_us']:.1f}us\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=200)
    p.add_argument("--rate", type=int, default=100)
    p.add_argument("--seed", type=str, default=None)
    args = p.parse_args()
    print_summary(SimulationRunner().run(count=args.count, rate_pps=args.rate, seed=args.seed))



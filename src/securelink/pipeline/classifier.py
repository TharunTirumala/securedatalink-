"""Classification decision logic and reason mapping."""

from securelink.core.types import Verdict, Reason


def map_reason_to_verdict(reason: Reason) -> Verdict:
    """Map verification failure or success reason to a high-level security verdict."""
    if reason == Reason.OK:
        return Verdict.AUTHENTIC
    if reason in (
        Reason.FRAME_MALFORMED,
        Reason.FRAME_TOO_SHORT,
        Reason.GCM_TAG_MISMATCH,
        Reason.UNKNOWN_EPOCH,
    ):
        return Verdict.TAMPERED

    if reason in (
        Reason.UNKNOWN_SENDER,
        Reason.INVALID_SIGNATURE,
        Reason.SENDER_BLOCKED,
    ):
        return Verdict.SPOOFED
    if reason in (
        Reason.DUPLICATE_SEQ,
        Reason.SEQ_OUT_OF_WINDOW,
        Reason.STALE_TIMESTAMP,
        Reason.EPOCH_EXPIRED,
    ):
        return Verdict.REPLAYED
    if reason == Reason.PACKET_DROPPED:
        return Verdict.DROPPED
    raise ValueError(f"Unhandled verification reason: {reason}")


classify = map_reason_to_verdict


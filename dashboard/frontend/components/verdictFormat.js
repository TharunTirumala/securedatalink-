// Shared Verdict, Reason, and Timestamp formatting utilities

export const REASON_DESCRIPTIONS = {
  ok: 'OK',
  duplicate_seq: 'DUPLICATE SEQ',
  seq_out_of_window: 'SEQ OUT OF WINDOW',
  stale_timestamp: 'STALE TIMESTAMP',
  gcm_tag_mismatch: 'GCM TAG MISMATCH',
  invalid_signature: 'INVALID SIGNATURE',
  unknown_sender: 'UNKNOWN SENDER',
  frame_malformed: 'FRAME MALFORMED',
  frame_too_short: 'FRAME TOO SHORT',
  unknown_epoch: 'UNKNOWN EPOCH',
  epoch_expired: 'EPOCH EXPIRED',
  sender_blocked: 'SENDER BLOCKED',
  packet_dropped: 'FRAME REMOVED',
  frame_removed: 'FRAME REMOVED',
  aead_auth_failed: 'AEAD AUTH FAILED',
  signature_invalid: 'INVALID SIGNATURE',
  replay_window_exceeded: 'REPLAY OUT OF WINDOW',
  future_epoch: 'FUTURE EPOCH',
  expired_epoch: 'EXPIRED EPOCH',
};

export function formatReason(reason) {
  if (!reason) return 'UNKNOWN';
  const key = String(reason).toLowerCase();
  return REASON_DESCRIPTIONS[key] || String(reason).toUpperCase().replace(/_/g, ' ');
}

export function formatTimestamp(ts) {
  if (ts == null || ts === '') return '—';
  const num = typeof ts === 'number' ? ts : parseFloat(ts);
  if (isNaN(num)) return String(ts);
  const d = new Date(num * 1000);
  const hms = d.toISOString().substring(11, 19);
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${hms}.${ms}`;
}

export function verdictBadge(verdict) {
  const v = String(verdict || 'AUTHENTIC').toUpperCase();
  let cls = 'badge-auth';
  if (v === 'TAMPERED') cls = 'badge-tamper';
  else if (v === 'REPLAYED') cls = 'badge-replay';
  else if (v === 'SPOOFED') cls = 'badge-spoof';
  else if (v === 'DROPPED') cls = 'badge-drop';
  else if (v !== 'AUTHENTIC') cls = 'badge-other';
  return `<span class="badge ${cls}">${escapeHTML(v)}</span>`;
}

export function truthBadge(truth, caught = null) {
  const t = String(truth || 'AUTHENTIC').toUpperCase();
  let cls = t === 'AUTHENTIC' ? 'badge-auth' : 'badge-tamper';
  if (t === 'REPLAYED') cls = 'badge-replay';
  if (t === 'SPOOFED') cls = 'badge-spoof';
  if (t === 'DROPPED') cls = 'badge-drop';

  let html = `<span class="badge ${cls}">${escapeHTML(t)}</span>`;
  if (caught === true) {
    html += ' <span class="badge-status badge-caught">CAUGHT</span>';
  } else if (caught === false) {
    html += ' <span class="badge-status badge-missed">MISSED</span>';
  }
  return html;
}

export function escapeHTML(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

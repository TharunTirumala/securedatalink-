// Common formatting and presentation utilities

export const reasonMap = {
  'ok': 'OK',
  'duplicate_seq': 'DUPLICATE SEQ',
  'seq_out_of_window': 'SEQ OUT OF WINDOW',
  'stale_timestamp': 'STALE TIMESTAMP',
  'gcm_tag_mismatch': 'GCM TAG MISMATCH',
  'invalid_signature': 'INVALID SIGNATURE',
  'unknown_sender': 'UNKNOWN SENDER',
  'frame_malformed': 'FRAME MALFORMED',
  'frame_too_short': 'FRAME TOO SHORT',
  'unknown_epoch': 'UNKNOWN EPOCH',
  'epoch_expired': 'EPOCH EXPIRED',
  'sender_blocked': 'SENDER BLOCKED',
  'packet_dropped': 'PACKET DROPPED',
};

export function formatReason(r) {
  return reasonMap[r] || (r ? r.toUpperCase() : 'UNKNOWN');
}

export function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toISOString().substring(11, 19) + '.' + Math.floor(d.getMilliseconds() / 100);
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function verdictBadge(verdict) {
  const v = (verdict || 'AUTHENTIC').toUpperCase();
  let cls = 'badge-auth';
  if (v === 'TAMPERED') cls = 'badge-tamper';
  else if (v === 'REPLAYED') cls = 'badge-replay';
  else if (v === 'SPOOFED') cls = 'badge-spoof';
  else if (v === 'DROPPED') cls = 'badge-drop';
  return `<span class="badge ${cls}">${v}</span>`;
}

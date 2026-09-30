// File Lab View - Template & DOM Rendering Helpers
import { renderStep1HTML } from './lab_dataset.js';

export function renderLabSkeleton() {
  return `
    <div class="lab-layout">
      <!-- Educational Banner -->
      <div class="lab-banner">
        <span style="font-size:16px;">🛡️</span>
        <div>
          <strong>ATTACK THE WIRE, NOT THE DATASET:</strong>
          Edit the encrypted frames, not the dataset. Changing the data before encryption is not an attack: the system protects data in transit.
        </div>
      </div>

      <!-- Step 1: Import Dataset & Generation -->
      ${renderStep1HTML()}

      <!-- Step 2: Multi-Epoch Wire Capture File Topbar & Enemy View -->
      <div class="lab-step" style="padding:10px 14px;">
        <div class="lab-topbar" style="border:none;padding:0;background:transparent;">
          <div class="lab-file-select-group">
            <label style="font-size:11px;font-weight:700;color:var(--text-dim);">ACTIVE WIRE FILE:</label>
            <select id="lab-file-select" class="lab-file-select"><option value="">(No files available)</option></select>
            <span id="lab-key-match-badge" class="badge-status normal" style="display:none;">KEY MATCH</span>
            <span id="lab-fp-label" style="font-size:10px;color:var(--text-dim);font-family:var(--font-mono);"></span>
          </div>
          <div style="display:flex;gap:8px;align-items:center;">
            <button id="btn-lab-download" class="btn btn-secondary btn-sm" title="Download wire file for hand editing">Download Wire File (.txt)</button>
            <label class="btn btn-secondary btn-sm" style="margin:0;cursor:pointer;" title="Upload hand-edited wire file">
              Upload Edited File <input type="file" id="lab-file-upload" accept=".wire.txt,.txt,.jsonl" style="display:none;">
            </label>
            <button id="btn-lab-delete" class="btn btn-outline-danger btn-sm" title="Delete file">Delete</button>
          </div>
        </div>
        <!-- What you sent vs what the enemy sees -->
        <div class="lab-vs-card" id="lab-vs-card" style="display:none;">
          <div>
            <div style="font-size:10px;font-weight:700;color:var(--c-green);margin-bottom:4px;">WHAT YOU SENT (Plaintext Row #1):</div>
            <div id="lab-vs-plain" style="font-family:var(--font-mono);font-size:10.5px;color:var(--text-main);word-break:break-all;"></div>
          </div>
          <div>
            <div style="font-size:10px;font-weight:700;color:var(--c-amber);margin-bottom:4px;">WHAT THE ENEMY SEES (Encrypted Wire Frame #1):</div>
            <div id="lab-vs-wire" style="font-family:var(--font-mono);font-size:10.5px;color:var(--c-amber);word-break:break-all;"></div>
          </div>
        </div>
      </div>

      <!-- Step 3: Attack Workbench -->
      <div class="lab-workbench">
        <!-- Left Column: Frame Table -->
        <div class="lab-panel">
          <div class="lab-panel-title">
            <div style="display:flex;gap:10px;align-items:center;">
              <span>WIRE FRAMES</span>
              <div style="display:flex;background:var(--bg-core);border:1px solid var(--border-color);border-radius:3px;">
                <button id="btn-mode-working" class="btn btn-sm" style="padding:2px 8px;font-size:10px;background:var(--c-cyan);color:#000;">Working Copy</button>
                <button id="btn-mode-original" class="btn btn-sm" style="padding:2px 8px;font-size:10px;background:transparent;color:var(--text-dim);">Original</button>
              </div>
            </div>
            <div style="display:flex;gap:8px;">
              <button id="btn-lab-baseline-verify" class="btn btn-outline-success btn-sm">Verify Baseline (Original)</button>
              <button id="btn-lab-verify" class="btn btn-primary btn-sm">Verify Working Copy</button>
            </div>
          </div>

          <div style="overflow-x:auto;max-height:440px;border:1px solid var(--border-color);border-radius:4px;">
            <table class="data-table" style="margin:0;font-size:11px;">
              <thead>
                <tr>
                  <th style="width:36px;">#</th><th>EID</th><th>Epoch</th><th>Seq</th><th>Size</th><th>Origin</th><th>Marks / Edits</th><th id="th-lab-verdict" style="display:none;">Verdict</th><th>Hex Preview</th>
                </tr>
              </thead>
              <tbody id="lab-frames-tbody">
                <tr><td colspan="9" class="placeholder-row">Select or import a dataset to begin.</td></tr>
              </tbody>
            </table>
          </div>

          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:11px;color:var(--text-dim);">
            <div id="lab-page-info">Showing 0 - 0 of 0 frames</div>
            <div style="display:flex;gap:6px;">
              <button id="btn-lab-prev-page" class="btn btn-secondary btn-sm" disabled>&larr; Prev</button>
              <button id="btn-lab-next-page" class="btn btn-secondary btn-sm" disabled>Next &rarr;</button>
            </div>
          </div>
        </div>

        <!-- Right Column: Inspector Drawer & Attack Workbench -->
        <div class="lab-panel">
          <div class="lab-panel-title">
            <span>FRAME INSPECTOR</span>
            <span id="lab-inspect-eid" style="font-size:10px;color:var(--text-dim);">-</span>
          </div>

          <div id="lab-inspect-empty" style="padding:20px 0;text-align:center;color:var(--text-dim);font-size:11px;font-style:italic;">
            Click a frame row to inspect bytes and inject attacks.
          </div>

          <div id="lab-inspect-content" style="display:none;">
            <div class="lab-hex-box" id="lab-hex-viewer"></div>
            <div class="lab-legend">
              <span><span class="legend-dot" style="background:#00e5ff;"></span>Header</span>
              <span><span class="legend-dot" style="background:#ffaa00;"></span>Ciphertext</span>
              <span><span class="legend-dot" style="background:#b366ff;"></span>Tag</span>
              <span><span class="legend-dot" style="background:#00ff88;"></span>Signature</span>
            </div>

            <div style="margin-top:14px;border-top:1px solid var(--border-color);padding-top:12px;">
              <div style="font-size:10.5px;font-weight:700;color:var(--c-amber);letter-spacing:1px;margin-bottom:8px;">MICRO-TAMPER / ATTACK INJECTION</div>
              <div style="display:flex;gap:6px;margin-bottom:10px;">
                <select id="lab-attack-op" class="lab-file-select" style="flex:1;">
                  <option value="tamper">Tamper Bytes</option>
                  <option value="replay">Replay Frame</option>
                  <option value="spoof">Spoof Sender</option>
                  <option value="drop">Drop Frame</option>
                </select>
                <button id="btn-lab-apply-attack" class="btn btn-warning btn-sm">Apply</button>
              </div>
              <div id="lab-attack-params" style="font-size:11px;margin-bottom:8px;"></div>
              <div id="lab-attack-hint" style="font-size:10px;color:var(--text-dim);font-style:italic;margin-bottom:10px;"></div>
            </div>

            <div style="margin-top:12px;border-top:1px solid var(--border-color);padding-top:10px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <span style="font-size:10.5px;font-weight:700;color:var(--text-bright);">ACTIVE EDITS (<span id="lab-edit-count">0</span>)</span>
                <button id="btn-lab-reset-edits" class="btn btn-outline-danger btn-sm" style="font-size:9.5px;padding:1px 6px;">Reset All</button>
              </div>
              <div id="lab-edit-list" style="max-height:140px;overflow-y:auto;"></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Step 4: Verification, C2 Stream & Reconciliation -->
      <div id="lab-step-4" class="lab-step" style="display:none;">
        <div class="lab-step-head">
          <span>STEP 4: VERIFICATION, DECODED C2 STREAM &amp; RECONCILIATION</span>
        </div>
        <div id="lab-verification-hud" class="lab-hud" style="margin-bottom:10px;"></div>
        <div id="lab-gap-alerts"></div>

        <div class="lab-tabs">
          <div class="lab-tab active" data-tab="verdicts">Verdicts Table</div>
          <div class="lab-tab" data-tab="c2">Decoded C2 Stream (<span id="lab-tab-c2-count">0</span>)</div>
          <div class="lab-tab" data-tab="recon">Reconciliation Audit</div>
        </div>

        <div id="tab-content-verdicts">
          <div id="lab-filters-bar" class="lab-filters" style="margin-bottom:8px;">
            <span class="lab-chip active" data-filter="ALL">All Frames</span>
            <span class="lab-chip" data-filter="AUTHENTIC">Authentic</span>
            <span class="lab-chip" data-filter="REJECTED">Rejected</span>
            <span class="lab-chip" data-filter="FALSE_ACCEPTS">False Accepts</span>
            <span class="lab-chip" data-filter="FALSE_REJECTS">False Rejects</span>
          </div>
        </div>

        <div id="tab-content-c2" style="display:none;">
          <div style="background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.3);padding:6px 12px;border-radius:4px;font-size:11px;color:var(--c-green);margin-bottom:8px;" id="c2-stream-banner">
            Clean C2 Output Stream
          </div>
          <div style="max-height:360px;overflow:auto;border:1px solid var(--border-color);border-radius:4px;">
            <table class="data-table" id="c2-stream-table" style="margin:0;font-size:11px;">
              <thead id="c2-stream-thead"></thead><tbody id="c2-stream-tbody"></tbody>
            </table>
          </div>
        </div>

        <div id="tab-content-recon" style="display:none;">
          <div class="recon-grid" id="recon-audit-cards"></div>
          <div id="recon-audit-details" style="font-size:11px;color:var(--text-dim);line-height:1.6;"></div>
        </div>
      </div>
    </div>
  `;
}

export function renderHexViewer(hexStr, ranges) {
  if (!hexStr) return '<span style="color:var(--text-dim);">(empty)</span>';
  const bytes = [];
  for (let i = 0; i < hexStr.length; i += 2) bytes.push(hexStr.slice(i, i + 2));
  return bytes.map((b, byteIdx) => {
    let kind = 'header';
    for (const r of ranges) {
      if (byteIdx >= r.start && byteIdx < r.end) { kind = r.kind; break; }
    }
    return `<span class="byte-${kind}" title="byte ${byteIdx} [${kind}]">${b}</span>`;
  }).join(' ');
}

export function renderHudCards(summary) {
  const faAlert = summary.false_accepts > 0 ? 'alert-danger' : 'alert-zero';
  const frAlert = summary.false_rejects > 0 ? 'alert-danger' : 'alert-zero';
  return `
    <div class="metric-card"><div class="metric-value">${summary.total}</div><div class="metric-label">TOTAL FRAMES</div></div>
    <div class="metric-card"><div class="metric-value" style="color:var(--c-green);">${summary.authentic}</div><div class="metric-label">AUTHENTIC</div></div>
    <div class="metric-card"><div class="metric-value" style="color:var(--c-amber);">${summary.correctly_rejected}</div><div class="metric-label">REJECTED</div></div>
    <div class="metric-card ${faAlert}"><div class="metric-value" style="color:${summary.false_accepts > 0 ? 'var(--c-red)' : 'var(--c-green)'};">${summary.false_accepts}</div><div class="metric-label">FALSE ACCEPTS</div></div>
    <div class="metric-card ${frAlert}"><div class="metric-value" style="color:${summary.false_rejects > 0 ? 'var(--c-red)' : 'var(--c-green)'};">${summary.false_rejects}</div><div class="metric-label">FALSE REJECTS</div></div>
    <div class="metric-card"><div class="metric-value" style="color:var(--c-cyan);">${summary.exact_label_match}</div><div class="metric-label">LABEL MATCHES</div></div>
  `;
}


export function renderAttackInputs(op) {
  if (op === 'tamper') {
    return {
      html: `
        <label style="color:var(--text-dim);">Target Field:</label>
        <select id="attack-tamper-target" class="lab-file-select" style="width:100%;margin-bottom:6px;">
          <option value="ciphertext">Ciphertext (AEAD payload)</option>
          <option value="tag">AEAD Auth Tag</option>
          <option value="signature">ECDSA Signature</option>
          <option value="header_sender">Sender ID in Header</option>
          <option value="header_seq">Sequence Number</option>
          <option value="header_epoch">Key Epoch</option>
        </select>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
          <div><label style="color:var(--text-dim);">Byte Offset:</label><input id="attack-tamper-offset" type="number" class="lab-file-select" value="0" min="0"></div>
          <div><label style="color:var(--text-dim);">XOR Mask (Hex):</label><input id="attack-tamper-mask" type="number" class="lab-file-select" value="1" min="1" max="255"></div>
        </div>`,
      hint: 'Expected: AEAD tag failure or signature verification failure.',
    };
  }
  if (op === 'replay') {
    return {
      html: `<div><label style="color:var(--text-dim);">Delay arrival by seconds:</label><input id="attack-replay-delay" type="number" step="0.5" class="lab-file-select" value="1.0" min="0"></div>`,
      hint: 'Expected: Dropped as duplicate by sliding replay guard window.',
    };
  }
  if (op === 'spoof') {
    return {
      html: `<div><label style="color:var(--text-dim);">Frames to inject:</label><input id="attack-spoof-count" type="number" class="lab-file-select" value="1" min="1" max="20"></div>`,
      hint: 'Expected: Rejected by signature validation or unknown sender/key.',
    };
  }
  return {
    html: `<span style="color:var(--text-dim);">Mark selected frame as dropped in arrival sequence.</span>`,
    hint: 'Expected: Frame omitted from RX arrival; creates detectable sequence gap.',
  };
}

export function renderFrameRowsHTML(rows, selectedEid, vMap, hasVerify) {
  return rows.map(r => {
    const isSel = r.eid === selectedEid ? 'style="background:rgba(0,229,255,0.08);cursor:pointer;"' : 'style="cursor:pointer;"';
    const marks = (r.marks || []).map(m => `<span class="badge-status badge-label-${m}">${m}</span>`).join(' ') || '<span style="color:var(--text-dim);">-</span>';
    let vCell = '';
    if (hasVerify) {
      const v = vMap[r.eid]?.verdict;
      const vClass = v === 'AUTHENTIC' ? 'normal' : 'blocked';
      vCell = `<td><span class="badge-status ${vClass}">${v || 'N/A'}</span></td>`;
    }
    const dropClass = r.dropped ? 'is-dropped' : '';
    return `
      <tr class="frame-row ${dropClass}" data-eid="${r.eid}" ${isSel}>
        <td>${r.n}</td>
        <td style="font-family:var(--font-mono);">${r.eid}</td>
        <td>${r.epoch ?? '-'}</td>
        <td style="font-family:var(--font-mono);">${r.seq ?? '-'}</td>
        <td>${r.size}B</td>
        <td>${r.origin}</td>
        <td>${marks}</td>
        ${vCell}
        <td style="font-family:var(--font-mono);color:var(--text-dim);">${r.hex_preview}...</td>
      </tr>
    `;
  }).join('');
}

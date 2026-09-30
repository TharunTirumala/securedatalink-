// Dynamic Re-keying Console View

import { api } from '../lib/api.js';
import { bus } from '../lib/bus.js';
import { formatTimestamp, formatReason } from '../lib/format.js';

let pollTimer = null;
let busUnsubs = [];
let lastReplayResult = null;

export function mountRekey(container) {
  container.innerHTML = `
    <div class="c2-container rekey-console-view">
      <!-- Header -->
      <header class="tactical-header">
        <div class="header-branding">
          <span class="hud-pill">CRYPTOGRAPHIC KEY LIFECYCLE MANAGEMENT</span>
          <h1>SECURELINK // DYNAMIC RE-KEYING CONSOLE</h1>
        </div>
        <div class="header-status">
          <span class="hud-pill">HKDF-SHA256 DOMAIN ISOLATED</span>
        </div>
      </header>

      <!-- 1. Status Cards -->
      <section class="stat-grid">
        <div class="stat-card">
          <div class="card-label">CURRENT EPOCH</div>
          <div class="card-val" id="rk-cur-epoch" style="color:var(--c-cyan);">—</div>
        </div>
        <div class="stat-card">
          <div class="card-label">TOTAL RE-KEYS</div>
          <div class="card-val" id="rk-total-rekeys" style="color:var(--c-amber);">—</div>
        </div>
        <div class="stat-card">
          <div class="card-label">KEY ID (8-HEX)</div>
          <div class="card-val" id="rk-key-id" style="font-size:16px; color:var(--c-green);">—</div>
        </div>
        <div class="stat-card">
          <div class="card-label">GRACE WINDOW</div>
          <div class="card-val" id="rk-grace-window" style="font-size:14px; color:var(--c-purple);">—</div>
        </div>
        <div class="stat-card">
          <div class="card-label">REKEY INTERVAL</div>
          <div class="card-val" id="rk-cur-interval">100 pkts</div>
        </div>
      </section>

      <!-- 2. Epoch Progress Bar -->
      <section class="panel">
        <div class="panel-header">
          <h3>EPOCH PACKET PROGRESS</h3>
          <span class="hud-subtext" id="rk-progress-label">0 / 100 packets in Epoch</span>
        </div>
        <div style="background: rgba(255,255,255,0.05); height: 12px; border-radius: 6px; overflow: hidden; border: 1px solid var(--border-color);">
          <div id="rk-progress-fill" style="background: linear-gradient(90deg, var(--c-cyan), var(--c-green)); height: 100%; width: 0%; transition: width 0.2s ease;"></div>
        </div>
      </section>

      <!-- 3. Re-Keying Controls & Configuration -->
      <section class="control-panel">
        <div class="control-group">
          <label>OPERATOR RE-KEY</label>
          <button id="btn-rk-force" class="btn-warning" style="padding: 7px 16px; font-weight:700;">FORCE RE-KEY NOW</button>
        </div>
        <div class="control-group">
          <label>ROTATION INTERVAL (10..10000)</label>
          <div style="display:flex; gap:6px;">
            <input type="number" id="input-rk-interval" min="10" max="10000" step="10" value="100" style="width: 100px;">
            <button id="btn-rk-apply-interval" class="btn-outline-success" style="padding: 5px 12px;">APPLY</button>
          </div>
          <span id="rk-config-err" style="color:var(--c-red); font-size:11px; display:none;"></span>
        </div>
        <div class="control-group">
          <label>GRACE EPOCHS (READ-ONLY)</label>
          <input type="text" id="rk-grace-epochs-val" value="1" disabled style="width: 60px; text-align:center;">
        </div>
      </section>

      <!-- 4. Epoch Timeline Chain -->
      <section class="panel">
        <div class="panel-header">
          <h3>ACTIVE & HISTORICAL EPOCH TIMELINE</h3>
          <span class="hud-subtext">Green = Active | Amber = Grace Window | Grey = Expired</span>
        </div>
        <div id="rk-epoch-chain" style="display:flex; gap:12px; overflow-x:auto; padding: 10px 4px;">
          <!-- Epoch blocks injected dynamically -->
        </div>
      </section>

      <!-- 5. Expired-Epoch Replay Injector & 6. History Table Grid -->
      <section class="bottom-grid">
        <div class="panel">
          <div class="panel-header">
            <h3>EXPIRED-EPOCH REPLAY INJECTOR</h3>
          </div>
          <div style="padding: 10px 0; display:flex; flex-direction:column; gap:12px;">
            <p style="color:var(--text-dim); font-size:12px;">
              Inject an authentic frame from a prior epoch into the active channel to verify whether the RX pipeline accepts or rejects it based on the configured grace window.
            </p>
            <div style="display:flex; align-items:center; gap:10px;">
              <label style="color:var(--text-dim);">EPOCHS BACK:</label>
              <select id="sel-rk-epochs-back" style="background:var(--bg-card); color:var(--text-main); border:1px solid var(--border-color); padding:4px 8px; border-radius:3px;">
                <option value="1">1 Epoch Back (Within Grace)</option>
                <option value="2" selected>2 Epochs Back (Expired)</option>
                <option value="3">3 Epochs Back (Expired)</option>
                <option value="4">4 Epochs Back (Expired)</option>
                <option value="5">5 Epochs Back (Expired)</option>
              </select>
              <button id="btn-rk-inject-replay" class="btn-outline-danger" style="padding: 6px 14px; font-weight:700;">INJECT REPLAY</button>
            </div>
            <div id="rk-replay-feedback" style="padding: 8px 12px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 3px; font-size:12px;">
              No replay test executed yet. Run simulation to capture frames.
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <h3>AUDIT: RE-KEY TRANSITION LOG</h3>
          </div>
          <div style="overflow-y:auto; max-height:220px;">
            <table class="feed-table" style="width:100%;">
              <thead>
                <tr><th>TIME</th><th>TRANSITION</th><th>TRIGGER</th><th>AT PACKET</th></tr>
              </thead>
              <tbody id="rk-history-tbody">
                <tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No transitions recorded.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  `;

  const $ = (id) => container.querySelector(`#${id}`);
  const el = {
    curEpoch: $('rk-cur-epoch'), totalRekeys: $('rk-total-rekeys'), keyId: $('rk-key-id'),
    graceWindow: $('rk-grace-window'), curInterval: $('rk-cur-interval'), progressLabel: $('rk-progress-label'),
    progressFill: $('rk-progress-fill'), btnForce: $('btn-rk-force'), inputInterval: $('input-rk-interval'),
    btnApplyInterval: $('btn-rk-apply-interval'), configErr: $('rk-config-err'), epochChain: $('rk-epoch-chain'),
    selEpochsBack: $('sel-rk-epochs-back'), btnInjectReplay: $('btn-rk-inject-replay'),
    replayFeedback: $('rk-replay-feedback'), historyTbody: $('rk-history-tbody'),
  };

  async function updateState() {
    try {
      const state = await api.get('/api/rekey/state');
      el.curEpoch.textContent = state.epoch;
      el.totalRekeys.textContent = state.rekeys;
      el.keyId.textContent = state.key_id || '—';
      el.graceWindow.textContent = (state.accepted_epochs || []).map(e => `E${e}`).join(', ') || 'None';
      el.curInterval.textContent = `${state.rekey_every_packets} pkts`;

      // Progress bar
      const pct = Math.min(100, (state.packets_in_epoch / state.rekey_every_packets * 100)).toFixed(1);
      el.progressFill.style.width = `${pct}%`;
      el.progressLabel.textContent = `${state.packets_in_epoch} / ${state.rekey_every_packets} packets in Epoch ${state.epoch} (${pct}%)`;

      // Button state
      el.btnInjectReplay.disabled = !state.running;
      if (!state.running) {
        el.btnInjectReplay.title = 'Start simulation in Live Monitor first';
      } else {
        el.btnInjectReplay.title = '';
      }
    } catch (_) {}

    // Epochs timeline
    try {
      const epochs = await api.get('/api/rekey/epochs?limit=10');
      if (el.epochChain && Array.isArray(epochs)) {
        el.epochChain.innerHTML = epochs.map(ep => {
          let borderCol = '#64748b';
          let bgCol = 'rgba(100, 116, 139, 0.1)';
          if (ep.status === 'active') { borderCol = 'var(--c-green)'; bgCol = 'rgba(0, 255, 136, 0.1)'; }
          else if (ep.status === 'grace') { borderCol = 'var(--c-amber)'; bgCol = 'rgba(255, 170, 0, 0.1)'; }

          return `
            <div style="min-width: 140px; padding: 10px 12px; border-radius: 4px; border: 2px solid ${borderCol}; background: ${bgCol}; display:flex; flex-direction:column; gap:4px;">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong style="color:var(--text-bright); font-size:14px;">EPOCH ${ep.epoch}</strong>
                <span class="badge" style="font-size:9px; background:${borderCol}; color:#000;">${ep.status.toUpperCase()}</span>
              </div>
              <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">
                Pkts: <strong style="color:var(--text-bright);">${ep.packets}</strong> | Auth: <strong style="color:var(--c-green);">${ep.authentic}</strong>
              </div>
              <div style="font-size:11px; color:var(--text-dim);">
                Rej: <strong style="color:${ep.rejected > 0 ? 'var(--c-red)' : 'var(--text-dim)'};">${ep.rejected}</strong>
              </div>
            </div>
          `;
        }).join('');
      }
    } catch (_) {}

    // History table
    try {
      const history = await api.get('/api/rekey/history?limit=15');
      if (el.historyTbody && Array.isArray(history)) {
        if (history.length === 0) {
          el.historyTbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim);">No transitions recorded.</td></tr>';
        } else {
          el.historyTbody.innerHTML = history.map(h => `
            <tr>
              <td>${formatTimestamp(h.ts)}</td>
              <td><span style="color:var(--c-cyan);">E${h.from_epoch}</span> ➔ <strong style="color:var(--c-green);">E${h.to_epoch}</strong></td>
              <td><span class="badge ${h.reason === 'manual' ? 'badge-tamper' : 'badge-auth'}">${(h.reason || 'auto').toUpperCase()}</span></td>
              <td>#${h.at_packet || 0}</td>
            </tr>
          `).join('');
        }
      }
    } catch (_) {}
  }

  // Hook button actions
  el.btnForce.addEventListener('click', async () => {
    try {
      await api.post('/api/rekey');
      setTimeout(updateState, 300);
    } catch (e) { alert(e.message); }
  });

  el.btnApplyInterval.addEventListener('click', async () => {
    el.configErr.style.display = 'none';
    const val = parseInt(el.inputInterval.value, 10);
    try {
      await api.post('/api/rekey/config', { rekey_every_packets: val });
      updateState();
    } catch (err) {
      el.configErr.textContent = err.message;
      el.configErr.style.display = 'block';
    }
  });

  el.btnInjectReplay.addEventListener('click', async () => {
    const epochsBack = parseInt(el.selEpochsBack.value, 10);
    try {
      el.replayFeedback.textContent = `Injecting frame from E(current - ${epochsBack})...`;
      await api.post('/api/rekey/replay-old', { epochs_back: epochsBack });
      el.replayFeedback.innerHTML = `<span style="color:var(--c-green);">Frame from E-${epochsBack} successfully pushed to channel queue. Awaiting RX verdict...</span>`;
    } catch (err) {
      el.replayFeedback.innerHTML = `<span style="color:var(--c-red);">${err.message}</span>`;
    }
  });

  // Watch for injected event in bus stream
  busUnsubs.push(bus.on('ws:events', (events) => {
    for (const ev of events) {
      if (ev.incident_id && ev.incident_id.endsWith('-inj')) {
        el.replayFeedback.innerHTML = `
          <strong>INJECTED FRAME RESULT:</strong>
          Verdict: <strong style="color:${ev.verdict === 'REPLAYED' ? 'var(--c-green)' : 'var(--c-red)'};">${ev.verdict}</strong> |
          Reason: <code>${formatReason(ev.reason)}</code> |
          Epoch: ${ev.epoch} | Seq: ${ev.seq}
        `;
      }
    }
  }));

  updateState();
  pollTimer = setInterval(updateState, 1000);
}

export function unmountRekey() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  for (const u of busUnsubs) u();
  busUnsubs = [];
}

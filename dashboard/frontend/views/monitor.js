// Live Monitor View: real-time telemetry stream, attack detection, and latency chart

import { bus } from '../lib/bus.js';
import { api, formatError } from '../lib/api.js';
import { formatReason, formatTimestamp, verdictBadge } from '../lib/format.js';
import { getEventBuffer, getWsState } from '../lib/ws.js';

let chart = null;
let unsubs = [];
let processTimer = null;
const MAX_FEED_ROWS = 50;

const state = {
  total: 0, authentic: 0, tampered: 0, replayed: 0, spoofed: 0, dropped: 0,
  attacksInjected: 0, correctlyRejected: 0, exactLabelMatches: 0, falseAccepts: 0, falseRejects: 0,
  recentLatencies: [], lastEpoch: null, eventQueue: [],
};

export function mountMonitor(container) {
  // Wire up existing dashboard elements inside container
  const $ = (id) => container.querySelector(`#${id}`);
  const el = {
    cntTotal: $('cnt-total'), cntAuth: $('cnt-auth'), cntTamper: $('cnt-tamper'),
    cntReplay: $('cnt-replay'), cntSpoof: $('cnt-spoof'), cntDrop: $('cnt-drop'),
    sumCorrectPct: $('sum-correct-pct'), sumCorrectRaw: $('sum-correct-raw'),
    sumExactPct: $('sum-exact-pct'), sumExactRaw: $('sum-exact-raw'),
    sumFa: $('sum-fa'), sumFr: $('sum-fr'), latencyStats: $('latency-stats'),
    feedTbody: $('feed-tbody'), incidentsContainer: $('incidents-container'),
    btnStart: $('btn-start'), btnStop: $('btn-stop'), btnRekey: $('btn-rekey'),
    btnClearIncidents: $('btn-clear-incidents'), ctrlCount: $('ctrl-count'),
    ctrlRate: $('ctrl-rate'), ctrlSeed: $('ctrl-seed'), ctrlRandomSeed: $('ctrl-random-seed'),
    ctrlTamper: $('ctrl-tamper'), ctrlReplay: $('ctrl-replay'), ctrlSpoof: $('ctrl-spoof'),
    ctrlDrop: $('ctrl-drop'), ctrlMock: $('ctrl-mock'),
    valTamper: $('val-tamper'), valReplay: $('val-replay'), valSpoof: $('val-spoof'), valDrop: $('val-drop'),
    ctrlSenderId: $('ctrl-sender-id'), btnBlockSender: $('btn-block-sender'),
    btnUnblockSender: $('btn-unblock-sender'), blockedStatusPill: $('blocked-status-pill'),
    currentSeedDisplay: $('current-seed-display'), btnCopySeed: $('btn-copy-seed'),
  };

  // Init chart
  const canvas = $('latencyChart');
  if (canvas && window.Chart) {
    if (chart) chart.destroy();
    chart = new window.Chart(canvas.getContext('2d'), {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          { label: 'p50 (µs)', data: [], borderColor: '#00e5ff', backgroundColor: 'rgba(0,229,255,0.1)', borderWidth: 2, pointRadius: 1, fill: true },
          { label: 'p99 (µs)', data: [], borderColor: '#ff3366', borderWidth: 2, borderDash: [4, 4], pointRadius: 1 }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 100 },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#798ba7', font: { family: 'Consolas', size: 10 } } },
          y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#798ba7', font: { family: 'Consolas', size: 10 } } }
        },
        plugins: { legend: { labels: { color: '#e2e8f0', font: { family: 'Consolas', size: 11 } } } }
      }
    });
  }

  function renderCounters() {
    if (!el.cntTotal) return;
    el.cntTotal.textContent = state.total;
    el.cntAuth.textContent = state.authentic;
    el.cntTamper.textContent = state.tampered;
    el.cntReplay.textContent = state.replayed;
    el.cntSpoof.textContent = state.spoofed;
    el.cntDrop.textContent = state.dropped;

    const crPct = state.attacksInjected > 0 ? (state.correctlyRejected / state.attacksInjected * 100).toFixed(1) : '100.0';
    el.sumCorrectPct.textContent = `${crPct}%`;
    el.sumCorrectRaw.textContent = `(${state.correctlyRejected} / ${state.attacksInjected} Attacks Mitigated)`;

    const exPct = state.total > 0 ? (state.exactLabelMatches / state.total * 100).toFixed(1) : '100.0';
    el.sumExactPct.textContent = `${exPct}%`;
    el.sumExactRaw.textContent = `(${state.exactLabelMatches} / ${state.total} Exact Categorizations)`;

    el.sumFa.textContent = state.falseAccepts;
    el.sumFr.textContent = state.falseRejects;
  }

  function handleBatch(events) {
    for (const ev of events) {
      state.total++;
      if (ev.latency_us) state.recentLatencies.push(ev.latency_us);
      if (state.recentLatencies.length > 200) state.recentLatencies.shift();

      const v = (ev.verdict || 'AUTHENTIC').toUpperCase();
      if (v === 'AUTHENTIC') state.authentic++;
      else if (v === 'TAMPERED') state.tampered++;
      else if (v === 'REPLAYED') state.replayed++;
      else if (v === 'SPOOFED') state.spoofed++;
      else if (v === 'DROPPED') state.dropped++;

      if (['TAMPERED', 'REPLAYED', 'SPOOFED'].includes(ev.truth)) {
        state.attacksInjected++;
        if (v !== 'AUTHENTIC') state.correctlyRejected++;
        else state.falseAccepts++;
      } else if (ev.truth === 'AUTHENTIC' && v !== 'AUTHENTIC' && ev.reason !== 'sender_blocked') {
        state.falseRejects++;
      }
      if (ev.truth === v) state.exactLabelMatches++;

      // Check epoch divider
      if (ev.epoch && state.lastEpoch !== null && ev.epoch !== state.lastEpoch) {
        const divRow = document.createElement('tr');
        divRow.className = 'epoch-divider-row';
        divRow.innerHTML = `<td colspan="8">─── ROTATION TO KEY EPOCH ${ev.epoch} (PREVIOUS: ${state.lastEpoch}) ───</td>`;
        el.feedTbody.prepend(divRow);
      }
      if (ev.epoch) state.lastEpoch = ev.epoch;

      // Feed row (Canonical 8 columns: SEQ, EPOCH, SRC, VERDICT, REASON, TRUTH, LATENCY, TIMESTAMP)
      const tr = document.createElement('tr');
      const srcText = ev.src || (ev.sender_id != null ? `NODE-${ev.sender_id}` : 'NODE-1');
      tr.innerHTML = `
        <td>${ev.seq || '—'}</td><td>${ev.epoch || 1}</td>
        <td>${srcText}</td><td>${verdictBadge(ev.verdict)}</td>
        <td class="td-reason">${formatReason(ev.reason)}</td>
        <td><span class="badge ${ev.truth === 'AUTHENTIC' ? 'badge-auth' : 'badge-tamper'}">${ev.truth || 'AUTH'}</span></td>
        <td class="td-latency">${ev.latency_us != null ? ev.latency_us.toFixed(1) + ' µs' : '—'}</td>
        <td style="color:var(--text-dim);font-size:11px;">${formatTimestamp(ev.ts)}</td>
      `;
      el.feedTbody.prepend(tr);
      while (el.feedTbody.children.length > MAX_FEED_ROWS) el.feedTbody.removeChild(el.feedTbody.lastChild);

      // Add to incident stream if security violation
      if (v !== 'AUTHENTIC') {
        const placeholder = el.incidentsContainer.querySelector('.no-incidents');
        if (placeholder) placeholder.remove();
        const card = document.createElement('div');
        const incId = ev.incident_id || `inc-${Date.now()}`;
        card.className = 'incident-card';
        card.id = `inc-row-${incId}`;
        card.innerHTML = `
          <div class="inc-head">
            <span class="inc-seq">FRAME #${ev.seq} [EP ${ev.epoch || 1}]</span>
            <span class="inc-time">${formatTimestamp(ev.ts)}</span>
          </div>
          <div class="inc-body">
            <span class="badge ${v === 'TAMPERED' ? 'badge-tamper' : (v === 'REPLAYED' ? 'badge-replay' : 'badge-spoof')}">${v}</span>
            <span class="inc-reason">${formatReason(ev.reason)}</span>
            <button class="btn-ack" data-id="${incId}">ACK</button>
          </div>
        `;
        card.querySelector('.btn-ack').addEventListener('click', async (e) => {
          try {
            await api.post(`/api/incidents/${incId}/ack`);
            card.classList.add('incident-acked');
            e.target.disabled = true;
            e.target.textContent = 'ACKED';
          } catch (_) {}
        });
        el.incidentsContainer.prepend(card);
      }
    }

    renderCounters();
    updateChart();
  }

  function updateChart() {
    if (!chart || state.recentLatencies.length === 0) return;
    const sorted = [...state.recentLatencies].sort((a, b) => a - b);
    const n = sorted.length;
    const p50 = sorted[Math.floor(n * 0.50)];
    const p99 = sorted[Math.min(n - 1, Math.floor(n * 0.99))];
    if (el.latencyStats) el.latencyStats.textContent = `p50: ${p50.toFixed(1)} µs | p99: ${p99.toFixed(1)} µs`;

    const labels = chart.data.labels;
    labels.push(state.total);
    if (labels.length > 25) labels.shift();
    chart.data.datasets[0].data.push(p50);
    if (chart.data.datasets[0].data.length > 25) chart.data.datasets[0].data.shift();
    chart.data.datasets[1].data.push(p99);
    if (chart.data.datasets[1].data.length > 25) chart.data.datasets[1].data.shift();
    chart.update();
  }

  // Hook controls
  ['Tamper', 'Replay', 'Spoof', 'Drop'].forEach((type) => {
    const s = el[`ctrl${type}`], v = el[`val${type}`];
    if (s && v) s.addEventListener('input', () => { v.textContent = `${s.value}%`; });
  });
  if (el.ctrlRandomSeed) {
    el.ctrlRandomSeed.addEventListener('change', () => {
      el.ctrlSeed.disabled = el.ctrlRandomSeed.checked;
      el.ctrlSeed.placeholder = el.ctrlRandomSeed.checked ? 'Random' : 'Seed';
    });
  }

  el.btnStart.addEventListener('click', async () => {
    state.eventQueue = [];
    el.feedTbody.innerHTML = '';
    el.incidentsContainer.innerHTML = '<div class="no-incidents">No security violations recorded yet.</div>';
    Object.assign(state, {
      total: 0, authentic: 0, tampered: 0, replayed: 0, spoofed: 0, dropped: 0,
      attacksInjected: 0, correctlyRejected: 0, exactLabelMatches: 0, falseAccepts: 0, falseRejects: 0,
      recentLatencies: [], lastEpoch: null
    });
    if (chart) { chart.data.labels = []; chart.data.datasets[0].data = []; chart.data.datasets[1].data = []; chart.update(); }

    const payload = {
      count: parseInt(el.ctrlCount.value, 10),
      rate_pps: parseInt(el.ctrlRate.value, 10),
      seed: el.ctrlRandomSeed.checked ? null : parseInt(el.ctrlSeed.value, 10),
      tamper: parseFloat(el.ctrlTamper.value) / 100,
      replay: parseFloat(el.ctrlReplay.value) / 100,
      spoof: parseFloat(el.ctrlSpoof.value) / 100,
      drop: parseFloat(el.ctrlDrop.value) / 100,
    };
    try {
      await api.post('/api/run', payload);
      el.btnStart.disabled = true;
      el.btnStop.disabled = false;
    } catch (e) { alert(formatError(e)); }
  });

  el.btnStop.addEventListener('click', async () => {
    try {
      await api.post('/api/stop');
      el.btnStart.disabled = false;
      el.btnStop.disabled = true;
    } catch (e) { alert(formatError(e)); }
  });

  el.btnRekey.addEventListener('click', async () => {
    try {
      await api.post('/api/rekey');
    } catch (e) { alert(formatError(e)); }
  });

  el.btnBlockSender.addEventListener('click', async () => {
    const sid = parseInt(el.ctrlSenderId.value, 10) || 1;
    try {
      await api.post(`/api/block/${sid}`);
    } catch (e) { alert(formatError(e)); }
  });

  el.btnUnblockSender.addEventListener('click', async () => {
    const sid = parseInt(el.ctrlSenderId.value, 10) || 1;
    try {
      await api.post(`/api/unblock/${sid}`);
    } catch (e) { alert(formatError(e)); }
  });

  if (el.btnClearIncidents) {
    el.btnClearIncidents.addEventListener('click', () => {
      el.incidentsContainer.innerHTML = '<div class="no-incidents">No security violations recorded yet.</div>';
    });
  }

  // Subscribe to bus events
  unsubs.push(bus.on('ws:events', (events) => {
    state.eventQueue.push(...events);
  }));

  unsubs.push(bus.on('server:state', (srv) => {
    if (srv.running) {
      el.btnStart.disabled = true;
      el.btnStop.disabled = false;
    } else {
      el.btnStart.disabled = false;
      el.btnStop.disabled = true;
    }
    if (el.blockedStatusPill) {
      const isBlk = srv.blockedSenders && srv.blockedSenders.includes(parseInt(el.ctrlSenderId.value, 10) || 1);
      el.blockedStatusPill.textContent = isBlk ? 'BLOCKED' : 'ACTIVE';
      el.blockedStatusPill.className = `status-pill ${isBlk ? 'pill-blocked' : 'pill-active'}`;
    }
  }));

  // Backfill from ring buffer if available
  const existing = getEventBuffer();
  if (existing.length > 0) {
    handleBatch(existing);
  }

  // 100ms render throttle loop
  processTimer = setInterval(() => {
    if (state.eventQueue.length > 0) {
      const batch = state.eventQueue.splice(0, 50);
      handleBatch(batch);
    }
  }, 100);
}

export function unmountMonitor() {
  if (processTimer) { clearInterval(processTimer); processTimer = null; }
  for (const u of unsubs) u();
  unsubs = [];
  if (chart) { chart.destroy(); chart = null; }
}

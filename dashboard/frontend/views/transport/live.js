// Live transport monitor card showing 5-node pipeline, verdict counters, and rolling feed

export function createLiveCard() {
  const container = document.createElement('div');
  container.className = 'panel transport-live-card';

  container.innerHTML = `
    <div class="panel-header">
      <h3>ACTIVE UDP DATALINK CHAIN</h3>
      <span class="hud-pill" id="tr-live-status">IDLE // READY</span>
    </div>

    <!-- 5-Node Pipeline Chain -->
    <div class="pipeline-strip" style="margin-top:10px;">
      <div class="pipe-node active" id="node-drone">
        <span class="node-title">SIM UAV</span>
        <span class="node-port">:14550</span>
      </div>
      <span class="pipe-arrow">➔</span>
      <div class="pipe-node active" id="node-tx">
        <span class="node-title">TX GATEWAY</span>
        <span class="node-port">UDP OUT</span>
      </div>
      <span class="pipe-arrow">➔</span>
      <div class="pipe-node attacker" id="node-atk">
        <span class="node-title">ATTACKER</span>
        <span class="node-port">:8888</span>
      </div>
      <span class="pipe-arrow">➔</span>
      <div class="pipe-node active" id="node-rx">
        <span class="node-title">RX GATEWAY</span>
        <span class="node-port">:9999</span>
      </div>
      <span class="pipe-arrow">➔</span>
      <div class="pipe-node active" id="node-c2">
        <span class="node-title">C2 VIEW</span>
        <span class="node-port">:14551</span>
      </div>
    </div>

    <!-- Session & Seed Status Indicator -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:10px; margin-bottom:4px; font-size:11px; color:#a0aec0;">
      <div>SESSION: <b id="tr-lbl-session" style="color:#00e5ff; font-family:monospace;">NONE</b></div>
      <div>SEED: <b id="tr-lbl-seed" style="color:#fff; font-family:monospace;">--</b></div>
    </div>

    <!-- Live Verdict Counters (8 Tiles) -->
    <div style="display:grid; grid-template-columns:repeat(8, 1fr); gap:6px; margin-top:6px;" id="tr-counters">
      <div class="flight-stat-tile"><div class="stat-label">SENT</div><div class="stat-val" id="cnt-sent">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label">RECEIVED</div><div class="stat-val" id="cnt-recv">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#00ff88;">AUTHENTIC</div><div class="stat-val" id="cnt-auth" style="color:#00ff88;">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#ff3366;">TAMPERED</div><div class="stat-val" id="cnt-tamp" style="color:#ff3366;">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#ffaa00;">REPLAYED</div><div class="stat-val" id="cnt-repl" style="color:#ffaa00;">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#d946ef;">SPOOFED</div><div class="stat-val" id="cnt-spoof" style="color:#d946ef;">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#94a3b8;">DROPPED</div><div class="stat-val" id="cnt-drop" style="color:#94a3b8;">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#ff0055;">FALSE ACCEPTS</div><div class="stat-val" id="cnt-fa" style="color:#00ff88;">0</div></div>
    </div>

    <!-- Live Table Feed -->
    <div style="margin-top:14px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span style="font-size:11px; font-weight:bold; color:#a0aec0;">REAL-TIME VERIFIED WIRE FEED</span>
        <span id="tr-feed-rate" style="font-family:monospace; font-size:10px; color:#718096;">0 PPS</span>
      </div>
      <div class="table-scroll" style="max-height:220px; overflow-y:auto; border:1px solid #1a2538; border-radius:4px;">
        <table class="tactical-table" style="width:100%; font-size:11px;">
          <thead>
            <tr>
              <th>SEQ</th>
              <th>EPOCH</th>
              <th>SRC</th>
              <th>VERDICT</th>
              <th>REASON</th>
              <th>TIME</th>
            </tr>
          </thead>
          <tbody id="tr-feed-tbody">
            <tr><td colspan="6" style="text-align:center; color:#4a5568; padding:16px;">Waiting for datagrams...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  const rows = [];
  const tbody = container.querySelector('#tr-feed-tbody');
  const cntSent = container.querySelector('#cnt-sent');
  const cntRecv = container.querySelector('#cnt-recv');
  const cntAuth = container.querySelector('#cnt-auth');
  const cntTamp = container.querySelector('#cnt-tamp');
  const cntRepl = container.querySelector('#cnt-repl');
  const cntSpoof = container.querySelector('#cnt-spoof');
  const cntDrop = container.querySelector('#cnt-drop');
  const cntFa = container.querySelector('#cnt-fa');
  const statusEl = container.querySelector('#tr-live-status');
  const lblSession = container.querySelector('#tr-lbl-session');
  const lblSeed = container.querySelector('#tr-lbl-seed');

  let stats = { sent: 0, recv: 0, auth: 0, tamp: 0, repl: 0, spoof: 0, drop: 0, fa: 0 };
  let renderScheduled = false;
  let lastRenderTime = 0;

  function scheduleRender() {
    if (renderScheduled) return;
    renderScheduled = true;
    const now = performance.now();
    const delay = Math.max(0, 100 - (now - lastRenderTime));
    setTimeout(() => {
      renderScheduled = false;
      lastRenderTime = performance.now();
      doRender();
    }, delay);
  }

  function doRender() {
    cntSent.textContent = stats.sent || 0;
    cntRecv.textContent = stats.recv || 0;
    cntAuth.textContent = stats.auth || 0;
    cntTamp.textContent = stats.tamp || 0;
    cntRepl.textContent = stats.repl || 0;
    cntSpoof.textContent = stats.spoof || 0;
    cntDrop.textContent = stats.drop || 0;
    cntFa.textContent = stats.fa || 0;
    cntFa.style.color = (stats.fa > 0) ? '#ff0055' : '#00ff88';
  }

  return {
    element: container,
    reset() {
      stats = { sent: 0, recv: 0, auth: 0, tamp: 0, repl: 0, spoof: 0, drop: 0, fa: 0 };
      doRender();
      rows.length = 0;
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#4a5568; padding:16px;">Waiting for datagrams...</td></tr>';
    },
    setStatus(text, color) {
      statusEl.textContent = text;
      if (color) statusEl.style.color = color;
    },
    setSessionInfo(sid, seed) {
      if (lblSession) lblSession.textContent = sid || 'NONE';
      if (lblSeed) lblSeed.textContent = (seed !== null && seed !== undefined) ? String(seed) : '--';
    },
    updateCounters(newStats) {
      if (!newStats) return;
      stats = {
        sent: newStats.sent || 0,
        recv: newStats.received !== undefined ? newStats.received : (newStats.recv || 0),
        auth: newStats.authentic !== undefined ? newStats.authentic : (newStats.auth || 0),
        tamp: newStats.tampered !== undefined ? newStats.tampered : (newStats.tamp || 0),
        repl: newStats.replayed !== undefined ? newStats.replayed : (newStats.repl || 0),
        spoof: newStats.spoofed !== undefined ? newStats.spoofed : (newStats.spoof || 0),
        drop: newStats.dropped !== undefined ? newStats.dropped : (newStats.drop || 0),
        fa: newStats.false_accepts !== undefined ? newStats.false_accepts : (newStats.fa || 0),
      };
      scheduleRender();
    },
    addEvent(ev) {
      if (rows.length === 0) tbody.innerHTML = '';
      const v = String(ev.verdict || 'UNKNOWN').toUpperCase();

      const tr = document.createElement('tr');
      const vClass = (v === 'AUTHENTIC') ? 'tag-authentic' : (v === 'TAMPERED') ? 'tag-tampered' : (v === 'REPLAYED') ? 'tag-replayed' : 'tag-alert';
      tr.innerHTML = `
        <td style="font-family:monospace;">#${ev.seq || 0}</td>
        <td style="font-family:monospace;">${ev.epoch || 1}</td>
        <td>NODE-1</td>
        <td><span class="badge ${vClass}">${v}</span></td>
        <td style="color:#718096;">${ev.reason || 'ok'}</td>
        <td style="color:#718096; font-family:monospace;">${new Date().toLocaleTimeString()}</td>
      `;
      tbody.insertBefore(tr, tbody.firstChild);
      rows.unshift(ev);
      if (rows.length > 50) {
        rows.pop();
        if (tbody.lastChild) tbody.removeChild(tbody.lastChild);
      }
    },
  };
}

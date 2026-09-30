// Main Transport View entry point orchestrating setup, live datalink, and reconciliation

import { bus } from '../../lib/bus.js';
import { createSetupCard } from './setup.js';
import { createLiveCard } from './live.js';
import { createDroneCard } from './drone.js';
import { createVerifyCard } from './verify.js';
import { createTransportPoller } from './poll.js';

let activeSessionId = null;
let currentPoller = null;
let syncInterval = null;
let lastUsedConfig = null;

export function mountTransport(container) {
  container.innerHTML = `
    <div class="transport-container">
      <header class="tactical-header" style="margin-bottom:0;">
        <div class="header-branding">
          <span class="hud-pill">PHASE 5+6 // MULTI-NODE UDP PIPELINE</span>
          <h1>SECURELINK // TACTICAL UDP TRANSPORT & UAV FLIGHT</h1>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-secondary active" id="tab-tr-live">LIVE TRANSMISSION</button>
          <button class="btn btn-secondary" id="tab-tr-reconcile">RECONCILIATION AUDIT</button>
        </div>
      </header>
      <div id="pane-tr-live">
        <div class="transport-grid-2col">
          <div id="col-tr-setup"></div>
          <div style="display:flex; flex-direction:column; gap:16px;">
            <div id="col-tr-pipeline"></div>
            <div id="col-tr-drone"></div>
          </div>
        </div>
      </div>
      <div id="pane-tr-reconcile" style="display:none;"><div id="col-tr-verify"></div></div>
    </div>`;

  const paneLive = container.querySelector('#pane-tr-live');
  const paneReconcile = container.querySelector('#pane-tr-reconcile');
  const tabLive = container.querySelector('#tab-tr-live');
  const tabReconcile = container.querySelector('#tab-tr-reconcile');

  tabLive.addEventListener('click', () => {
    tabLive.classList.add('active');
    tabReconcile.classList.remove('active');
    paneLive.style.display = 'block';
    paneReconcile.style.display = 'none';
  });

  tabReconcile.addEventListener('click', () => {
    tabReconcile.classList.add('active');
    tabLive.classList.remove('active');
    paneLive.style.display = 'none';
    paneReconcile.style.display = 'block';
    if (activeSessionId) fetchReconcileReport(activeSessionId);
  });

  const setupCard = createSetupCard(handleStart, handleStop, handleAttackChange, handleRepeat);
  const liveCard = createLiveCard();
  const droneCard = createDroneCard();
  const verifyCard = createVerifyCard();

  container.querySelector('#col-tr-setup').appendChild(setupCard.element);
  container.querySelector('#col-tr-pipeline').appendChild(liveCard.element);
  container.querySelector('#col-tr-drone').appendChild(droneCard.element);
  container.querySelector('#col-tr-verify').appendChild(verifyCard.element);

  const poller = createTransportPoller({
    liveCard,
    droneCard,
    setupCard,
    onFinished: (sid) => {
      activeSessionId = sid;
      fetchReconcileReport(sid);
    },
  });
  currentPoller = poller;

  // Check split-portal role
  fetch('/api/transport/role')
    .then((r) => r.json())
    .then((data) => {
      if (data.role === 'sender') {
        liveCard.setStatus('SENDER NODE ONLY', 'var(--c-cyan)');
      } else if (data.role === 'receiver') {
        liveCard.setStatus('RECEIVER NODE ONLY', '#00ff88');
      }
    })
    .catch(() => {});

  async function syncStatus() {
    try {
      const resp = await fetch('/api/transport/status');
      if (!resp.ok) return;
      const data = await resp.json();
      if (data.session_id) {
        activeSessionId = data.session_id;
        liveCard.setSessionInfo(data.session_id, data.seed);
        if (data.counters) {
          liveCard.updateCounters(data.counters);
        }
      }
      if (data.state === 'running') {
        setupCard.setRunning(true);
        liveCard.setStatus('ACTIVE // TRANSMITTING', '#00ff88');
        poller.start();
      } else if (data.state === 'stopping') {
        setupCard.setRunning(false);
        liveCard.setStatus('STOPPING...', 'var(--c-amber)');
      } else {
        setupCard.setRunning(false);
        liveCard.setStatus(data.session_id ? 'FINISHED // READY' : 'IDLE // READY', 'var(--c-cyan)');
      }
    } catch (e) {
      // Quiet sync error
    }
  }

  // Initial status synchronization on mount
  syncStatus();
  syncInterval = setInterval(syncStatus, 2000);

  async function handleStart(cfg, restart = false) {
    lastUsedConfig = cfg;
    setupCard.hideError();
    if (!restart) {
      liveCard.reset();
      droneCard.reset();
    }
    // Set waiting status and start polling immediately before POST returns
    droneCard.setWaiting(true);
    liveCard.setStatus('STARTING PROCESSES...', 'var(--c-amber)');
    setupCard.setRunning(true);
    poller.start();

    try {
      const payload = { ...cfg, restart };
      const resp = await fetch('/api/transport/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) {
        poller.stop();
        setupCard.setRunning(false);
        if (resp.status === 409) {
          const sid = data.session_id || 'active';
          liveCard.setStatus('CONFLICT // RUNNING', '#ffaa00');
          setupCard.showError(`Session ${sid} is currently running.`, () => handleStart(cfg, true));
        } else {
          liveCard.setStatus('FAILED TO START', '#ff3366');
          setupCard.showError(`Failed to start session: ${data.detail || 'Error'}`);
        }
        return;
      }
      activeSessionId = data.session_id;
      liveCard.setSessionInfo(data.session_id, cfg.drone_seed);
    } catch (err) {
      poller.stop();
      setupCard.setRunning(false);
      liveCard.setStatus('FAILED TO START', '#ff3366');
      setupCard.showError(`Network error starting session: ${err.message}`);
    }
  }

  async function handleStop() {
    liveCard.setStatus('STOPPING...', 'var(--c-amber)');
    poller.stop();
    try {
      await fetch('/api/transport/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: activeSessionId || null }),
      });
      setupCard.setRunning(false);
      liveCard.setStatus('FINISHED // READY', 'var(--c-cyan)');
      if (activeSessionId) await fetchReconcileReport(activeSessionId);
    } catch (err) {
      console.error(err);
      setupCard.setRunning(false);
    }
  }

  async function handleAttackChange(mode, rate) {
    if (!activeSessionId) return;
    try {
      await fetch('/api/transport/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: activeSessionId,
          mode: mode,
          rate: rate,
          params: { lat_offset_deg: 0.005, lon_offset_deg: 0.005 },
        }),
      });
    } catch (err) {
      console.error('Failed to update attack mode mid-flight:', err);
    }
  }

  function handleRepeat() {
    if (lastUsedConfig) {
      handleStart(lastUsedConfig);
    }
  }

  async function fetchReconcileReport(sid) {
    try {
      const resp = await fetch(`/api/transport/session/${sid}/reconcile`);
      if (resp.ok) {
        const report = await resp.json();
        verifyCard.update(report);
      }
    } catch (err) {
      console.error('Failed to load reconcile report:', err);
    }
  }

  // Subscribe to live incoming WebSocket events from RX gateway
  const unsubscribeWs = bus.on('ws:events', (batch) => {
    if (Array.isArray(batch)) {
      liveCard.addEvents(batch);
    }
  });

  return {
    unmount() {
      poller.stop();
      if (syncInterval) {
        clearInterval(syncInterval);
        syncInterval = null;
      }
      unsubscribeWs();
    },
  };
}

export function unmountTransport() {
  if (currentPoller) {
    currentPoller.stop();
    currentPoller = null;
  }
  if (syncInterval) {
    clearInterval(syncInterval);
    syncInterval = null;
  }
}

// SecureLink App Shell & Hash Router

import { bus } from './lib/bus.js';
import { connectWebSocket, startStatePolling } from './lib/ws.js';
import { mountMonitor, unmountMonitor } from './views/monitor.js';
import { mountRekey, unmountRekey } from './views/rekey.js';
import { mountLab, unmountLab } from './views/lab.js';
import { mountTransport, unmountTransport } from './views/transport/index.js';

let currentRoute = null;

const routes = {
  '#/monitor': {
    panelId: 'view-monitor',
    mount: mountMonitor,
    unmount: unmountMonitor,
  },
  '#/rekey': {
    panelId: 'view-rekey',
    mount: mountRekey,
    unmount: unmountRekey,
  },
  '#/lab': {
    panelId: 'view-lab',
    mount: mountLab,
    unmount: unmountLab,
  },
  '#/transport': {
    panelId: 'view-transport',
    mount: mountTransport,
    unmount: unmountTransport,
  },
};

function navigate(targetHash) {
  let rawHash = targetHash || window.location.hash || '#/monitor';
  let cleanHash = rawHash.split('?')[0].replace(/\/+$/, '');
  if (cleanHash === '#lab') cleanHash = '#/lab';
  if (cleanHash === '#rekey') cleanHash = '#/rekey';
  if (cleanHash === '#monitor') cleanHash = '#/monitor';
  if (cleanHash === '#transport') cleanHash = '#/transport';
  const matchedKey = Object.keys(routes).find((r) => cleanHash === r || cleanHash.startsWith(r + '/')) || '#/monitor';

  if (currentRoute && routes[currentRoute] && currentRoute !== matchedKey) {
    const prev = routes[currentRoute];
    if (prev.unmount) prev.unmount();
  }

  // Hide all view panels
  Object.values(routes).forEach((r) => {
    const panel = document.getElementById(r.panelId);
    if (panel) panel.style.display = 'none';
  });

  currentRoute = matchedKey;
  const next = routes[matchedKey];
  const nextPanel = document.getElementById(next.panelId);
  if (nextPanel) {
    nextPanel.style.display = 'block';
    if (next.mount) next.mount(nextPanel);
  }

  // Update active sidebar nav item
  const currentView = matchedKey.replace('#/', '');
  document.querySelectorAll('.app-sidebar .nav-item').forEach((item) => {
    const href = item.getAttribute('href');
    const view = item.getAttribute('data-view');
    if (href === matchedKey || view === currentView) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });
}

function initShell() {
  window.addEventListener('hashchange', () => navigate(window.location.hash));

  // Sidebar item click synchronization
  document.querySelectorAll('.app-sidebar .nav-item').forEach((item) => {
    item.addEventListener('click', () => {
      const href = item.getAttribute('href');
      if (href) {
        document.querySelectorAll('.app-sidebar .nav-item').forEach((i) => i.classList.remove('active'));
        item.classList.add('active');
      }
    });
  });

  // Initialize WebSocket connection & state polling
  const isMock = new URLSearchParams(window.location.search).get('mock') === '1';
  connectWebSocket(isMock);
  startStatePolling();

  // Sidebar footer status hooks
  const sbDot = document.getElementById('sb-status-dot');
  const sbText = document.getElementById('sb-status-text');
  const sbEpoch = document.getElementById('sb-epoch');
  const sbRunId = document.getElementById('sb-run-id');

  bus.on('ws:status', (s) => {
    if (sbDot) sbDot.className = 'status-dot' + (s.connected ? ' active' : ' stopped');
    if (sbText) sbText.textContent = s.connected ? (s.isMock ? 'MOCK FEED' : 'LIVE WS') : 'OFFLINE';
  });

  bus.on('server:state', (srv) => {
    if (sbEpoch) sbEpoch.textContent = srv.epoch || 1;
    if (sbRunId) sbRunId.textContent = (srv.run_id ? srv.run_id.substring(0, 8) : '—');
    if (sbText && srv.connected !== false) {
      sbText.textContent = srv.running ? 'RUNNING' : 'IDLE';
    }
  });

  // Initial navigation
  navigate(window.location.hash || '#/monitor');
}

document.addEventListener('DOMContentLoaded', initShell);

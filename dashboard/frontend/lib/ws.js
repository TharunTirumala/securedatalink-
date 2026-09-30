// Persistent singleton WebSocket manager with a 500-event circular buffer

import { bus } from './bus.js';

const BUFFER_MAX = 500;
const eventRingBuffer = [];
let wsInstance = null;
let reconnectTimer = null;
let pollTimer = null;

const wsState = {
  connected: false,
  running: false,
  seed: null,
  run_id: null,
  epoch: 1,
  rekeys: 0,
  blockedSenders: [],
};

export function getWsState() {
  return { ...wsState };
}

export function getEventBuffer() {
  return [...eventRingBuffer];
}

export function connectWebSocket(isMock = false) {
  if (wsInstance && (wsInstance.readyState === WebSocket.OPEN || wsInstance.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host || '127.0.0.1:8000';
  const url = `${proto}//${host}/ws/events?mock=${isMock ? 1 : 0}`;

  wsInstance = new WebSocket(url);

  wsInstance.onopen = () => {
    wsState.connected = true;
    bus.emit('ws:status', { connected: true, isMock });
  };

  wsInstance.onmessage = (msg) => {
    try {
      const data = JSON.parse(msg.data);
      if (data && typeof data === 'object') {
        if (data.seed != null) wsState.seed = data.seed;
        if (data.run_id != null) wsState.run_id = data.run_id;

        const events = Array.isArray(data.events) ? data.events : (Array.isArray(data) ? data : []);
        for (const ev of events) {
          eventRingBuffer.push(ev);
          if (eventRingBuffer.length > BUFFER_MAX) {
            eventRingBuffer.shift();
          }
        }
        if (events.length > 0) {
          bus.emit('ws:events', events);
        }
        bus.emit('ws:state_update', getWsState());
      }
    } catch (err) {
      console.error('WS message error:', err);
    }
  };

  wsInstance.onclose = () => {
    wsState.connected = false;
    bus.emit('ws:status', { connected: false });
    if (!reconnectTimer) {
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectWebSocket(isMock);
      }, 2000);
    }
  };
}

export function startStatePolling() {
  if (pollTimer) return;
  const poll = async () => {
    try {
      const res = await fetch('/api/state');
      if (res.ok) {
        const d = await res.json();
        wsState.running = d.running;
        wsState.epoch = d.epoch || 1;
        wsState.rekeys = d.rekeys || 0;
        wsState.blockedSenders = d.blocked_senders || [];
        if (d.run_id) wsState.run_id = d.run_id;
        bus.emit('server:state', wsState);
      }
    } catch (_) {}
  };
  poll();
  pollTimer = setInterval(poll, 1000);
}

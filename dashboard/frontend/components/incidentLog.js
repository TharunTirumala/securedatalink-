// Shared Security Incident Log Component with ACK and Feed Cross-Linking
import { formatReason, formatTimestamp, verdictBadge, escapeHTML } from './verdictFormat.js';

export function createIncidentLog(container, options = {}) {
  const onSelectIncident = options.onSelectIncident || (() => {});
  const onAck = options.onAck || (async () => {});
  let incidents = [];

  container.innerHTML = `
    <div class="incident-log-widget">
      <div class="incident-log-header">
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="incident-count-badge">0 INCIDENTS</span>
        </div>
        <button class="btn-tool btn-clear-incidents" style="padding:2px 8px; font-size:11px;">Clear Log</button>
      </div>
      <div class="incident-card-stream" style="max-height:${options.maxHeight || '420px'}; overflow-y:auto; display:flex; flex-direction:column; gap:8px; padding-top:8px;">
        <div class="no-incidents" style="text-align:center; padding:32px 16px; color:var(--text-dim); font-size:12px;">
          No incidents. Baseline is clean.
        </div>
      </div>
    </div>
  `;

  const stream = container.querySelector('.incident-card-stream');
  const countBadge = container.querySelector('.incident-count-badge');
  const btnClear = container.querySelector('.btn-clear-incidents');

  btnClear.addEventListener('click', () => {
    incidents = [];
    render();
  });

  function buildCard(inc) {
    const card = document.createElement('div');
    const incId = inc.incident_id || inc.eid || `inc-${Date.now()}-${Math.random()}`;
    card.className = `incident-card${inc.acked ? ' incident-acked' : ''}`;
    card.id = `inc-row-${incId}`;
    card.dataset.id = incId;
    card.dataset.eid = inc.eid || '';
    if (inc.seq != null) card.dataset.seq = inc.seq;

    const frameRef = inc.seq != null ? `FRAME #${inc.seq}` : (inc.line != null ? `LINE ${inc.line}` : `FRAME [${inc.eid}]`);
    const epRef = inc.epoch != null ? ` [EP ${inc.epoch}]` : '';
    const timeRef = formatTimestamp(inc.t || inc.ts);

    card.innerHTML = `
      <div class="inc-head">
        <span class="inc-seq">${escapeHTML(frameRef + epRef)}</span>
        <span class="inc-time">${escapeHTML(timeRef)}</span>
      </div>
      <div class="inc-body">
        ${verdictBadge(inc.verdict)}
        <span class="inc-reason" title="${escapeHTML(inc.reason)}">${escapeHTML(formatReason(inc.reason))}</span>
        <button class="btn-ack" data-id="${escapeHTML(incId)}" ${inc.acked ? 'disabled' : ''}>
          ${inc.acked ? 'ACKED' : 'ACK'}
        </button>
      </div>
    `;

    // Card click scrolls feed to corresponding frame
    card.addEventListener('click', (e) => {
      if (e.target.closest('.btn-ack')) return;
      stream.querySelectorAll('.incident-card-active').forEach((c) => c.classList.remove('incident-card-active'));
      card.classList.add('incident-card-active');
      onSelectIncident(inc);
    });

    const btnAck = card.querySelector('.btn-ack');
    btnAck.addEventListener('click', async (e) => {
      e.stopPropagation();
      try {
        btnAck.disabled = true;
        btnAck.textContent = '...';
        await onAck(incId, inc, btnAck);
        inc.acked = true;
        card.classList.add('incident-acked');
        btnAck.textContent = 'ACKED';
      } catch (err) {
        btnAck.disabled = false;
        btnAck.textContent = 'ACK';
      }
    });

    return card;
  }

  function render() {
    stream.innerHTML = '';
    countBadge.textContent = `${incidents.length} INCIDENT${incidents.length === 1 ? '' : 'S'}`;

    if (!incidents || incidents.length === 0) {
      stream.innerHTML = `
        <div class="no-incidents" style="text-align:center; padding:32px 16px; color:var(--text-dim); font-size:12px;">
          No incidents. Baseline is clean.
        </div>
      `;
      return;
    }

    const fragment = document.createDocumentFragment();
    incidents.forEach((inc) => {
      fragment.appendChild(buildCard(inc));
    });
    stream.appendChild(fragment);
  }

  return {
    setIncidents: (items) => {
      incidents = Array.isArray(items) ? [...items] : [];
      render();
    },
    pushIncident: (inc) => {
      const placeholder = stream.querySelector('.no-incidents');
      if (placeholder) placeholder.remove();

      incidents.unshift(inc);
      countBadge.textContent = `${incidents.length} INCIDENTS`;
      const card = buildCard(inc);
      stream.prepend(card);
    },
    clear: () => {
      incidents = [];
      render();
    },
    getCount: () => incidents.length,
  };
}

// Canonical 8-Column Packet Feed Table Component for File Lab & Live Monitor
import { formatReason, formatTimestamp, verdictBadge, truthBadge, escapeHTML } from './verdictFormat.js';

export function createVerdictFeed(container, options = {}) {
  const mode = options.mode || 'fileLab'; // 'fileLab' (wire order) or 'liveMonitor' (newest first)
  const maxRows = options.maxRows || 50;
  const onSelectRow = options.onSelectRow || (() => {});
  const onProgress = options.onProgress || (() => {});
  const onComplete = options.onComplete || (() => {});

  let allRows = [], displayedRows = [], filterVerdict = null;
  let lastEpoch = null, renderLimit = 200, revealTimer = null;
  let isRevealing = false, isAutoScroll = true;
  let activeCounts = null, activeIncidents = null;

  container.innerHTML = `
    <div class="verdict-feed-container">
      <div class="feed-toolbar" style="${mode === 'fileLab' ? 'display:flex;' : 'display:none;'} justify-content:space-between; align-items:center; padding:6px 10px; background:rgba(0,0,0,0.2); border-bottom:1px solid var(--border-color); font-size:11px;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="color:var(--text-dim);">Speed:</span>
          <select class="feed-speed-select" style="background:var(--bg-card); color:var(--text-bright); border:1px solid var(--border-color); border-radius:3px; padding:2px 6px; font-size:11px;">
            <option value="10">10/s</option>
            <option value="40" selected>40/s</option>
            <option value="200">200/s</option>
            <option value="instant">Instant</option>
          </select>
        </div>
        <div style="display:flex; gap:6px;">
          <button class="btn-tool btn-feed-skip" style="padding:2px 8px; font-size:10.5px; display:none;">Skip to End</button>
          <button class="btn-tool btn-feed-replay" style="padding:2px 8px; font-size:10.5px; display:none;">Replay</button>
        </div>
      </div>
      <div class="feed-table-scroll" style="max-height: ${options.maxHeight || '460px'}; overflow-y: auto;">
        <table class="data-table feed-table">
          <thead>
            <tr>
              <th style="width:55px;">SEQ</th>
              <th style="width:65px;">EPOCH</th>
              <th style="width:75px;">SRC</th>
              <th style="width:105px;">VERDICT</th>
              <th>REASON</th>
              <th style="width:125px;">TRUTH</th>
              <th style="width:85px;">LATENCY</th>
              <th style="width:105px;">TIMESTAMP</th>
            </tr>
          </thead>
          <tbody class="feed-tbody">
            <tr class="placeholder-row"><td colspan="8" style="text-align:center; color:var(--text-dim); padding:24px;">No frames to display</td></tr>
          </tbody>
        </table>
      </div>
      <div class="feed-load-more" style="display:none; text-align:center; padding:8px; border-top:1px solid var(--border-color);">
        <button class="btn-tool btn-load-more" style="padding:4px 14px; font-size:11px;">Load More Frames...</button>
      </div>
    </div>
  `;

  const tbody = container.querySelector('.feed-tbody');
  const scrollWrap = container.querySelector('.feed-table-scroll');
  const loadMoreWrap = container.querySelector('.feed-load-more');
  const btnLoadMore = container.querySelector('.btn-load-more');
  const speedSelect = container.querySelector('.feed-speed-select');
  const btnSkip = container.querySelector('.btn-feed-skip');
  const btnReplay = container.querySelector('.btn-feed-replay');

  if (btnLoadMore) {
    btnLoadMore.addEventListener('click', () => {
      renderLimit += 200;
      renderTable();
    });
  }

  scrollWrap.addEventListener('scroll', () => {
    const atBottom = scrollWrap.scrollTop + scrollWrap.clientHeight >= scrollWrap.scrollHeight - 35;
    isAutoScroll = atBottom;
    if (atBottom && renderLimit < displayedRows.length && !isRevealing) {
      renderLimit += 200;
      renderTable();
    }
  });

  function buildRowElement(row) {
    const tr = document.createElement('tr');
    const isDropped = Boolean(row.dropped || row.verdict === 'DROPPED');
    tr.className = `feed-row${isDropped ? ' feed-row-dropped' : ''}`;
    tr.dataset.eid = row.eid || '';
    if (row.seq != null) tr.dataset.seq = row.seq;

    const seqText = row.seq != null ? escapeHTML(row.seq) : (row.n != null ? escapeHTML(row.n) : '—');
    const epochText = row.epoch != null ? escapeHTML(row.epoch) : 1;
    const srcText = row.src || (row.sender_id != null ? `NODE-${row.sender_id}` : (row.line != null ? `line ${row.line}` : 'NODE-1'));
    const latencyText = row.latency_us != null ? `${Number(row.latency_us).toFixed(1)} µs` : '—';
    const timeText = formatTimestamp(row.t || row.ts);

    tr.innerHTML = `
      <td>${seqText}</td>
      <td>${epochText}</td>
      <td style="color:var(--text-dim);">${escapeHTML(srcText)}</td>
      <td>${verdictBadge(row.verdict)}</td>
      <td class="td-reason" title="${escapeHTML(row.reason)}">${escapeHTML(formatReason(row.reason))}</td>
      <td>${truthBadge(row.truth, row.caught)}</td>
      <td class="td-latency" style="color:var(--text-dim);">${latencyText}</td>
      <td style="color:var(--text-dim); font-size:11px;">${timeText}</td>
    `;

    tr.addEventListener('click', () => {
      tbody.querySelectorAll('.row-selected').forEach((r) => r.classList.remove('row-selected'));
      tr.classList.add('row-selected');
      onSelectRow(row, tr);
    });
    return tr;
  }

  function renderTable() {
    tbody.innerHTML = '';
    lastEpoch = null;
    if (!displayedRows || displayedRows.length === 0) {
      tbody.innerHTML = `<tr class="placeholder-row"><td colspan="8" style="text-align:center; color:var(--text-dim); padding:24px;">No frames match current filter</td></tr>`;
      if (loadMoreWrap) loadMoreWrap.style.display = 'none';
      return;
    }
    const rowsToRender = displayedRows.slice(0, renderLimit);
    const fragment = document.createDocumentFragment();
    rowsToRender.forEach((row) => {
      const ep = row.epoch;
      if (ep != null && lastEpoch !== null && ep !== lastEpoch) {
        const divRow = document.createElement('tr');
        divRow.className = 'epoch-divider-row';
        divRow.innerHTML = `<td colspan="8">─── ROTATION TO KEY EPOCH ${escapeHTML(ep)} (PREVIOUS: ${escapeHTML(lastEpoch)}) ───</td>`;
        fragment.appendChild(divRow);
      }
      if (ep != null) lastEpoch = ep;
      fragment.appendChild(buildRowElement(row));
    });
    tbody.appendChild(fragment);
    if (loadMoreWrap) {
      loadMoreWrap.style.display = renderLimit < displayedRows.length ? 'block' : 'none';
      if (btnLoadMore) btnLoadMore.textContent = `Showing ${rowsToRender.length} of ${displayedRows.length} frames — Load More`;
    }
  }

  function applyFilter() {
    if (!filterVerdict || filterVerdict === 'ALL') {
      displayedRows = allRows;
    } else {
      displayedRows = allRows.filter((r) => String(r.verdict || '').toUpperCase() === filterVerdict.toUpperCase());
    }
    renderLimit = 200;
    renderTable();
  }

  function stopReveal() {
    if (revealTimer) {
      clearTimeout(revealTimer);
      revealTimer = null;
    }
    isRevealing = false;
    if (btnSkip) btnSkip.style.display = 'none';
    if (btnReplay && allRows.length > 0) btnReplay.style.display = 'inline-block';
  }

  function startReveal() {
    stopReveal();
    const speedVal = speedSelect ? speedSelect.value : '40';
    if (speedVal === 'instant' || allRows.length <= 1) {
      applyFilter();
      if (activeCounts) onProgress(activeCounts, activeIncidents || []);
      onComplete();
      return;
    }

    const pps = parseInt(speedVal, 10) || 40;
    const intervalMs = Math.max(4, Math.round(1000 / pps));
    tbody.innerHTML = '';
    lastEpoch = null;
    isRevealing = true;
    isAutoScroll = true;
    if (btnSkip) btnSkip.style.display = 'inline-block';
    if (btnReplay) btnReplay.style.display = 'none';

    let idx = 0;
    const runCounts = { AUTHENTIC: 0, TAMPERED: 0, REPLAYED: 0, SPOOFED: 0, DROPPED: 0, OTHER: 0, total: 0 };
    const runIncidents = [];

    function step() {
      if (!isRevealing) return;
      if (idx >= allRows.length) {
        stopReveal();
        if (activeCounts) onProgress(activeCounts, activeIncidents || []);
        onComplete();
        return;
      }
      const row = allRows[idx];
      const ep = row.epoch;
      if (ep != null && lastEpoch !== null && ep !== lastEpoch) {
        const divRow = document.createElement('tr');
        divRow.className = 'epoch-divider-row';
        divRow.innerHTML = `<td colspan="8">─── ROTATION TO KEY EPOCH ${escapeHTML(ep)} (PREVIOUS: ${escapeHTML(lastEpoch)}) ───</td>`;
        tbody.appendChild(divRow);
      }
      if (ep != null) lastEpoch = ep;
      tbody.appendChild(buildRowElement(row));

      const v = String(row.verdict || 'OTHER').toUpperCase();
      if (runCounts[v] != null) runCounts[v]++;
      else runCounts.OTHER++;
      runCounts.total++;

      if (v !== 'AUTHENTIC') {
        const inc = (activeIncidents || []).find((i) => String(i.eid) === String(row.eid)) || {
          eid: row.eid, seq: row.seq, line: row.line, epoch: row.epoch,
          t: row.t, verdict: row.verdict, reason: row.reason, truth: row.truth,
        };
        runIncidents.push(inc);
      }
      onProgress({ ...runCounts }, [...runIncidents]);

      if (isAutoScroll) scrollWrap.scrollTop = scrollWrap.scrollHeight;
      idx++;
      revealTimer = setTimeout(step, intervalMs);
    }
    step();
  }

  if (btnSkip) {
    btnSkip.addEventListener('click', () => {
      console.log('BTN_SKIP CLICKED! allRows:', allRows.length, 'tbody attached:', document.body.contains(tbody));
      stopReveal();
      applyFilter();
      if (activeCounts) onProgress(activeCounts, activeIncidents || []);
      onComplete();
    });
  }

  if (btnReplay) {
    btnReplay.addEventListener('click', () => startReveal());
  }

  return {
    setData: (rows, meta = {}) => {
      console.log('FEED setData called! rows:', rows?.length, 'tbody attached:', document.body.contains(tbody));
      filterVerdict = null;
      allRows = Array.isArray(rows) ? rows : [];
      activeCounts = meta.counts || null;
      activeIncidents = meta.incidents || null;
      if (mode === 'fileLab' && meta.animate !== false) {
        startReveal();
      } else {
        stopReveal();
        applyFilter();
        if (activeCounts) onProgress(activeCounts, activeIncidents || []);
        onComplete();
      }
    },
    setFilter: (verdict) => {
      stopReveal();
      filterVerdict = verdict;
      applyFilter();
    },
    pushLiveEvent: (ev) => {
      if (mode !== 'liveMonitor') return;
      const placeholder = tbody.querySelector('.placeholder-row');
      if (placeholder) placeholder.remove();
      if (ev.epoch != null && lastEpoch !== null && ev.epoch !== lastEpoch) {
        const divRow = document.createElement('tr');
        divRow.className = 'epoch-divider-row';
        divRow.innerHTML = `<td colspan="8">─── ROTATION TO KEY EPOCH ${escapeHTML(ev.epoch)} (PREVIOUS: ${escapeHTML(lastEpoch)}) ───</td>`;
        tbody.prepend(divRow);
      }
      if (ev.epoch != null) lastEpoch = ev.epoch;
      tbody.prepend(buildRowElement(ev));
      while (tbody.children.length > maxRows) tbody.removeChild(tbody.lastChild);
    },
    clear: () => {
      stopReveal();
      allRows = []; displayedRows = [];
      tbody.innerHTML = `<tr class="placeholder-row"><td colspan="8" style="text-align:center; color:var(--text-dim); padding:24px;">No frames to display</td></tr>`;
      if (loadMoreWrap) loadMoreWrap.style.display = 'none';
    },
    scrollToItem: (eidOrSeq) => {
      const match = tbody.querySelector(`tr[data-eid="${eidOrSeq}"], tr[data-seq="${eidOrSeq}"]`);
      if (match) {
        tbody.querySelectorAll('.row-selected').forEach((r) => r.classList.remove('row-selected'));
        match.classList.add('row-selected');
        match.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    },
  };
}

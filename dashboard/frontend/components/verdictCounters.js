// Shared Verdict Counters with Coloured Tiles, Proportions Bar, and Click-to-Filter

export function createVerdictCounters(container, options = {}) {
  let counts = { AUTHENTIC: 0, TAMPERED: 0, REPLAYED: 0, SPOOFED: 0, DROPPED: 0, OTHER: 0, total: 0 };
  let activeFilter = null;
  const onFilterChange = options.onFilterChange || (() => {});

  container.innerHTML = `
    <div class="verdict-counters-wrap">
      <div class="verdict-tiles-row">
        <div class="metric-card verdict-tile" data-verdict="AUTHENTIC" title="Filter Authentic">
          <div class="metric-value tile-val-auth" style="color:var(--c-green);">0</div>
          <div class="metric-label">AUTHENTIC</div>
        </div>
        <div class="metric-card verdict-tile" data-verdict="TAMPERED" title="Filter Tampered">
          <div class="metric-value tile-val-tamper" style="color:var(--c-red);">0</div>
          <div class="metric-label">TAMPERED</div>
        </div>
        <div class="metric-card verdict-tile" data-verdict="REPLAYED" title="Filter Replayed">
          <div class="metric-value tile-val-replay" style="color:#b088ff;">0</div>
          <div class="metric-label">REPLAYED</div>
        </div>
        <div class="metric-card verdict-tile" data-verdict="SPOOFED" title="Filter Spoofed">
          <div class="metric-value tile-val-spoof" style="color:var(--c-amber);">0</div>
          <div class="metric-label">SPOOFED</div>
        </div>
        <div class="metric-card verdict-tile" data-verdict="DROPPED" title="Filter Dropped">
          <div class="metric-value tile-val-drop" style="color:var(--text-dim);">0</div>
          <div class="metric-label">DROPPED</div>
        </div>
        <div class="metric-card verdict-tile" data-verdict="OTHER" title="Filter Other">
          <div class="metric-value tile-val-other" style="color:var(--c-cyan);">0</div>
          <div class="metric-label">OTHER</div>
        </div>
        <div class="metric-card verdict-tile" data-verdict="ALL" title="Show All Frames">
          <div class="metric-value tile-val-total" style="color:var(--text-bright);">0</div>
          <div class="metric-label">TOTAL</div>
        </div>
      </div>

      <!-- Stacked Distribution Bar -->
      <div class="verdict-distribution-container">
        <div class="verdict-stacked-bar">
          <div class="bar-seg seg-auth" style="width:0%; background:var(--c-green);" title="Authentic"></div>
          <div class="bar-seg seg-tamper" style="width:0%; background:var(--c-red);" title="Tampered"></div>
          <div class="bar-seg seg-replay" style="width:0%; background:#b088ff;" title="Replayed"></div>
          <div class="bar-seg seg-spoof" style="width:0%; background:var(--c-amber);" title="Spoofed"></div>
          <div class="bar-seg seg-drop" style="width:0%; background:#64748b;" title="Dropped"></div>
          <div class="bar-seg seg-other" style="width:0%; background:var(--c-cyan);" title="Other"></div>
        </div>
        <div class="verdict-distribution-legend">
          <span class="legend-text-summary">0 total frames</span>
        </div>
      </div>
    </div>
  `;

  const tiles = container.querySelectorAll('.verdict-tile');
  const valAuth = container.querySelector('.tile-val-auth');
  const valTamper = container.querySelector('.tile-val-tamper');
  const valReplay = container.querySelector('.tile-val-replay');
  const valSpoof = container.querySelector('.tile-val-spoof');
  const valDrop = container.querySelector('.tile-val-drop');
  const valOther = container.querySelector('.tile-val-other');
  const valTotal = container.querySelector('.tile-val-total');

  const segAuth = container.querySelector('.seg-auth');
  const segTamper = container.querySelector('.seg-tamper');
  const segReplay = container.querySelector('.seg-replay');
  const segSpoof = container.querySelector('.seg-spoof');
  const segDrop = container.querySelector('.seg-drop');
  const segOther = container.querySelector('.seg-other');
  const legendSummary = container.querySelector('.legend-text-summary');

  tiles.forEach((tile) => {
    tile.addEventListener('click', () => {
      const v = tile.dataset.verdict;
      if (v === 'ALL' || activeFilter === v) {
        activeFilter = null;
      } else {
        activeFilter = v;
      }
      updateActiveTileUI();
      onFilterChange(activeFilter);
    });
  });

  function updateActiveTileUI() {
    tiles.forEach((t) => {
      const v = t.dataset.verdict;
      if ((!activeFilter && v === 'ALL') || activeFilter === v) {
        t.classList.add('active-filter');
      } else {
        t.classList.remove('active-filter');
      }
    });
  }

  function setCounts(newCounts = {}) {
    counts = {
      AUTHENTIC: newCounts.AUTHENTIC || 0,
      TAMPERED: newCounts.TAMPERED || 0,
      REPLAYED: newCounts.REPLAYED || 0,
      SPOOFED: newCounts.SPOOFED || 0,
      DROPPED: newCounts.DROPPED || 0,
      OTHER: newCounts.OTHER || 0,
      total: newCounts.total != null ? newCounts.total : (
        (newCounts.AUTHENTIC || 0) + (newCounts.TAMPERED || 0) +
        (newCounts.REPLAYED || 0) + (newCounts.SPOOFED || 0) +
        (newCounts.DROPPED || 0) + (newCounts.OTHER || 0)
      ),
    };

    valAuth.textContent = counts.AUTHENTIC;
    valTamper.textContent = counts.TAMPERED;
    valReplay.textContent = counts.REPLAYED;
    valSpoof.textContent = counts.SPOOFED;
    valDrop.textContent = counts.DROPPED;
    valOther.textContent = counts.OTHER;
    valTotal.textContent = counts.total;

    const tot = counts.total || 1;
    const pAuth = ((counts.AUTHENTIC / tot) * 100).toFixed(1);
    const pTamper = ((counts.TAMPERED / tot) * 100).toFixed(1);
    const pReplay = ((counts.REPLAYED / tot) * 100).toFixed(1);
    const pSpoof = ((counts.SPOOFED / tot) * 100).toFixed(1);
    const pDrop = ((counts.DROPPED / tot) * 100).toFixed(1);
    const pOther = ((counts.OTHER / tot) * 100).toFixed(1);

    segAuth.style.width = `${pAuth}%`;
    segAuth.title = `Authentic: ${counts.AUTHENTIC} (${pAuth}%)`;
    segTamper.style.width = `${pTamper}%`;
    segTamper.title = `Tampered: ${counts.TAMPERED} (${pTamper}%)`;
    segReplay.style.width = `${pReplay}%`;
    segReplay.title = `Replayed: ${counts.REPLAYED} (${pReplay}%)`;
    segSpoof.style.width = `${pSpoof}%`;
    segSpoof.title = `Spoofed: ${counts.SPOOFED} (${pSpoof}%)`;
    segDrop.style.width = `${pDrop}%`;
    segDrop.title = `Dropped: ${counts.DROPPED} (${pDrop}%)`;
    segOther.style.width = `${pOther}%`;
    segOther.title = `Other: ${counts.OTHER} (${pOther}%)`;

    const authPct = counts.total > 0 ? ((counts.AUTHENTIC / counts.total) * 100).toFixed(1) : '100.0';
    legendSummary.textContent = `${counts.total} frames \u2022 ${authPct}% authentic`;
    updateActiveTileUI();
  }

  updateActiveTileUI();

  return {
    setCounts,
    getFilter: () => activeFilter,
    setFilter: (f) => {
      activeFilter = f;
      updateActiveTileUI();
      onFilterChange(activeFilter);
    },
  };
}

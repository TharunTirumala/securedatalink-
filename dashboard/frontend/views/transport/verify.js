// Multi-Hop Verification and Reconciliation View

export function createVerifyCard() {
  const container = document.createElement('div');
  container.className = 'panel transport-verify-card';

  container.innerHTML = `
    <div class="panel-header">
      <h3>MULTI-HOP VERIFICATION & RECONCILIATION</h3>
      <button class="btn btn-secondary btn-sm" id="btn-export-reconcile">EXPORT AUDIT REPORT</button>
    </div>

    <!-- Summary Metrics Grid -->
    <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:8px; margin-top:12px;">
      <div class="flight-stat-tile"><div class="stat-label">TOTAL SENT</div><div class="stat-val" id="rec-sent">—</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#00ff88;">DELIVERED CLEAN</div><div class="stat-val" id="rec-deliv" style="color:#00ff88;">—</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#00ff88;">FALSE ACCEPTS (GOAL: 0)</div><div class="stat-val" id="rec-fa" style="color:#00ff88;">0</div></div>
      <div class="flight-stat-tile"><div class="stat-label" style="color:#00e5ff;">FALSE REJECTS (GOAL: 0)</div><div class="stat-val" id="rec-fr" style="color:#00e5ff;">0</div></div>
    </div>

    <!-- Missing Attribution & Telemetry Audit Split -->
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:12px;">
      <div style="background:#090e17; border:1px solid #1a2538; border-radius:4px; padding:10px 14px;">
        <span style="font-size:10px; font-weight:bold; color:#718096; text-transform:uppercase;">MISSING FRAME ATTRIBUTION</span>
        <div style="margin-top:6px; font-size:12px; display:flex; flex-direction:column; gap:4px;">
          <div style="display:flex; justify-content:space-between;"><span>Dropped by Attacker:</span><strong id="attr-drop">0</strong></div>
          <div style="display:flex; justify-content:space-between;"><span>Tampered & Cut by RX:</span><strong id="attr-tamp" style="color:#ff3366;">0</strong></div>
          <div style="display:flex; justify-content:space-between;"><span>Unexplained Loss:</span><strong id="attr-unexp">0</strong></div>
        </div>
      </div>

      <div style="background:#090e17; border:1px solid #1a2538; border-radius:4px; padding:10px 14px;">
        <span style="font-size:10px; font-weight:bold; color:#718096; text-transform:uppercase;">TELEMETRY DIVERGENCE AUDIT</span>
        <div style="margin-top:6px; font-size:12px; display:flex; flex-direction:column; gap:4px;">
          <div style="display:flex; justify-content:space-between;"><span>Delivered Identical:</span><strong id="telem-ident" style="color:#00ff88;">0</strong></div>
          <div style="display:flex; justify-content:space-between;"><span>Delivered Altered:</span><strong id="telem-alt" style="color:#ff3366;">0</strong></div>
          <div style="display:flex; justify-content:space-between;"><span>Max Position Error:</span><strong id="telem-max-err">0.00 m</strong></div>
        </div>
      </div>
    </div>

    <!-- Timeline of Events -->
    <div style="margin-top:14px;">
      <span style="font-size:11px; font-weight:bold; color:#a0aec0;">CHRONOLOGICAL VERDICT TIMELINE</span>
      <div class="table-scroll" style="max-height:160px; overflow-y:auto; border:1px solid #1a2538; border-radius:4px; margin-top:6px;">
        <table class="tactical-table" style="width:100%; font-size:11px;">
          <thead><tr><th>TIME</th><th>TYPE</th><th>LABEL</th><th>DETAIL</th></tr></thead>
          <tbody id="rec-timeline-tbody">
            <tr><td colspan="4" style="text-align:center; color:#4a5568; padding:12px;">Run a session to view timeline...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  let latestReport = null;

  function neutralize(val) {
    if (typeof val === 'string' && /^[=+\-@]/.test(val)) {
      return `'${val}`;
    }
    return val;
  }

  container.querySelector('#btn-export-reconcile').addEventListener('click', () => {
    if (!latestReport) return;
    const fSum = latestReport.frame_reconciliation?.summary || {};
    const tSum = latestReport.telemetry_reconciliation || {};
    const rows = [
      ['Metric', 'Value'],
      ['Total Sent', neutralize(fSum.total_sent || 0)],
      ['Total Delivered', neutralize(fSum.total_delivered || 0)],
      ['Authentic', neutralize(fSum.authentic || 0)],
      ['False Accepts', neutralize(fSum.false_accepts || 0)],
      ['False Rejects', neutralize(fSum.false_rejects || 0)],
      ['Delivered Altered', neutralize(tSum.delivered_altered || 0)],
      ['Max Pos Error (m)', neutralize(tSum.max_position_error_m || 0)],
    ];
    const csvContent = 'data:text/csv;charset=utf-8,' + rows.map(r => r.join(',')).join('\n');
    const encoded = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encoded);
    link.setAttribute('download', `reconciliation_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  return {
    element: container,
    update(report) {
      latestReport = report;
      const fSum = report.frame_reconciliation?.summary || {};
      const tSum = report.telemetry_reconciliation || {};
      const attr = fSum.missing_attribution || {};

      container.querySelector('#rec-sent').textContent = fSum.total_sent || 0;
      container.querySelector('#rec-deliv').textContent = fSum.total_delivered || 0;

      const faEl = container.querySelector('#rec-fa');
      faEl.textContent = fSum.false_accepts || 0;
      faEl.style.color = (fSum.false_accepts > 0) ? '#ff0055' : '#00ff88';

      const frEl = container.querySelector('#rec-fr');
      frEl.textContent = fSum.false_rejects || 0;

      container.querySelector('#attr-drop').textContent = attr.dropped_by_attacker || 0;
      container.querySelector('#attr-tamp').textContent = attr.tampered_and_rejected || 0;
      container.querySelector('#attr-unexp').textContent = attr.unexplained || 0;

      container.querySelector('#telem-ident').textContent = tSum.delivered_identical || 0;
      const altEl = container.querySelector('#telem-alt');
      altEl.textContent = tSum.delivered_altered || 0;
      altEl.style.color = (tSum.delivered_altered > 0) ? '#ff3366' : '#00ff88';

      container.querySelector('#telem-max-err').textContent = `${(tSum.max_position_error_m || 0).toFixed(2)} m`;

      const tbody = container.querySelector('#rec-timeline-tbody');
      const timeline = report.frame_reconciliation?.timeline || [];
      if (timeline.length > 0) {
        tbody.innerHTML = '';
        timeline.slice(0, 50).forEach((t) => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td style="font-family:monospace; color:#718096;">${new Date(t.ts * 1000).toLocaleTimeString()}</td>
            <td>${t.type}</td>
            <td style="font-weight:bold;">${t.label}</td>
            <td style="color:#718096; font-size:10px;">${t.detail}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    }
  };
}

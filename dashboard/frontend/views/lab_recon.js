// File Lab Step 4: Clean C2 Stream & Reconciliation Audit Rendering

export function renderReconcileCards(delivery) {
  const mismatchAlert = delivery.content_mismatches > 0 ? 'alert-danger' : 'alert-zero';
  return `
    <div class="metric-card"><div class="metric-value">${delivery.source_rows}</div><div class="metric-label">SOURCE ROWS</div></div>
    <div class="metric-card"><div class="metric-value" style="color:var(--c-green);">${delivery.delivered_rows}</div><div class="metric-label">DELIVERED TO C2</div></div>
    <div class="metric-card"><div class="metric-value" style="color:var(--c-amber);">${delivery.suppressed_at_gate}</div><div class="metric-label">SUPPRESSED AT GATE</div></div>
    <div class="metric-card"><div class="metric-value">${delivery.missing_rows}</div><div class="metric-label">MISSING ROWS</div></div>
    <div class="metric-card"><div class="metric-value">${delivery.duplicates_delivered}</div><div class="metric-label">DUPLICATES DELIVERED</div></div>
    <div class="metric-card ${mismatchAlert}"><div class="metric-value" style="color:${delivery.content_mismatches > 0 ? 'var(--c-red)' : 'var(--c-green)'};">${delivery.content_mismatches}</div><div class="metric-label">CONTENT MISMATCHES</div></div>
  `;
}

export function renderC2StreamTable(cleanRows, delivery) {
  const banner = document.getElementById('c2-stream-banner');
  banner.textContent = `Clean C2 Output Stream — Delivered: ${delivery.delivered_rows || 0} / ${delivery.source_rows || 0} (${delivery.suppressed_at_gate || 0} suppressed at gate)`;
  const thead = document.getElementById('c2-stream-thead'), tbody = document.getElementById('c2-stream-tbody');
  thead.innerHTML = ''; tbody.innerHTML = '';
  if (!cleanRows.length) {
    tbody.innerHTML = '<tr><td class="placeholder-row">No authentic payloads reached C2 stream.</td></tr>';
    return;
  }
  const cols = ['seq', 'epoch', ...Object.keys(cleanRows[0].data || {})];
  thead.innerHTML = `<tr>${cols.map(c => `<th>${c}</th>`).join('')}</tr>`;
  cleanRows.forEach(row => {
    const tr = document.createElement('tr');
    cols.forEach(col => {
      const td = document.createElement('td');
      const val = (col === 'seq' || col === 'epoch') ? row[col] : (row.data ? row.data[col] : '');
      td.textContent = val !== undefined ? String(val) : '';
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

export function renderReconciliationTab(delivery, gaps) {
  document.getElementById('recon-audit-cards').innerHTML = renderReconcileCards(delivery);
  let detailHtml = `<p>Original Source Rows: <strong>${delivery.source_rows}</strong></p>`;
  detailHtml += `<p>Delivered Clean: <strong>${delivery.delivered_rows}</strong> | Suppressed: <strong>${delivery.suppressed_at_gate}</strong></p>`;
  if (gaps.length) {
    detailHtml += `<p style="color:var(--c-amber);">Detected ${gaps.length} arrival sequence gap(s) due to dropped/missing frames.</p>`;
  } else {
    detailHtml += `<p style="color:var(--c-green);">✓ Zero sequence gaps in delivered stream.</p>`;
  }
  if (delivery.content_mismatches === 0) {
    detailHtml += `<p style="color:var(--c-green);">✓ Zero payload content mismatches detected against source truth.</p>`;
  } else {
    detailHtml += `<p style="color:var(--c-red);">⚠️ Warning: ${delivery.content_mismatches} content mismatch(es) detected!</p>`;
  }
  document.getElementById('recon-audit-details').innerHTML = detailHtml;
}

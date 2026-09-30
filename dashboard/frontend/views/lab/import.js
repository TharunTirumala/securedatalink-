// File Lab Step 1: Import Dataset (Streamlined UX)
import { formatError } from '../../lib/api.js';
import { opPreviewDataset, opImportDataset, opGenerateFile } from '../lab_ops.js';

let datasetText = null, datasetPreview = null, selectedColumns = new Set();

export function renderStep1HTML() {
  return `
    <div class="step-card" id="step-1-card">
      <div class="step-header" id="step-1-header">
        <div class="step-title-group">
          <span class="step-badge" id="step-1-badge">1</span>
          <span class="step-title">IMPORT DATASET</span>
          <span class="step-summary-text" id="step-1-summary" style="display:none;"></span>
        </div>
        <button class="btn-step-edit" id="step-1-edit-btn" style="display:none;">Edit</button>
      </div>

      <div class="step-content" id="step-1-content">
        <div class="import-main-zone">
          <div id="step1-dropzone" class="lab-dropzone">
            <input type="file" id="step1-file-input" accept=".csv,.json,.jsonl,.txt" style="display:none;">
            <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:4px;">
              Drag &amp; Drop CSV / JSON / JSONL here
            </div>
            <div style="font-size:11px;color:var(--text-dim);">or click to browse from disk (up to 5 MB)</div>
          </div>
          <div style="margin-top:6px;text-align:center;">
            <button class="btn-text-link" id="btn-step1-synthetic">Or use synthetic telemetry sample (100 frames)</button>
          </div>
        </div>

        <!-- Collapsible Advanced Options -->
        <div class="collapsible-section" style="margin-top:12px;">
          <div class="section-toggle" id="step1-options-toggle">
            <span class="toggle-arrow" id="step1-options-arrow">&#9656;</span>
            <span style="font-weight:700;font-size:11px;">Options:</span>
            <span class="options-hint" id="step1-options-hint">auto-detect &middot; 100 pps &middot; re-key every 50</span>
          </div>
          <div class="section-body" id="step1-options-body" style="display:none;margin-top:8px;">
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;font-size:11px;">
              <div>
                <label class="control-label">Format:</label>
                <select id="step1-format" class="lab-file-select" style="width:100%;">
                  <option value="auto">Auto-detect</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON Array</option>
                  <option value="jsonl">JSONL</option>
                </select>
              </div>
              <div>
                <label class="control-label">Rate (pps):</label>
                <input type="number" id="step1-rate" class="lab-file-select" style="width:100%;" value="100" min="1" max="2000">
              </div>
              <div>
                <label class="control-label">Re-key interval:</label>
                <input type="number" id="step1-rekey" class="lab-file-select" style="width:100%;" value="50" min="5" max="1000">
              </div>
              <div>
                <label class="control-label">Capture Name:</label>
                <input type="text" id="step1-name" class="lab-file-select" style="width:100%;" placeholder="e.g. flight-data">
              </div>
            </div>
          </div>
        </div>

        <!-- 3-Row Sample Preview & Column Dropdown -->
        <div id="step1-preview-wrap" style="display:none;margin-top:12px;border-top:1px solid var(--border-color);padding-top:10px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:11px;flex-wrap:wrap;gap:8px;">
            <span id="step1-preview-title" style="color:var(--c-cyan);font-weight:700;">-</span>
            
            <!-- Column Picker Dropdown -->
            <div style="position:relative;">
              <button class="btn btn-secondary btn-sm" id="btn-col-picker-toggle">Columns (All) &#9662;</button>
              <div id="col-picker-menu" class="dropdown-menu-box" style="display:none;">
                <div style="display:flex;justify-content:space-between;gap:8px;padding-bottom:6px;border-bottom:1px solid var(--border-color);margin-bottom:6px;font-size:10px;">
                  <button class="btn-link" id="btn-col-select-all">Select all</button>
                  <button class="btn-link" id="btn-col-select-none">None</button>
                </div>
                <div id="col-picker-list" style="max-height:160px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;"></div>
              </div>
            </div>
          </div>

          <div class="table-responsive" style="max-height:130px;overflow:auto;border:1px solid var(--border-color);border-radius:4px;">
            <table class="data-table" id="step1-preview-table" style="margin:0;font-size:10.5px;">
              <thead id="step1-preview-thead"></thead>
              <tbody id="step1-preview-tbody"></tbody>
            </table>
          </div>
        </div>

        <!-- Primary Action -->
        <div style="margin-top:14px;display:flex;justify-content:flex-end;">
          <button id="btn-step1-encrypt" class="btn btn-primary" style="padding:7px 20px;" disabled>
            Encrypt &amp; Sign Wire File &rarr;
          </button>
        </div>
      </div>
    </div>
  `;
}

export function initStep1(onSuccess) {
  const byId = id => document.getElementById(id);
  const dz = byId('step1-dropzone'), fi = byId('step1-file-input');

  dz?.addEventListener('click', () => fi.click());
  dz?.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
  dz?.addEventListener('dragleave', () => dz.classList.remove('dragover'));
  dz?.addEventListener('drop', e => {
    e.preventDefault(); dz.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
  fi?.addEventListener('change', e => { if (e.target.files.length) handleFile(e.target.files[0]); });

  byId('step1-options-toggle')?.addEventListener('click', toggleOptions);
  ['step1-format', 'step1-rate', 'step1-rekey'].forEach(id => {
    byId(id)?.addEventListener('change', updateOptionsHint);
  });

  byId('btn-step1-synthetic')?.addEventListener('click', async () => {
    try {
      const res = await opGenerateFile(null, 100, 25, null);
      if (onSuccess) onSuccess(res.file_id, 'Generated synthetic sample · 100 frames · 4 epochs');
    } catch (err) { alert(`Synthetic failed: ${formatError(err)}`); }
  });

  byId('btn-col-picker-toggle')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const menu = byId('col-picker-menu');
    if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  });
  document.addEventListener('click', () => {
    const menu = byId('col-picker-menu');
    if (menu) menu.style.display = 'none';
  });
  byId('col-picker-menu')?.addEventListener('click', e => e.stopPropagation());

  byId('btn-col-select-all')?.addEventListener('click', () => setAllColumns(true));
  byId('btn-col-select-none')?.addEventListener('click', () => setAllColumns(false));

  byId('btn-step1-encrypt')?.addEventListener('click', async () => {
    if (!datasetText) return;
    const name = byId('step1-name').value.trim() || undefined;
    const fmt = byId('step1-format').value;
    const rate = parseInt(byId('step1-rate').value || 100, 10);
    const rekey = parseInt(byId('step1-rekey').value || 50, 10);
    const cols = Array.from(selectedColumns);
    try {
      const res = await opImportDataset(datasetText, name, fmt, cols, rate, rekey);
      const rowCount = datasetPreview?.row_count || 'dataset';
      const summary = `Imported ${name || 'dataset'} · ${rowCount} rows · ${cols.length} cols`;
      if (onSuccess) onSuccess(res.file_id, summary);
    } catch (err) { alert(`Import failed: ${formatError(err)}`); }
  });

  async function handleFile(file) {
    try {
      datasetText = await file.text();
      const fmt = byId('step1-format').value;
      datasetPreview = await opPreviewDataset(datasetText, fmt);
      selectedColumns = new Set(datasetPreview.columns);
      renderPreview(file.name);
      byId('btn-step1-encrypt').disabled = false;
      if (!byId('step1-name').value) byId('step1-name').value = file.name.replace(/\.[^/.]+$/, "");
    } catch (err) { alert(`Preview failed: ${formatError(err)}`); }
  }

  function renderPreview(filename) {
    const p = datasetPreview;
    byId('step1-preview-wrap').style.display = 'block';
    byId('step1-preview-title').textContent = `${filename} (${p.row_count} rows · ${p.columns.length} columns)`;
    updateColPickerButton();

    const pickerList = byId('col-picker-list');
    pickerList.innerHTML = p.columns.map(c => `
      <label style="cursor:pointer;display:flex;align-items:center;gap:6px;font-size:10.5px;">
        <input type="checkbox" class="col-checkbox" data-col="${c}" checked> ${c}
      </label>
    `).join('');

    pickerList.querySelectorAll('.col-checkbox').forEach(cb => {
      cb.addEventListener('change', e => {
        if (e.target.checked) selectedColumns.add(e.target.dataset.col);
        else selectedColumns.delete(e.target.dataset.col);
        updateColPickerButton();
      });
    });

    byId('step1-preview-thead').innerHTML = `<tr>${p.columns.map(c => `<th>${c}</th>`).join('')}</tr>`;
    const tb = byId('step1-preview-tbody');
    tb.innerHTML = '';
    // Show 3 rows only
    p.sample.slice(0, 3).forEach(row => {
      const tr = document.createElement('tr');
      p.columns.forEach(c => {
        const td = document.createElement('td');
        td.textContent = row[c] !== undefined ? String(row[c]) : '';
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
  }

  function setAllColumns(selectAll) {
    if (!datasetPreview) return;
    selectedColumns = selectAll ? new Set(datasetPreview.columns) : new Set();
    document.querySelectorAll('.col-checkbox').forEach(cb => { cb.checked = selectAll; });
    updateColPickerButton();
  }

  function updateColPickerButton() {
    const total = datasetPreview?.columns.length || 0;
    byId('btn-col-picker-toggle').innerHTML = `Columns (${selectedColumns.size} of ${total}) &#9662;`;
  }

  function toggleOptions() {
    const body = byId('step1-options-body'), arrow = byId('step1-options-arrow');
    const isHidden = body.style.display === 'none';
    body.style.display = isHidden ? 'block' : 'none';
    arrow.innerHTML = isHidden ? '&#9660;' : '&#9656;';
  }

  function updateOptionsHint() {
    const fmt = byId('step1-format').value;
    const rate = byId('step1-rate').value;
    const rekey = byId('step1-rekey').value;
    byId('step1-options-hint').textContent = `${fmt} · ${rate} pps · re-key every ${rekey}`;
  }
}

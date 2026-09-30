// File Lab Step 1: Dataset Import & Generation Handlers
import { opPreviewDataset, opImportDataset, opGenerateFile } from './lab_ops.js';

let datasetText = null, datasetPreview = null, selectedColumns = new Set();

export function renderStep1HTML() {
  return `
    <div class="lab-step">
      <div class="lab-step-head">
        <span>STEP 1: IMPORT DATASET &amp; GENERATE WIRE CAPTURE</span>
        <div style="display:flex;gap:8px;">
          <button id="btn-use-synthetic" class="btn btn-secondary btn-sm">Use Synthetic Sample</button>
          <button id="btn-toggle-import-panel" class="btn btn-secondary btn-sm">&minus; Collapse</button>
        </div>
      </div>
      <div id="lab-import-panel" style="display:flex;flex-direction:column;gap:10px;">
        <div style="display:grid;grid-template-columns:1fr 280px;gap:12px;">
          <div id="lab-dropzone" class="lab-dropzone">
            <input type="file" id="lab-dataset-file" accept=".csv,.json,.jsonl,.txt" style="display:none;">
            <div style="font-size:12px;font-weight:700;color:var(--text-bright);margin-bottom:4px;">Drag &amp; Drop CSV / JSON / JSONL here</div>
            <div style="font-size:10px;">or click to browse from disk (up to 5 MB)</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;font-size:11px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
              <div>
                <label style="color:var(--text-dim);display:block;margin-bottom:2px;">Format:</label>
                <select id="import-format" class="lab-file-select" style="width:100%;">
                  <option value="auto">Auto-detect</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON Array</option>
                  <option value="jsonl">JSONL</option>
                </select>
              </div>
              <div>
                <label style="color:var(--text-dim);display:block;margin-bottom:2px;">Rate (pps):</label>
                <input type="number" id="import-rate" class="lab-file-select" style="width:100%;" value="100" min="1" max="2000">
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
              <div>
                <label style="color:var(--text-dim);display:block;margin-bottom:2px;">Rekey (packets):</label>
                <input type="number" id="import-rekey" class="lab-file-select" style="width:100%;" value="50" min="5" max="1000">
              </div>
              <div>
                <label style="color:var(--text-dim);display:block;margin-bottom:2px;">Capture Name:</label>
                <input type="text" id="import-name" class="lab-file-select" style="width:100%;" placeholder="e.g. flight-data">
              </div>
            </div>
            <button id="btn-import-encrypt" class="btn btn-primary btn-sm" style="margin-top:4px;" disabled>
              Encrypt &amp; Sign Wire File
            </button>
          </div>
        </div>
        <div id="lab-dataset-preview-container" style="display:none;border-top:1px solid var(--border-color);padding-top:8px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;font-size:11px;">
            <span id="lab-dataset-meta" style="color:var(--c-cyan);font-weight:700;">-</span>
            <span style="color:var(--text-dim);font-size:10px;">Select columns to include:</span>
          </div>
          <div id="lab-dataset-col-picks" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px;font-size:10.5px;"></div>
          <div style="max-height:140px;overflow:auto;border:1px solid var(--border-color);border-radius:3px;">
            <table class="data-table" id="lab-preview-table" style="margin:0;font-size:10.5px;">
              <thead id="lab-preview-thead"></thead><tbody id="lab-preview-tbody"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;
}

export function setupDatasetHandlers(onFileReady) {
  const byId = id => document.getElementById(id);
  const dz = byId('lab-dropzone'), fi = byId('lab-dataset-file');
  if (dz && fi) {
    dz.addEventListener('click', () => fi.click());
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
    dz.addEventListener('drop', e => {
      e.preventDefault(); dz.classList.remove('dragover');
      if (e.dataTransfer.files.length) loadFile(e.dataTransfer.files[0]);
    });
    fi.addEventListener('change', e => { if (e.target.files.length) loadFile(e.target.files[0]); });
  }

  byId('btn-toggle-import-panel')?.addEventListener('click', () => {
    const p = byId('lab-import-panel'), b = byId('btn-toggle-import-panel');
    const isHidden = p.style.display === 'none';
    p.style.display = isHidden ? 'flex' : 'none';
    b.innerHTML = isHidden ? '&minus; Collapse' : '&#43; Expand';
  });

  byId('btn-use-synthetic')?.addEventListener('click', async () => {
    try {
      const res = await opGenerateFile(null, 100, 25, null);
      onFileReady(res.file_id);
    } catch (err) { alert(`Synthetic sample failed: ${err.message}`); }
  });

  byId('btn-import-encrypt')?.addEventListener('click', async () => {
    if (!datasetText) return;
    const name = byId('import-name').value.trim() || undefined;
    const fmt = byId('import-format').value;
    const rate = parseInt(byId('import-rate').value || 100, 10);
    const rekey = parseInt(byId('import-rekey').value || 50, 10);
    const cols = Array.from(selectedColumns);
    try {
      const res = await opImportDataset(datasetText, name, fmt, cols, rate, rekey);
      onFileReady(res.file_id);
    } catch (err) { alert(`Import failed: ${err.message}`); }
  });

  async function loadFile(file) {
    try {
      datasetText = await file.text();
      const fmt = byId('import-format').value;
      datasetPreview = await opPreviewDataset(datasetText, fmt);
      selectedColumns = new Set(datasetPreview.columns);
      renderPreview(file.name);
      byId('btn-import-encrypt').disabled = false;
      if (!byId('import-name').value) byId('import-name').value = file.name.replace(/\.[^/.]+$/, "");
    } catch (err) { alert(`Preview failed: ${err.message}`); }
  }

  function renderPreview(filename) {
    const p = datasetPreview;
    byId('lab-dataset-preview-container').style.display = 'block';
    byId('lab-dataset-meta').textContent = `${p.format.toUpperCase()} (${filename}): ${p.row_count} rows, ${p.columns.length} columns`;
    const picks = byId('lab-dataset-col-picks');
    picks.innerHTML = p.columns.map(c => `
      <label style="cursor:pointer;"><input type="checkbox" class="col-pick" data-col="${c}" checked> ${c}</label>
    `).join('');
    picks.querySelectorAll('.col-pick').forEach(cb => {
      cb.addEventListener('change', e => {
        if (e.target.checked) selectedColumns.add(e.target.dataset.col);
        else selectedColumns.delete(e.target.dataset.col);
      });
    });
    byId('lab-preview-thead').innerHTML = `<tr>${p.columns.map(c => `<th>${c}</th>`).join('')}</tr>`;
    const tb = byId('lab-preview-tbody');
    tb.innerHTML = '';
    p.sample.forEach(row => {
      const tr = document.createElement('tr');
      p.columns.forEach(c => {
        const td = document.createElement('td');
        td.textContent = row[c] !== undefined ? String(row[c]) : '';
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
  }
}

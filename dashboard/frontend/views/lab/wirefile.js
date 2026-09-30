// File Lab Step 2: Wire File Management & Hand-Attack Flow
import { formatError } from '../../lib/api.js';
import { opDownloadFile, opUploadFile, opDeleteFile, opGetSourceRows, opGetFrames } from '../lab_ops.js';

let currentFile = null;

export function renderStep2HTML() {
  return `
    <div class="step-card" id="step-2-card">
      <div class="step-header" id="step-2-header">
        <div class="step-title-group">
          <span class="step-badge" id="step-2-badge">2</span>
          <span class="step-title">WIRE CAPTURE FILE</span>
          <span class="step-summary-text" id="step-2-summary" style="display:none;"></span>
        </div>
        <button class="btn-step-edit" id="step-2-edit-btn" style="display:none;">Edit</button>
      </div>

      <div class="step-content" id="step-2-content" style="display:none;">
        <!-- Compact File Card -->
        <div class="wire-card">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <span id="step2-file-dropdown-wrap" style="display:none;">
                <select id="step2-file-select" class="lab-file-select"></select>
              </span>
              <span id="step2-file-name" style="font-weight:700;font-size:13px;color:var(--text-bright);">-</span>
              <span id="step2-meta-stats" style="font-size:11px;color:var(--text-dim);">-</span>
              <span id="step2-key-badge" class="badge-status normal" style="display:none;">Keys OK</span>
            </div>

            <!-- Actions: Download, Upload, More -->
            <div style="display:flex;align-items:center;gap:8px;">
              <button id="btn-step2-download" class="btn btn-secondary btn-sm" title="Download wire file for offline editing">
                Download wire file (.txt)
              </button>
              <label class="btn btn-secondary btn-sm" style="margin:0;cursor:pointer;" title="Upload hand-edited wire file">
                Upload edited file
                <input type="file" id="step2-file-upload" accept=".wire.txt,.txt,.jsonl" style="display:none;">
              </label>

              <!-- Extra actions menu -->
              <div style="position:relative;">
                <button id="btn-step2-more" class="btn btn-secondary btn-sm" style="padding:4px 8px;">&hellip;</button>
                <div id="step2-more-menu" class="dropdown-menu-box" style="display:none;right:0;">
                  <button class="btn-link" id="btn-step2-delete" style="color:var(--c-red);">Delete capture</button>
                </div>
              </div>
            </div>
          </div>

          <!-- Collapsible: Plaintext vs Ciphertext comparison -->
          <div style="margin-top:12px;border-top:1px solid var(--border-color);padding-top:10px;">
            <div class="section-toggle" id="step2-vs-toggle">
              <span class="toggle-arrow" id="step2-vs-arrow">&#9656;</span>
              <span style="font-weight:600;font-size:11px;color:var(--text-dim);">Show plaintext vs ciphertext comparison</span>
            </div>
            <div id="step2-vs-body" style="display:none;margin-top:8px;">
              <div class="lab-vs-card" style="margin-top:0;">
                <div>
                  <div style="font-size:10px;font-weight:700;color:var(--c-green);margin-bottom:3px;">WHAT YOU SENT (Plaintext Row #1):</div>
                  <div id="step2-vs-plain" style="font-family:var(--font-mono);font-size:10.5px;color:var(--text-main);word-break:break-all;">-</div>
                </div>
                <div>
                  <div style="font-size:10px;font-weight:700;color:var(--c-amber);margin-bottom:3px;">WHAT THE ENEMY SEES (Encrypted Wire Frame #1):</div>
                  <div id="step2-vs-wire" style="font-family:var(--font-mono);font-size:10.5px;color:var(--c-amber);word-break:break-all;">-</div>
                </div>
              </div>
            </div>
          </div>

          <!-- Collapsible: Cheat Sheet -->
          <div style="margin-top:8px;">
            <div class="section-toggle" id="step2-cheat-toggle">
              <span class="toggle-arrow" id="step2-cheat-arrow">&#9656;</span>
              <span style="font-weight:600;font-size:11px;color:var(--text-dim);">How to attack by hand (offline cheat sheet)</span>
            </div>
            <div id="step2-cheat-body" style="display:none;margin-top:8px;font-size:11px;color:var(--text-dim);line-height:1.5;background:rgba(0,0,0,0.2);padding:10px;border-radius:4px;border:1px solid var(--border-color);">
              <p><strong>1. Download:</strong> Click <em>[Download wire file (.txt)]</em>. Open the file in Notepad or VS Code.</p>
              <p><strong>2. Tamper:</strong> Change any single hex character in the <code>hex</code> field of a frame.</p>
              <p><strong>3. Replay:</strong> Duplicate any line and paste it further down the file.</p>
              <p><strong>4. Drop:</strong> Delete an entire line from the file to simulate packet loss.</p>
              <p><strong>5. Upload:</strong> Click <em>[Upload edited file]</em>. SecureLink automatically diffs your edits and runs verification.</p>
            </div>
          </div>
        </div>

        <!-- Next Step Prompt -->
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px;">
          <span style="font-size:11px;color:var(--text-dim);">Ready to test? Attack the wire file or verify immediately:</span>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-secondary btn-sm" id="btn-goto-step3">Attack in Browser &rarr;</button>
            <button class="btn btn-primary btn-sm" id="btn-goto-step4">Proceed to Verify &rarr;</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

export function initStep2({ onFileChanged, onUploadEdited, onGoToStep, onDeleteSuccess }) {
  const byId = id => document.getElementById(id);

  byId('btn-step2-download')?.addEventListener('click', () => {
    if (currentFile?.file_id) opDownloadFile(currentFile.file_id, 'working');
  });

  byId('step2-file-upload')?.addEventListener('change', async e => {
    const file = e.target.files[0];
    if (!file || !currentFile?.file_id) return;
    try {
      const data = await opUploadFile(file, currentFile.file_id);
      if (onUploadEdited) onUploadEdited(data.file_id, file.name);
    } catch (err) { alert(`Upload failed: ${formatError(err)}`); }
  });

  byId('step2-file-select')?.addEventListener('change', e => {
    if (onFileChanged) onFileChanged(e.target.value);
  });

  byId('btn-step2-more')?.addEventListener('click', e => {
    e.stopPropagation();
    const menu = byId('step2-more-menu');
    if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  });
  document.addEventListener('click', () => {
    const menu = byId('step2-more-menu');
    if (menu) menu.style.display = 'none';
  });

  byId('btn-step2-delete')?.addEventListener('click', async () => {
    if (!currentFile?.file_id || !confirm(`Permanently delete wire file ${currentFile.name}?`)) return;
    try {
      await opDeleteFile(currentFile.file_id);
      if (onDeleteSuccess) onDeleteSuccess();
    } catch (err) { alert(`Delete failed: ${formatError(err)}`); }
  });

  byId('step2-vs-toggle')?.addEventListener('click', () => toggleSection('step2-vs-body', 'step2-vs-arrow'));
  byId('step2-cheat-toggle')?.addEventListener('click', () => toggleSection('step2-cheat-body', 'step2-cheat-arrow'));

  byId('btn-goto-step3')?.addEventListener('click', () => { if (onGoToStep) onGoToStep(3); });
  byId('btn-goto-step4')?.addEventListener('click', () => { if (onGoToStep) onGoToStep(4); });

  function toggleSection(bodyId, arrowId) {
    const b = byId(bodyId), a = byId(arrowId);
    const isHidden = b.style.display === 'none';
    b.style.display = isHidden ? 'block' : 'none';
    a.innerHTML = isHidden ? '&#9660;' : '&#9656;';
  }
}

export async function updateStep2Card(file, allFiles = []) {
  currentFile = file;
  const byId = id => document.getElementById(id);
  if (!file) return;

  const selWrap = byId('step2-file-dropdown-wrap');
  const sel = byId('step2-file-select');
  if (allFiles.length > 1 && sel && selWrap) {
    selWrap.style.display = 'inline-block';
    sel.innerHTML = allFiles.map(f => `
      <option value="${f.file_id}" ${f.file_id === file.file_id ? 'selected' : ''}>${f.name || f.file_id.slice(0, 8)}</option>
    `).join('');
    byId('step2-file-name').style.display = 'none';
  } else {
    if (selWrap) selWrap.style.display = 'none';
    const nameEl = byId('step2-file-name');
    if (nameEl) {
      nameEl.style.display = 'inline-block';
      nameEl.textContent = file.name || file.file_id.slice(0, 8);
    }
  }

  const epochs = Math.ceil((file.frame_count || 1) / (file.rekey_every_packets || 50));
  byId('step2-meta-stats').textContent = `${file.frame_count} frames · ${epochs} epochs · rekey/${file.rekey_every_packets || 50}`;

  const badge = byId('step2-key-badge');
  if (badge) {
    badge.style.display = 'inline-block';
    if (file.key_match) {
      badge.textContent = 'Keys OK';
      badge.className = 'badge-status normal';
    } else {
      badge.textContent = 'Key mismatch';
      badge.className = 'badge-status blocked';
    }
  }

  // Update VS preview
  try {
    const src = await opGetSourceRows(file.file_id, 0, 1);
    if (src.rows?.length) {
      byId('step2-vs-plain').textContent = JSON.stringify(src.rows[0]);
    }
    const frames = await opGetFrames(file.file_id, 'working', 0, 1);
    if (frames.rows?.length) {
      byId('step2-vs-wire').textContent = frames.rows[0].hex_preview + '... [AES-GCM + Ed25519]';
    }
  } catch (e) {}
}

// File Lab Step 3: Attack Workbench (Edit by hand + Quick browser attack)
import { formatError } from '../../lib/api.js';
import { opResetEdits, opRemoveEdit, opGetFrames, opGetFileInfo } from '../lab_ops.js';
import { renderFrameTableSkeleton, FrameTableController } from './components/frameTable.js';
import { openDrawer } from './components/drawer.js';

let activeFileId = null, tableCtrl = null;

export function renderStep3HTML() {
  return `
    <div class="step-card" id="step-3-card">
      <div class="step-header" id="step-3-header">
        <div class="step-title-group">
          <span class="step-badge" id="step-3-badge">3</span>
          <span class="step-title">ATTACK WORKBENCH</span>
          <span class="step-summary-text" id="step-3-summary" style="display:none;"></span>
        </div>
        <button class="btn-step-edit" id="step-3-edit-btn" style="display:none;">Edit</button>
      </div>

      <div class="step-content" id="step-3-content" style="display:none;">
        <!-- Top Attack Tabs -->
        <div class="sub-tab-bar">
          <button class="sub-tab active" id="tab-attack-hand">Edit by Hand (Recommended)</button>
          <button class="sub-tab" id="tab-attack-browser">Quick Attack in Browser</button>
        </div>

        <!-- Tab 1: Edit by Hand Panel -->
        <div id="panel-attack-hand" class="sub-tab-panel" style="margin-top:12px;">
          <div style="background:rgba(0,0,0,0.2);padding:14px;border-radius:4px;border:1px solid var(--border-color);line-height:1.6;font-size:11.5px;">
            <p style="font-weight:700;color:var(--c-cyan);margin-bottom:6px;">How to attack the wire file offline:</p>
            <ol style="margin-left:18px;margin-bottom:12px;">
              <li>In <strong>Step 2</strong>, click <em>[Download wire file (.txt)]</em> to save the encrypted frames.</li>
              <li>Open the file in any text editor (Notepad, VS Code, vim).</li>
              <li>Change any bytes in a frame's <code>hex</code> field to tamper with ciphertext or tags.</li>
              <li>Duplicate or delete lines to test replay or dropped packets.</li>
              <li>In <strong>Step 2</strong>, click <em>[Upload edited file]</em>. SecureLink verifies all mutations against ground truth.</li>
            </ol>
            <div style="display:flex;gap:10px;">
              <button class="btn btn-secondary btn-sm" id="btn-back-to-step2">&larr; Back to Step 2 (Download / Upload)</button>
              <button class="btn btn-outline-success btn-sm" id="btn-hand-goto-step4">Proceed to Verify &rarr;</button>
            </div>
          </div>
        </div>

        <!-- Tab 2: Quick Attack in Browser Panel -->
        <div id="panel-attack-browser" class="sub-tab-panel" style="display:none;margin-top:12px;">
          <div style="margin-bottom:8px;font-size:11px;color:var(--text-dim);display:flex;justify-content:space-between;align-items:center;">
            <span>Click any frame row below to open the inspector and inject an attack:</span>
            <button class="btn btn-outline-danger btn-sm" id="btn-reset-all-edits" style="font-size:10px;padding:2px 8px;">Reset All Edits</button>
          </div>

          <!-- Shared Frame Table -->
          ${renderFrameTableSkeleton('step3-frame-table')}

          <!-- Collapsible Active Edit Log -->
          <div style="margin-top:12px;border-top:1px solid var(--border-color);padding-top:10px;">
            <div class="section-toggle" id="step3-edits-toggle">
              <span class="toggle-arrow" id="step3-edits-arrow">&#9656;</span>
              <span style="font-weight:700;font-size:11px;color:var(--c-amber);">
                ACTIVE IN-BROWSER EDITS (<span id="step3-edit-count">0</span>)
              </span>
            </div>
            <div id="step3-edits-body" style="display:none;margin-top:8px;max-height:120px;overflow-y:auto;">
              <div id="step3-edits-list"></div>
            </div>
          </div>

          <div style="margin-top:14px;display:flex;justify-content:flex-end;">
            <button class="btn btn-primary btn-sm" id="btn-browser-goto-step4">Proceed to Verify Working Copy &rarr;</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

export function initStep3(fileIdOrOpts = {}, maybeOpts = {}) {
  const byId = id => document.getElementById(id);
  const opts = (typeof fileIdOrOpts === 'object' && fileIdOrOpts !== null) ? fileIdOrOpts : maybeOpts;
  if (typeof fileIdOrOpts === 'string') activeFileId = fileIdOrOpts;
  const onGoToStep = opts.onGoToStep || null;
  const onEditsChanged = opts.onEditsChanged || null;

  tableCtrl = new FrameTableController('step3-frame-table', {
    onRowClick: eid => {
      if (activeFileId) openDrawer(activeFileId, eid);
    },
  });
  tableCtrl.mount();

  byId('tab-attack-hand')?.addEventListener('click', () => switchTab('hand'));
  byId('tab-attack-browser')?.addEventListener('click', () => switchTab('browser'));

  byId('btn-back-to-step2')?.addEventListener('click', () => { if (onGoToStep) onGoToStep(2); });
  byId('btn-hand-goto-step4')?.addEventListener('click', () => { if (onGoToStep) onGoToStep(4); });
  byId('btn-browser-goto-step4')?.addEventListener('click', () => { if (onGoToStep) onGoToStep(4); });

  byId('step3-edits-toggle')?.addEventListener('click', () => {
    const b = byId('step3-edits-body'), a = byId('step3-edits-arrow');
    const isHidden = b.style.display === 'none';
    b.style.display = isHidden ? 'block' : 'none';
    a.innerHTML = isHidden ? '&#9660;' : '&#9656;';
  });

  byId('btn-reset-all-edits')?.addEventListener('click', async () => {
    if (!activeFileId || !confirm('Reset all in-browser edits to baseline?')) return;
    try {
      await opResetEdits(activeFileId);
      await refreshStep3(activeFileId);
      if (onEditsChanged) onEditsChanged(activeFileId);
    } catch (err) { alert(`Reset failed: ${formatError(err)}`); }
  });

  function switchTab(mode) {
    const isHand = mode === 'hand';
    byId('tab-attack-hand').classList.toggle('active', isHand);
    byId('tab-attack-browser').classList.toggle('active', !isHand);
    byId('panel-attack-hand').style.display = isHand ? 'block' : 'none';
    byId('panel-attack-browser').style.display = isHand ? 'none' : 'block';
  }
}

export async function refreshStep3(fileId) {
  activeFileId = fileId;
  if (!fileId) return;

  try {
    const data = await opGetFrames(fileId, 'working', 0, 100);
    const fileInfo = await opGetFileInfo(fileId);
    tableCtrl.setData(data.rows || []);
    renderEditList(fileInfo.edits || []);
  } catch (err) { console.error('Failed to refresh step 3:', formatError(err)); }
}

function renderEditList(edits) {
  const byId = id => document.getElementById(id);
  byId('step3-edit-count').textContent = edits.length;
  const list = byId('step3-edits-list');
  if (!list) return;

  if (!edits.length) {
    list.innerHTML = '<div style="font-size:10px;color:var(--text-dim);font-style:italic;">No active in-browser edits.</div>';
    return;
  }

  list.innerHTML = edits.map(e => `
    <div class="lab-edit-item">
      <span><strong>${e.op.toUpperCase()}</strong>: ${JSON.stringify(e.params)}</span>
      <button class="btn btn-outline-danger btn-sm" style="font-size:9.5px;padding:0 5px;" data-edit-id="${e.edit_id}">Undo</button>
    </div>
  `).join('');

  list.querySelectorAll('button[data-edit-id]').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await opRemoveEdit(activeFileId, btn.dataset.editId);
        await refreshStep3(activeFileId);
      } catch (err) { alert(formatError(err)); }
    });
  });
}

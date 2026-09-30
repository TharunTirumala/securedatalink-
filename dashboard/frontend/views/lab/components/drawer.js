// File Lab - Slide-Over Frame Inspector & Attack Drawer Component
import { opGetFrameDetail, opApplyAttack, readAttackParams } from '../../lab_ops.js';
import { renderHexViewer, renderAttackInputs } from '../../lab_render.js';

let activeFileId = null, activeEid = null, attackCallback = null;

export function renderDrawerSkeleton() {
  return `
    <div id="lab-drawer-backdrop" class="drawer-backdrop" style="display:none;"></div>
    <div id="lab-drawer" class="drawer-panel" style="display:none;">
      <div class="drawer-header">
        <div>
          <span style="font-size:12px;font-weight:700;color:var(--c-cyan);">FRAME INSPECTOR</span>
          <span id="drawer-frame-title" style="font-size:11px;color:var(--text-dim);margin-left:8px;">-</span>
        </div>
        <button id="btn-close-drawer" class="drawer-close-btn">&times;</button>
      </div>
      <div id="drawer-body" class="drawer-body">
        <div id="drawer-hex-box" class="lab-hex-box"></div>
        <div class="lab-legend" style="margin-top:6px;">
          <span><span class="legend-dot" style="background:#00e5ff;"></span>Header</span>
          <span><span class="legend-dot" style="background:#ffaa00;"></span>Ciphertext</span>
          <span><span class="legend-dot" style="background:#b366ff;"></span>Tag</span>
          <span><span class="legend-dot" style="background:#00ff88;"></span>Signature</span>
        </div>
        <div style="margin-top:16px;border-top:1px solid var(--border-color);padding-top:12px;">
          <div style="font-size:11px;font-weight:700;color:var(--c-amber);letter-spacing:1px;margin-bottom:8px;">INJECT ADVERSARIAL ATTACK</div>
          <div style="display:flex;gap:6px;margin-bottom:8px;">
            <select id="drawer-attack-op" class="lab-file-select" style="flex:1;">
              <option value="tamper">Tamper Bytes</option>
              <option value="replay">Replay Frame</option>
              <option value="spoof">Spoof Sender</option>
              <option value="drop">Drop Frame</option>
            </select>
            <button id="btn-drawer-apply-attack" class="btn btn-warning btn-sm">Apply Attack</button>
          </div>
          <div id="drawer-attack-params" style="font-size:11px;margin-bottom:6px;"></div>
          <div id="drawer-attack-hint" style="font-size:10px;color:var(--text-dim);font-style:italic;"></div>
        </div>
      </div>
    </div>
  `;
}

export function initDrawer(onAttackApplied) {
  attackCallback = onAttackApplied;
  const backdrop = document.getElementById('lab-drawer-backdrop');
  const closeBtn = document.getElementById('btn-close-drawer');
  const opSelect = document.getElementById('drawer-attack-op');
  const applyBtn = document.getElementById('btn-drawer-apply-attack');

  backdrop?.addEventListener('click', closeDrawer);
  closeBtn?.addEventListener('click', closeDrawer);
  opSelect?.addEventListener('change', renderOpInputs);
  applyBtn?.addEventListener('click', handleApply);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isDrawerOpen()) closeDrawer();
  });
  renderOpInputs();
}

export function isDrawerOpen() {
  const drawer = document.getElementById('lab-drawer');
  return drawer && drawer.style.display !== 'none';
}

export async function openDrawer(fileId, eid) {
  activeFileId = fileId;
  activeEid = eid;
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('lab-drawer-backdrop');
  if (!drawer || !backdrop) return;

  backdrop.style.display = 'block';
  drawer.style.display = 'flex';
  document.getElementById('drawer-frame-title').textContent = `Loading EID ${eid}...`;

  try {
    const detail = await opGetFrameDetail(fileId, eid);
    document.getElementById('drawer-frame-title').textContent = `Line ${detail.n + 1} · EID ${eid} (${detail.size}B)`;
    document.getElementById('drawer-hex-box').innerHTML = renderHexViewer(detail.hex, detail.ranges || []);
  } catch (err) {
    document.getElementById('drawer-hex-box').innerHTML = `<span style="color:var(--c-red);">Failed to inspect: ${err.message}</span>`;
  }
}

export function closeDrawer() {
  const drawer = document.getElementById('lab-drawer');
  const backdrop = document.getElementById('lab-drawer-backdrop');
  if (backdrop) backdrop.style.display = 'none';
  if (drawer) drawer.style.display = 'none';
  activeEid = null;
}

function renderOpInputs() {
  const op = document.getElementById('drawer-attack-op')?.value || 'tamper';
  const cfg = renderAttackInputs(op);
  const container = document.getElementById('drawer-attack-params');
  const hint = document.getElementById('drawer-attack-hint');
  if (container) container.innerHTML = cfg.html;
  if (hint) hint.textContent = cfg.hint;
}

async function handleApply() {
  if (!activeFileId || !activeEid) return alert('No frame selected.');
  const op = document.getElementById('drawer-attack-op').value;
  const params = readAttackParams(op, activeEid);
  try {
    await opApplyAttack(activeFileId, op, params);
    if (attackCallback) await attackCallback(activeEid);
    await openDrawer(activeFileId, activeEid);
  } catch (err) { alert(`Attack failed: ${err.message}`); }
}

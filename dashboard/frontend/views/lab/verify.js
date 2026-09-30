import { formatError } from '../../lib/api.js';
import { opVerify, opGetFileInfo } from '../lab_ops.js';
import { renderC2StreamTable, renderReconciliationTab } from '../lab_recon.js';
import { createVerdictCounters } from '../../components/verdictCounters.js';
import { createVerdictFeed } from '../../components/verdictFeed.js';
import { createIncidentLog } from '../../components/incidentLog.js';
import { openDrawer } from './components/drawer.js';

let activeFileId = null, onVerifiedCb = null, lastVerifyMode = 'working';
let countersCtrl = null, feedCtrl = null, incidentCtrl = null;
let lastBaselineSummary = null;

export function renderStep4HTML() {
  return `
    <div class="step-card" id="step-4-card">
      <div class="step-header" id="step-4-header">
        <div class="step-title-group">
          <span class="step-badge" id="step-4-badge">4</span>
          <span class="step-title">VERIFY & RESULTS</span>
          <span class="step-summary-text" id="step-4-summary" style="display:none;"></span>
        </div>
        <button class="btn-step-edit" id="step-4-edit-btn" style="display:none;">Edit</button>
      </div>

      <div class="step-content" id="step-4-content" style="display:none;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn btn-primary" id="btn-verify-working">Verify Working Copy</button>
            <button class="btn btn-secondary" id="btn-verify-baseline">Verify Baseline (Untouched)</button>
            <button class="btn-tool" id="btn-download-wire" style="padding:6px 10px;font-size:11px;">Download .wire</button>
          </div>
          <div id="verify-status-msg" style="font-size:11px;color:var(--text-dim);"></div>
        </div>

        <div id="verify-error-box" style="display:none;margin-bottom:12px;border:1px solid var(--c-red);background:rgba(255,51,102,0.12);padding:10px 14px;border-radius:4px;color:var(--c-red);font-size:11.5px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
            <span id="verify-error-text" style="word-break:break-word;"></span>
            <button class="btn btn-outline-danger btn-sm" id="btn-verify-retry" style="font-size:10px;padding:2px 8px;white-space:nowrap;">Retry</button>
          </div>
        </div>

        <div id="baseline-clean-banner" style="display:none;margin-bottom:12px;padding:8px 12px;border-radius:4px;border:1px solid rgba(0,255,136,0.3);background:rgba(0,255,136,0.08);color:var(--c-green);font-size:11.5px;font-weight:600;">
          &#10003; Baseline Clean: 100% Authentic &mdash; Untouched original passes all crypto, epoch &amp; replay checks.
        </div>
        <div id="baseline-compare-strip" style="display:none;margin-bottom:12px;padding:8px 12px;border-radius:4px;border:1px solid var(--border-color);background:rgba(0,0,0,0.25);font-size:11px;color:var(--text-dim);">
          <span id="compare-text"></span>
        </div>

        <div class="sub-tab-bar" style="margin-bottom:12px;">
          <button class="sub-tab active" id="tab-v-feed">Packet Feed &amp; Incidents</button>
          <button class="sub-tab" id="tab-v-c2">Decoded C2 Stream</button>
          <button class="sub-tab" id="tab-v-recon">Reconciliation Audit</button>
        </div>

        <div id="panel-v-feed" class="sub-tab-panel">
          <div id="lab-counters-host"></div>
          <div class="lab-results-grid">
            <div class="panel" style="min-width:0;">
              <div class="panel-header">
                <h3>VERIFIED WIRE FEED</h3>
                <span class="hud-subtext" id="lab-feed-subtext">Wire Order &bull; Lines 1..N</span>
              </div>
              <div id="lab-feed-host" style="padding:0;"></div>
            </div>
            <div class="panel" style="min-width:0;">
              <div class="panel-header">
                <h3>SECURITY INCIDENT LOG</h3>
                <span class="hud-subtext">In-Memory ACK</span>
              </div>
              <div id="lab-incidents-host" style="padding:10px;"></div>
            </div>
          </div>
        </div>

        <div id="panel-v-c2" class="sub-tab-panel" style="display:none;">
          <div id="c2-stream-banner" style="margin-bottom:8px;font-size:11.5px;color:var(--c-cyan);">Clean C2 Output Stream</div>
          <div class="table-responsive">
            <table class="data-table" style="width:100%;"><thead id="c2-stream-thead"></thead><tbody id="c2-stream-tbody"></tbody></table>
          </div>
        </div>

        <div id="panel-v-recon" class="sub-tab-panel" style="display:none;">
          <div class="dashboard-grid" id="recon-audit-cards" style="margin-bottom:12px;"></div>
          <div id="recon-audit-details" style="background:rgba(0,0,0,0.2);padding:14px;border-radius:4px;border:1px solid var(--border-color);line-height:1.6;font-size:11.5px;"></div>
        </div>
      </div>
    </div>
  `;
}

function initControllers() {
  const countersHost = document.getElementById('lab-counters-host');
  const feedHost = document.getElementById('lab-feed-host');
  const incidentsHost = document.getElementById('lab-incidents-host');

  if (countersHost && (!countersCtrl || !countersHost.querySelector('.verdict-counters-wrap'))) {
    countersCtrl = createVerdictCounters(countersHost, {
      onFilterChange: (verdict) => {
        if (feedCtrl) feedCtrl.setFilter(verdict);
      },
    });
  }

  if (feedHost && (!feedCtrl || !feedHost.querySelector('.verdict-feed-container'))) {
    feedCtrl = createVerdictFeed(feedHost, {
      mode: 'fileLab',
      maxHeight: '440px',
      onSelectRow: (row) => {
        if (activeFileId && row.eid) openDrawer(activeFileId, row.eid);
      },
      onProgress: (runningCounts, runningIncidents) => {
        if (countersCtrl) countersCtrl.setCounts(runningCounts);
        if (incidentCtrl) incidentCtrl.setIncidents(runningIncidents);
      },
    });
  }

  if (incidentsHost && (!incidentCtrl || !incidentsHost.querySelector('.incident-log-container'))) {
    incidentCtrl = createIncidentLog(incidentsHost, {
      maxHeight: '400px',
      onSelectIncident: (inc) => {
        if (feedCtrl) feedCtrl.scrollToItem(inc.eid || inc.seq);
      },
      onAck: async () => {},
    });
  }
}

export function initStep4(fileId, options = {}) {
  activeFileId = fileId;
  onVerifiedCb = options.onVerified || null;

  initControllers();

  const byId = (id) => document.getElementById(id);
  byId('btn-verify-working')?.addEventListener('click', () => runVerification('working'));
  byId('btn-verify-baseline')?.addEventListener('click', () => runVerification('original'));
  byId('btn-verify-retry')?.addEventListener('click', () => runVerification(lastVerifyMode));

  byId('btn-download-wire')?.addEventListener('click', () => {
    if (activeFileId) window.open(`/api/lab/files/${activeFileId}/download?view=${lastVerifyMode}`, '_blank');
  });

  byId('tab-v-feed')?.addEventListener('click', () => switchTab('feed'));
  byId('tab-v-c2')?.addEventListener('click', () => switchTab('c2'));
  byId('tab-v-recon')?.addEventListener('click', () => switchTab('recon'));
}

export async function setStep4File(fileId) {
  if (fileId && fileId !== activeFileId) {
    activeFileId = fileId;
    if (feedCtrl) feedCtrl.clear();
    if (incidentCtrl) incidentCtrl.clear();
    if (countersCtrl) countersCtrl.setCounts({ AUTHENTIC: 0, TAMPERED: 0, REPLAYED: 0, SPOOFED: 0, DROPPED: 0, OTHER: 0, total: 0 });
  } else if (fileId) {
    activeFileId = fileId;
  }
  initControllers();
  const btnB = document.getElementById('btn-verify-baseline');
  if (!btnB) return;
  try {
    const info = await opGetFileInfo(fileId);
    const isUploadedWithoutParent = info?.meta?.source_kind === 'upload' && !info?.parent_id;
    btnB.disabled = Boolean(isUploadedWithoutParent);
    btnB.style.opacity = isUploadedWithoutParent ? '0.5' : '1';
    btnB.style.cursor = isUploadedWithoutParent ? 'not-allowed' : 'pointer';
  } catch (_) {}
}

export async function runVerification(mode = 'working') {
  if (!activeFileId) {
    const sel = document.getElementById('step2-file-select');
    if (sel && sel.value) activeFileId = sel.value;
  }
  console.log('[runVerification] activeFileId:', activeFileId, 'mode:', mode);
  if (!activeFileId) return;
  lastVerifyMode = mode;
  initControllers();

  const statusEl = document.getElementById('verify-status-msg');
  const errBox = document.getElementById('verify-error-box');
  const btnW = document.getElementById('btn-verify-working');
  const btnB = document.getElementById('btn-verify-baseline');

  if (errBox) errBox.style.display = 'none';
  if (btnW) btnW.disabled = true;
  if (btnB) btnB.disabled = true;
  if (statusEl) statusEl.textContent = 'Verifying frames...';

  try {
    const vData = await opVerify(activeFileId, mode);
    renderVerificationResults(vData, mode);
    if (onVerifiedCb) onVerifiedCb(vData.summary, mode);
  } catch (err) {
    if (errBox) {
      errBox.style.display = 'block';
      const errText = document.getElementById('verify-error-text');
      if (errText) errText.textContent = formatError(err);
    }
  } finally {
    if (btnW) btnW.disabled = false;
    if (btnB) btnB.disabled = false;
    if (statusEl) statusEl.textContent = '';
  }
}

function renderVerificationResults(vData, mode) {
  const sum = vData.summary || {};
  const feedData = vData.feed || {};
  const rows = feedData.rows || vData.rows || [];
  console.log('[renderVerificationResults] rows:', rows.length, 'mode:', mode, 'feedCtrl exists:', Boolean(feedCtrl));
  const counts = feedData.counts || {
    AUTHENTIC: sum.authentic || 0,
    TAMPERED: 0, REPLAYED: 0, SPOOFED: 0, DROPPED: 0, OTHER: 0,
    total: rows.length,
  };
  const incidents = feedData.incidents || [];

  const feedSubtext = document.getElementById('lab-feed-subtext');
  if (feedSubtext) {
    feedSubtext.textContent = `Wire Order \u2022 Lines 1\u2013${counts.total} (${counts.total} rows loaded)`;
  }

  if (countersCtrl) {
    countersCtrl.setCounts({ ...counts, AUTHENTIC: 0, TAMPERED: 0, REPLAYED: 0, SPOOFED: 0, DROPPED: 0, OTHER: 0, total: 0 });
  }
  if (incidentCtrl) {
    incidentCtrl.setIncidents([]);
  }
  if (feedCtrl) {
    feedCtrl.setData(rows, { counts, incidents, animate: true });
  }

  const baseBanner = document.getElementById('baseline-clean-banner');
  const compStrip = document.getElementById('baseline-compare-strip');
  const compText = document.getElementById('compare-text');

  if (mode === 'original') {
    lastBaselineSummary = { ...sum, total: counts.total, authentic: counts.AUTHENTIC };
    if (baseBanner) baseBanner.style.display = (counts.AUTHENTIC === counts.total) ? 'block' : 'none';
    if (compStrip) compStrip.style.display = 'none';
  } else {
    if (baseBanner) baseBanner.style.display = 'none';
    if (compStrip && compText) {
      const baseAuth = lastBaselineSummary ? (lastBaselineSummary.authentic ?? counts.total) : counts.total;
      const baseTot = lastBaselineSummary ? (lastBaselineSummary.total ?? counts.total) : counts.total;
      const suppressed = counts.total - counts.AUTHENTIC;
      compText.textContent = `Clean baseline: ${baseAuth}/${baseTot} authentic (0 suppressed) \u2022 Working copy: ${counts.AUTHENTIC}/${counts.total} authentic (${suppressed} suppressed)`;
      compStrip.style.display = 'block';
    }
  }

  renderC2StreamTable(vData.clean_output || [], vData.delivery || {});
  renderReconciliationTab(vData.delivery || {}, vData.gaps || []);
}

function switchTab(tab) {
  ['feed', 'c2', 'recon'].forEach((t) => {
    const tabBtn = document.getElementById(`tab-v-${t}`);
    const panel = document.getElementById(`panel-v-${t}`);
    if (tabBtn) tabBtn.classList.toggle('active', t === tab);
    if (panel) panel.style.display = t === tab ? 'block' : 'none';
  });
}

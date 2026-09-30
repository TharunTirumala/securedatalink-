// File Lab Main Shell - Stepper Header, Accordion Coordinator, Drawer Host
import { opListFiles, opGetFileInfo } from '../lab_ops.js';
import { renderDrawerSkeleton, initDrawer } from './components/drawer.js';
import { renderStep1HTML, initStep1 } from './import.js';
import { renderStep2HTML, initStep2, updateStep2Card } from './wirefile.js';
import { renderStep3HTML, initStep3, refreshStep3 } from './attack.js';
import { renderStep4HTML, initStep4, setStep4File, runVerification } from './verify.js';

let activeStep = 1, activeFileId = null, allFiles = [];
const stepSummaries = { 1: '', 2: '', 3: '', 4: '' };

export function mountLab(container) {
  container.innerHTML = `
    <div class="lab-container">
      <!-- Dismissible Educational Banner -->
      <div class="lab-banner" id="lab-edu-banner">
        <div>
          <strong style="color:var(--c-cyan);">File Lab:</strong> Import CSV/JSON telemetry, inspect encrypted wire frames across HKDF epochs, test hand/browser attacks, and verify RX pipeline defenses.
        </div>
        <button class="btn-banner-close" id="btn-close-banner" aria-label="Dismiss banner">&times;</button>
      </div>

      <!-- Sticky Stepper Header -->
      <div class="stepper-header" id="lab-stepper">
        <div class="stepper-item active" data-step="1">
          <span class="stepper-circle">1</span>
          <span class="stepper-label">Import Dataset</span>
        </div>
        <div class="stepper-sep">&rarr;</div>
        <div class="stepper-item pending" data-step="2">
          <span class="stepper-circle">2</span>
          <span class="stepper-label">Wire File</span>
        </div>
        <div class="stepper-sep">&rarr;</div>
        <div class="stepper-item pending" data-step="3">
          <span class="stepper-circle">3</span>
          <span class="stepper-label">Attack Workbench</span>
        </div>
        <div class="stepper-sep">&rarr;</div>
        <div class="stepper-item pending" data-step="4">
          <span class="stepper-circle">4</span>
          <span class="stepper-label">Verify &amp; Results</span>
        </div>
      </div>

      <!-- 4 Accordion Step Cards -->
      <div class="steps-container">
        ${renderStep1HTML()}
        ${renderStep2HTML()}
        ${renderStep3HTML()}
        ${renderStep4HTML()}
      </div>

      <!-- Slide-Over Drawer Host -->
      ${renderDrawerSkeleton()}
    </div>
  `;

  bindBanner();
  bindStepperClicks();
  bindEditButtons();

  initDrawer(async () => {
    if (activeFileId) {
      await refreshStep3(activeFileId);
      updateStep3Summary(activeFileId);
    }
  });

  initStep1((newFileId, summaryText) => {
    stepSummaries[1] = summaryText;
    activeFileId = newFileId;
    loadFiles(newFileId).then(() => setActiveStep(2));
  });

  initStep2({
    onFileChanged: fid => switchFile(fid),
    onUploadEdited: (newFid, fileName) => {
      stepSummaries[2] = `Uploaded edited: ${fileName}`;
      activeFileId = newFid;
      loadFiles(newFid).then(() => {
        setActiveStep(4);
        runVerification('working');
      });
    },
    onGoToStep: stepNum => setActiveStep(stepNum),
    onDeleteSuccess: () => {
      activeFileId = null;
      loadFiles().then(() => setActiveStep(1));
    },
  });

  initStep3(activeFileId, {
    onEditsChanged: fid => updateStep3Summary(fid),
    onGoToStep: stepNum => setActiveStep(stepNum),
  });

  initStep4(activeFileId, {
    onVerified: (summary, mode) => {
      const tot = summary.total || 0, auth = summary.authentic || 0, fa = summary.false_accepts || 0;
      stepSummaries[4] = `${auth}/${tot} authentic \u2022 ${fa} false accepts (${mode})`;
      updateCardHeaders();
    },
  });

  loadFiles().then(() => {
    if (allFiles.length > 0) {
      setActiveStep(2);
    } else {
      setActiveStep(1);
    }
  });
}

export function unmountLab() {
  activeFileId = null;
}

export function setActiveStep(stepNum) {
  if (stepNum > 1 && !activeFileId && allFiles.length === 0) return;
  activeStep = stepNum;

  for (let s = 1; s <= 4; s++) {
    const cardContent = document.getElementById(`step-${s}-content`);
    const cardSummary = document.getElementById(`step-${s}-summary`);
    const editBtn = document.getElementById(`step-${s}-edit-btn`);
    const stepperItem = document.querySelector(`.stepper-item[data-step="${s}"]`);

    const isOpen = s === stepNum;
    if (cardContent) cardContent.style.display = isOpen ? 'block' : 'none';

    if (isOpen) {
      if (cardSummary) cardSummary.style.display = 'none';
      if (editBtn) editBtn.style.display = 'none';
    } else {
      const hasSummary = Boolean(stepSummaries[s]);
      if (cardSummary) {
        cardSummary.textContent = hasSummary ? `\u2022 ${stepSummaries[s]}` : '';
        cardSummary.style.display = hasSummary ? 'inline-block' : 'none';
      }
      if (editBtn) editBtn.style.display = hasSummary ? 'inline-block' : 'none';
    }

    if (stepperItem) {
      stepperItem.classList.remove('active', 'completed', 'pending');
      if (s === stepNum) stepperItem.classList.add('active');
      else if (s < stepNum || stepSummaries[s]) stepperItem.classList.add('completed');
      else stepperItem.classList.add('pending');
    }
  }

  if (stepNum === 3 && activeFileId) refreshStep3(activeFileId);
  if (stepNum === 4 && activeFileId) setStep4File(activeFileId);
}

function updateCardHeaders() {
  for (let s = 1; s <= 4; s++) {
    if (s !== activeStep) {
      const sumEl = document.getElementById(`step-${s}-summary`);
      const editBtn = document.getElementById(`step-${s}-edit-btn`);
      if (sumEl && stepSummaries[s]) {
        sumEl.textContent = `\u2022 ${stepSummaries[s]}`;
        sumEl.style.display = 'inline-block';
        if (editBtn) editBtn.style.display = 'inline-block';
      }
    }
  }
}

async function loadFiles(preferredId = null) {
  try {
    allFiles = await opListFiles();
    if (allFiles.length > 0) {
      if (preferredId && allFiles.find(f => f.file_id === preferredId)) {
        activeFileId = preferredId;
      } else if (!activeFileId || !allFiles.find(f => f.file_id === activeFileId)) {
        activeFileId = allFiles[0].file_id;
      }
      const cur = allFiles.find(f => f.file_id === activeFileId) || allFiles[0];
      stepSummaries[1] = `${cur.name || 'Dataset'} (${cur.frame_count || 0} frames)`;
      stepSummaries[2] = `${cur.name || 'Wire capture'} \u2022 ${cur.frame_count || 0} frames \u2022 Keys OK`;
      await updateStep2Card(cur, allFiles);
      if (activeStep === 3) await refreshStep3(activeFileId);
      setStep4File(activeFileId);
      updateStep3Summary(activeFileId);
    } else {
      activeFileId = null;
      stepSummaries[1] = ''; stepSummaries[2] = ''; stepSummaries[3] = ''; stepSummaries[4] = '';
    }
    updateCardHeaders();
  } catch (err) { console.error('Failed to load lab files:', err); }
}

async function switchFile(fid) {
  activeFileId = fid;
  await loadFiles(fid);
}

async function updateStep3Summary(fid) {
  try {
    const info = await opGetFileInfo(fid);
    const count = info?.edits?.length || 0;
    const inferred = info?.inferred_labels || {};
    const changesCount = Object.values(inferred).filter(l => l !== 'AUTHENTIC').length;
    if (changesCount > 0 && count === 0) {
      stepSummaries[3] = `${changesCount} changes detected \u2022 0 active edits`;
    } else if (changesCount > 0 && count > 0) {
      stepSummaries[3] = `${changesCount} uploaded changes + ${count} in-browser edits`;
    } else {
      stepSummaries[3] = count > 0 ? `${count} active edits` : '0 edits active';
    }
    updateCardHeaders();
  } catch (err) { /* silent */ }
}

function bindBanner() {
  const banner = document.getElementById('lab-edu-banner');
  const closeBtn = document.getElementById('btn-close-banner');
  if (sessionStorage.getItem('securelink_lab_banner_dismissed') === '1') {
    if (banner) banner.style.display = 'none';
  }
  closeBtn?.addEventListener('click', () => {
    if (banner) banner.style.display = 'none';
    sessionStorage.setItem('securelink_lab_banner_dismissed', '1');
  });
}

function bindStepperClicks() {
  document.querySelectorAll('.stepper-item').forEach(item => {
    item.addEventListener('click', () => {
      const step = parseInt(item.dataset.step, 10);
      setActiveStep(step);
    });
  });
}

function bindEditButtons() {
  for (let s = 1; s <= 4; s++) {
    document.getElementById(`step-${s}-edit-btn`)?.addEventListener('click', () => setActiveStep(s));
    document.getElementById(`step-${s}-header`)?.addEventListener('click', (e) => {
      if (e.target.closest('.btn-step-edit') || s !== activeStep) {
        setActiveStep(s);
      }
    });
  }
}

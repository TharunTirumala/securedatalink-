// File Lab - Shared Reusable Frame Table Component
export function renderFrameTableSkeleton(containerId) {
  return `
    <div class="frame-table-wrapper" id="${containerId}">
      <div class="frame-table-toolbar">
        <div class="lab-filters" id="${containerId}-filters">
          <span class="lab-chip active" data-filter="ALL">All Frames</span>
          <span class="lab-chip" data-filter="EDITED">Edited Only</span>
          <span class="lab-chip" data-filter="REJECTED">Rejected Only</span>
        </div>
        <div style="display:flex;align-items:center;gap:12px;">
          <button class="btn btn-secondary btn-sm btn-more-cols" id="${containerId}-toggle-cols" style="font-size:10px;padding:2px 8px;">
            More columns &#9662;
          </button>
          <div class="frame-table-page-info" id="${containerId}-page-info" style="font-size:11px;color:var(--text-dim);">
            Showing 0 - 0 of 0
          </div>
          <div style="display:flex;gap:4px;">
            <button class="btn btn-secondary btn-sm" id="${containerId}-prev" disabled>&larr;</button>
            <button class="btn btn-secondary btn-sm" id="${containerId}-next" disabled>&rarr;</button>
          </div>
        </div>
      </div>

      <div class="table-responsive" style="margin-top:8px;">
        <table class="data-table clean-frame-table" style="width:100%;margin:0;">
          <thead>
            <tr>
              <th style="width:55px;">Line</th>
              <th class="col-more" style="display:none;width:60px;">EID</th>
              <th style="width:65px;">Epoch</th>
              <th style="width:75px;">Seq</th>
              <th class="col-more" style="display:none;width:65px;">Size</th>
              <th class="col-more" style="display:none;width:75px;">Origin</th>
              <th style="width:100px;">Marks</th>
              <th class="th-verdict" style="width:110px;display:none;">Verdict</th>
              <th>Hex Preview</th>
            </tr>
          </thead>
          <tbody id="${containerId}-tbody">
            <tr><td colspan="7" class="placeholder-row">No frames to display.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;
}

export class FrameTableController {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.onRowClick = options.onRowClick || null;
    this.pageSize = 25;
    this.page = 0;
    this.showMoreCols = false;
    this.filter = 'ALL';
    this.rows = [];
    this.verifyData = null;
    this.selectedEid = null;
  }

  mount() {
    const byId = id => document.getElementById(`${this.containerId}-${id}`);
    byId('toggle-cols')?.addEventListener('click', () => this.toggleMoreCols());
    byId('prev')?.addEventListener('click', () => this.changePage(-1));
    byId('next')?.addEventListener('click', () => this.changePage(1));

    this.bindFilters();
  }

  setFilters(filtersHtml) {
    const filterBox = document.getElementById(`${this.containerId}-filters`);
    if (!filterBox) return;
    filterBox.innerHTML = filtersHtml;
    this.bindFilters();
  }

  bindFilters() {
    const filterBox = document.getElementById(`${this.containerId}-filters`);
    filterBox?.querySelectorAll('.lab-chip').forEach(chip => {
      chip.addEventListener('click', e => {
        filterBox.querySelectorAll('.lab-chip').forEach(c => c.classList.remove('active'));
        e.target.classList.add('active');
        this.filter = e.target.dataset.filter;
        this.page = 0;
        this.render();
      });
    });
  }

  setData(rows, verifyData = null) {
    this.rows = rows || [];
    this.verifyData = verifyData;
    this.render();
  }

  setSelectedEid(eid) {
    this.selectedEid = eid;
    this.render();
  }

  toggleMoreCols() {
    this.showMoreCols = !this.showMoreCols;
    const btn = document.getElementById(`${this.containerId}-toggle-cols`);
    if (btn) btn.innerHTML = this.showMoreCols ? 'Fewer columns &#9652;' : 'More columns &#9662;';
    const root = document.getElementById(this.containerId);
    root?.querySelectorAll('.col-more').forEach(el => {
      el.style.display = this.showMoreCols ? 'table-cell' : 'none';
    });
  }

  changePage(dir) {
    const maxPage = Math.max(0, Math.ceil(this.getFilteredRows().length / this.pageSize) - 1);
    this.page = Math.max(0, Math.min(this.page + dir, maxPage));
    this.render();
  }

  getFilteredRows() {
    const vMap = {};
    if (this.verifyData?.rows) {
      this.verifyData.rows.forEach(r => { vMap[r.eid] = r; });
    }
    return this.rows.filter(r => {
      const isEdited = (r.marks && r.marks.length > 0) || r.dropped || r.origin !== 'original';
      const vItem = vMap[r.eid];
      const verdict = vItem?.verdict;
      const classification = vItem?.classification;
      if (this.filter === 'EDITED') return isEdited;
      if (this.filter === 'REJECTED') return verdict && verdict !== 'AUTHENTIC';
      if (this.filter === 'AUTHENTIC') return verdict === 'AUTHENTIC';
      if (this.filter === 'FALSE_ACCEPTS') return classification === 'FALSE_ACCEPT';
      if (this.filter === 'FALSE_REJECTS') return classification === 'FALSE_REJECT';
      return true;
    });
  }

  render() {
    const tbody = document.getElementById(`${this.containerId}-tbody`);
    if (!tbody) return;

    const filtered = this.getFilteredRows();
    const total = filtered.length;
    const start = total === 0 ? 0 : this.page * this.pageSize + 1;
    const end = Math.min((this.page + 1) * this.pageSize, total);

    const info = document.getElementById(`${this.containerId}-page-info`);
    if (info) info.textContent = `Showing ${start} - ${end} of ${total}`;

    const prevBtn = document.getElementById(`${this.containerId}-prev`);
    const nextBtn = document.getElementById(`${this.containerId}-next`);
    if (prevBtn) prevBtn.disabled = this.page === 0;
    if (nextBtn) nextBtn.disabled = end >= total;

    const root = document.getElementById(this.containerId);
    const hasVerify = !!this.verifyData;
    root?.querySelectorAll('.th-verdict').forEach(th => {
      th.style.display = hasVerify ? 'table-cell' : 'none';
    });
    root?.querySelectorAll('.col-more').forEach(el => {
      el.style.display = this.showMoreCols ? 'table-cell' : 'none';
    });

    if (!total) {
      const colSpan = this.showMoreCols ? (hasVerify ? 9 : 8) : (hasVerify ? 6 : 5);
      tbody.innerHTML = `<tr><td colspan="${colSpan}" class="placeholder-row">No matching frames.</td></tr>`;
      return;
    }

    const vMap = {};
    if (this.verifyData?.rows) {
      this.verifyData.rows.forEach(r => { vMap[r.eid] = r; });
    }

    const pageSlice = filtered.slice(this.page * this.pageSize, (this.page + 1) * this.pageSize);
    tbody.innerHTML = pageSlice.map(r => {
      const lineNo = r.n + 1;
      const isSel = r.eid === this.selectedEid ? 'selected-row' : '';
      const isDrop = r.dropped ? 'is-dropped' : '';
      const marks = (r.marks || []).map(m => `<span class="badge-status badge-label-${m}">${m}</span>`).join(' ') || '<span style="color:var(--text-dim);">-</span>';
      
      let vCell = '';
      if (hasVerify) {
        const v = vMap[r.eid]?.verdict;
        const vClass = v === 'AUTHENTIC' ? 'normal' : 'blocked';
        vCell = `<td><span class="badge-status ${vClass}">${v || 'N/A'}</span></td>`;
      }

      const hexShort = (r.hex_preview || '').slice(0, 24);
      const moreCells = `
        <td class="col-more cell-mono" style="${this.showMoreCols ? '' : 'display:none;'}">${r.eid}</td>
        <td class="col-more cell-mono" style="${this.showMoreCols ? '' : 'display:none;'}">${r.size}B</td>
        <td class="col-more" style="${this.showMoreCols ? '' : 'display:none;'}">${r.origin}</td>
      `;

      return `
        <tr class="frame-row ${isSel} ${isDrop}" data-eid="${r.eid}">
          <td class="cell-num">${lineNo}</td>
          ${moreCells}
          <td class="cell-num">${r.epoch ?? '-'}</td>
          <td class="cell-num cell-mono">${r.seq ?? '-'}</td>
          <td>${marks}</td>
          ${vCell}
          <td class="cell-mono hex-preview-col" title="${r.hex_preview}">${hexShort}<span class="hex-ellipsis">...</span></td>
        </tr>
      `;
    }).join('');

    tbody.querySelectorAll('.frame-row').forEach(tr => {
      tr.addEventListener('click', () => {
        const eid = tr.dataset.eid;
        this.selectedEid = eid;
        this.render();
        if (this.onRowClick) this.onRowClick(eid);
      });
    });
  }
}

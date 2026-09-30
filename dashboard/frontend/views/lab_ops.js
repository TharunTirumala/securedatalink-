// File Lab API Operations (Preview, Import, Generate, Upload, Attack, Verify, Reconcile)
import { api, getApiToken } from '../lib/api.js';

export async function opPreviewDataset(text, format = 'auto', columns = null) {
  const token = getApiToken(), headers = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (token) headers['X-SecureLink-Token'] = token;
  const colParam = columns?.length ? `&columns=${encodeURIComponent(columns.join(','))}` : '';
  const res = await fetch(`/api/lab/datasets/preview?format=${format}${colParam}`, { method: 'POST', headers, body: text });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

export async function opImportDataset(text, name, format = 'auto', columns = null, rate = 100, rekey = 50) {
  const token = getApiToken(), headers = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (token) headers['X-SecureLink-Token'] = token;
  const colParam = columns?.length ? `&columns=${encodeURIComponent(columns.join(','))}` : '';
  const nameParam = name ? `&name=${encodeURIComponent(name)}` : '';
  const url = `/api/lab/datasets/import?format=${format}&rate_pps=${rate}&rekey_every_packets=${rekey}${nameParam}${colParam}`;
  const res = await fetch(url, { method: 'POST', headers, body: text });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

export async function opGenerateFile(inputName, count, rekey, seed) {
  return await api.post('/api/lab/files/generate', {
    name: inputName || undefined, count, rekey_every_packets: rekey,
    seed: seed ? parseInt(seed, 10) : undefined,
  });
}

export async function opUploadFile(file, parentId = null) {
  const text = await file.text(), token = getApiToken();
  const headers = { 'Content-Type': 'text/plain; charset=utf-8' };
  if (token) headers['X-SecureLink-Token'] = token;
  const pParam = parentId ? `&parent_id=${encodeURIComponent(parentId)}` : '';
  const res = await fetch(`/api/lab/files/upload?name=${encodeURIComponent(file.name)}${pParam}`, {
    method: 'POST', headers, body: text,
  });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

export async function opListFiles() { return await api.get('/api/lab/files'); }
export async function opGetFileInfo(fid) { return await api.get(`/api/lab/files/${fid}`); }
export async function opGetSourceRows(fid, offset = 0, limit = 100) {
  return await api.get(`/api/lab/files/${fid}/source?offset=${offset}&limit=${limit}`);
}
export async function opGetFrames(fid, view = 'working', offset = 0, limit = 100) {
  return await api.get(`/api/lab/files/${fid}/frames?view=${view}&offset=${offset}&limit=${limit}`);
}
export async function opGetFrameDetail(fid, eid) { return await api.get(`/api/lab/files/${fid}/frames/${eid}`); }
export async function opApplyAttack(fid, op, params) { return await api.post(`/api/lab/files/${fid}/edits`, { op, params }); }
export async function opRemoveEdit(fid, editId) { return await api.delete(`/api/lab/files/${fid}/edits/${editId}`); }
export async function opResetEdits(fid) { return await api.post(`/api/lab/files/${fid}/edits/reset`, {}); }
export async function opVerify(fid, mode = 'working') { return await api.post(`/api/lab/files/${fid}/verify`, { mode }); }

export async function opGetLastVerification(fid, mode = 'working', view = 'rows', verdict = null, offset = 0, limit = 100) {
  const vParam = verdict ? `&verdict=${encodeURIComponent(verdict)}` : '';
  return await api.get(`/api/lab/files/${fid}/verify/last?mode=${mode}&view=${view}&offset=${offset}&limit=${limit}${vParam}`);
}

export async function opDeleteFile(fid) { return await api.delete(`/api/lab/files/${fid}`); }
export function opDownloadFile(fid, viewMode) {
  window.open(`/api/lab/files/${fid}/download?view=${viewMode}`, '_blank');
}

export function readAttackParams(op, selectedEid) {
  const params = {};
  if (op === 'tamper') {
    params.eid = selectedEid;
    params.target = document.getElementById('attack-tamper-target')?.value || 'ciphertext';
    params.byte_offset = parseInt(document.getElementById('attack-tamper-offset')?.value || 0, 10);
    params.xor_mask = parseInt(document.getElementById('attack-tamper-mask')?.value || 1, 10);
  } else if (op === 'replay') {
    params.source_eid = selectedEid;
    params.delay_s = parseFloat(document.getElementById('attack-replay-delay')?.value || 1.0);
  } else if (op === 'spoof') {
    params.insert_after_eid = selectedEid;
    params.count = parseInt(document.getElementById('attack-spoof-count')?.value || 1, 10);
  } else if (op === 'drop') {
    params.eid_from = selectedEid;
  }
  return params;
}

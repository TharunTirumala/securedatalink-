// Centralized API client with error handling, formatError, and optional token header

let apiToken = localStorage.getItem('securelink_token') || '';

export function setApiToken(token) {
  apiToken = token;
  if (token) {
    localStorage.setItem('securelink_token', token);
  } else {
    localStorage.removeItem('securelink_token');
  }
}

export function getApiToken() {
  return apiToken;
}

export function formatError(err) {
  if (!err) return 'Unknown error';
  if (typeof err === 'string') return err;

  // Network failures
  if (err.status === 0 || (err.name === 'TypeError' && (err.message?.includes('fetch') || err.message?.includes('NetworkError') || err.message?.includes('Failed')))) {
    return 'Cannot reach the server. Ensure the SecureLink backend is running.';
  }

  const statusPrefix = err.status ? `[HTTP ${err.status}] ` : '';
  const detail = err.detail !== undefined ? err.detail : err.message;

  if (typeof detail === 'string') {
    if (detail.startsWith('{') || detail.startsWith('[')) {
      try {
        return formatError({ status: err.status, detail: JSON.parse(detail) });
      } catch (_) {}
    }
    return `${statusPrefix}${detail}`;
  }

  if (Array.isArray(detail)) {
    const msgs = detail.map(item => {
      if (typeof item === 'string') return item;
      const field = Array.isArray(item.loc) ? item.loc[item.loc.length - 1] : (item.loc || 'field');
      return `${field}: ${item.msg || 'invalid'}`;
    });
    return `${statusPrefix}${msgs.join('; ')}`;
  }

  if (detail && typeof detail === 'object') {
    if (detail.detail) return formatError({ status: err.status, detail: detail.detail });
    if (detail.message) return `${statusPrefix}${detail.message}`;
    try {
      const s = JSON.stringify(detail);
      return `${statusPrefix}${s.length > 300 ? s.slice(0, 300) + '...' : s}`;
    } catch (_) {
      return `${statusPrefix}Unspecified error object`;
    }
  }

  return `${statusPrefix}${String(err)}`;
}

export async function request(endpoint, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };
  if (apiToken) {
    headers['X-SecureLink-Token'] = apiToken;
  }

  const config = {
    ...options,
    headers,
  };

  let response;
  try {
    response = await fetch(endpoint, config);
  } catch (netErr) {
    const err = new Error('Cannot reach the server');
    err.name = 'TypeError';
    err.status = 0;
    throw err;
  }

  if (!response.ok) {
    let errDetail = `${response.status} ${response.statusText}`;
    let rawDetail = null;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail !== undefined) {
        rawDetail = errJson.detail;
        errDetail = typeof rawDetail === 'string' ? rawDetail : JSON.stringify(rawDetail);
      }
    } catch (_) {
      try {
        const text = await response.text();
        if (text) errDetail = text;
      } catch (_) {}
    }
    const err = new Error(errDetail);
    err.status = response.status;
    err.detail = rawDetail !== null ? rawDetail : errDetail;
    throw err;
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return await response.json();
  }
  return await response.text();
}

export const api = {
  get: (url, opts) => request(url, { ...opts, method: 'GET' }),
  post: (url, body, opts) => request(url, { ...opts, method: 'POST', body: JSON.stringify(body) }),
  delete: (url, opts) => request(url, { ...opts, method: 'DELETE' }),
};

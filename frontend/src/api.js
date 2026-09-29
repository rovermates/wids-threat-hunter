export async function request(path, options = {}) {
  const response = await fetch(`/api${path}`, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const message = typeof body.detail === 'string' ? body.detail : 'The request could not be completed. Check your input and try again.';
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

export function query(values) {
  return new URLSearchParams(Object.entries(values).filter(([, value]) => value !== '' && value != null)).toString();
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function exportPackets(values) {
  const response = await fetch(`/api/export?${query(values)}`);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || 'Export failed. Refresh and try again.');
  }
  downloadBlob(await response.blob(), `wids-packets.${values.format}`);
}

export const count = (value) => value == null ? '—' : new Intl.NumberFormat('en-US').format(value);
export const percent = (value) => value == null ? '—' : `${(value * 100).toFixed(2)}%`;
export const time = (value) => value ? new Date(value).toLocaleTimeString('en-GB', { timeZone: 'UTC', hour12: false }) : '—';

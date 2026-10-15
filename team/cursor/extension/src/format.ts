/** $142.60, or $1,234 above $1,000. */
export function money(d: number): string {
  return d >= 1000 ? `$${Math.round(d).toLocaleString('en-US')}` : `$${d.toFixed(2)}`;
}

/** $142, for tight spaces such as the status bar. */
export function moneyShort(d: number): string {
  return d < 10 ? `$${d.toFixed(2)}` : `$${Math.round(d).toLocaleString('en-US')}`;
}

export function pct(share: number): string {
  return `${Math.round(share * 100)}%`;
}

/** '2026-10-19' -> 'Oct 19' (dates from the API are UTC calendar days). */
export function day(isoDate: string): string {
  return new Date(`${isoDate.slice(0, 10)}T00:00:00Z`).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

/** Timestamp -> 'Oct 7, 09:12' in local time. */
export function dateTime(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}, ` +
    d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

export function monthName(month: string): string {
  return new Date(`${month}-01T00:00:00Z`).toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
}

/** 'October 2026' when the billing period is a calendar month, else its dates, e.g. 'Oct 15 – Nov 14'. */
export function periodName(s: { month: string; period_start?: string; period_end?: string }): string {
  const start = s.period_start ? new Date(s.period_start) : undefined;
  if (!start || !s.period_end || (start.getUTCDate() === 1 && start.getUTCHours() === 0 && start.getUTCMinutes() === 0)) {
    return monthName(s.month);
  }
  const last = new Date(new Date(s.period_end).getTime() - 1);
  const f = (d: Date) => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
  return `${f(start)} – ${f(last)}`;
}

export function ago(iso: string | null): string {
  if (!iso) { return 'never'; }
  const min = Math.round((Date.now() - new Date(iso).getTime()) / 60_000);
  if (min < 1) { return 'just now'; }
  if (min < 60) { return `${min} min ago`; }
  const h = Math.round(min / 60);
  return h < 24 ? `${h} h ago` : `${Math.round(h / 24)} d ago`;
}

export function openFor(days: number): string {
  if (days < 1) { return 'under a day'; }
  const n = Math.round(days);
  return `${n} day${n === 1 ? '' : 's'}`;
}

export function tokens(n: number | null): string {
  if (n === null) { return '?'; }
  return n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : `${n}`;
}

export function esc(s: string | null | undefined): string {
  return (s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

export function shiftMonth(month: string, by: number): string {
  const [y, m] = month.split('-').map(Number);
  const d = new Date(Date.UTC(y, m - 1 + by, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

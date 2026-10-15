import { DevUser, Summary, Tip, Tokens } from './api';
import { ago, dateTime, day, esc, money, moneyShort, openFor, pct, periodName, tokens } from './format';

/** Colours come from the active Cursor theme, so the views match light and dark themes. */
const CSS = `
:root {
  --fg: var(--vscode-foreground); --muted: var(--vscode-descriptionForeground);
  --line: var(--vscode-widget-border, var(--vscode-panel-border, rgba(128,128,128,.35)));
  --accent: var(--vscode-charts-blue, #3794ff); --ok: var(--vscode-charts-green, #89d185);
  --warn: var(--vscode-charts-orange, #d18616); --crit: var(--vscode-charts-red, #f14c4c);
  --hover: var(--vscode-list-hoverBackground, rgba(128,128,128,.12)); --track: rgba(128,128,128,.22);
}
body { color: var(--fg); font-family: var(--vscode-font-family); font-size: var(--vscode-font-size, 13px); line-height: 1.45; margin: 0; }
.tnum { font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); }
.mono { font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; }
h2 { font-size: 18px; font-weight: 600; margin: 0; }
h4 { font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; margin: 0; display: flex; justify-content: space-between; gap: 8px; }
h4 small { font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--muted); }
.pill { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 999px; white-space: nowrap; }
.pill.ok { color: var(--ok); background: color-mix(in srgb, var(--ok) 18%, transparent); }
.pill.warn { color: var(--warn); background: color-mix(in srgb, var(--warn) 18%, transparent); }
.pill.crit { color: var(--crit); background: color-mix(in srgb, var(--crit) 18%, transparent); }
.pill.final { color: var(--muted); background: var(--track); }
.meter { height: 8px; border-radius: 4px; background: var(--track); position: relative; }
.meter i { position: absolute; inset: 0 auto 0 0; border-radius: 4px; max-width: 100%; }
.meter i.ok { background: var(--accent); } .meter i.warn { background: var(--warn); } .meter i.crit { background: var(--crit); }
.meter b { position: absolute; top: -3px; bottom: -3px; width: 2px; background: var(--fg); }
button { font: inherit; font-size: 12px; padding: 4px 10px; border-radius: 2px; border: 1px solid transparent; cursor: pointer;
  color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
button:hover { background: var(--vscode-button-secondaryHoverBackground); }
button:disabled { opacity: .45; cursor: default; }
button:disabled:hover { background: var(--vscode-button-secondaryBackground); }
button.primary { color: var(--vscode-button-foreground); background: var(--vscode-button-background); }
button.primary:hover { background: var(--vscode-button-hoverBackground); }
button:focus-visible { outline: 1px solid var(--vscode-focusBorder); outline-offset: 2px; }
button.wide { width: 100%; padding: 6px; }
.banner { font-size: 12px; padding: 6px 8px; border-radius: 3px; border: 1px dashed var(--warn); color: var(--warn); }
.bars { display: grid; gap: 7px; }
.bar { display: grid; grid-template-columns: minmax(0,1fr) auto; gap: 2px 8px; font-size: 12px; }
.bar > span:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar .track { grid-column: 1 / -1; height: 5px; background: var(--track); border-radius: 3px; }
.bar .track i { display: block; height: 100%; border-radius: 3px; background: var(--accent); }
.tipno { display: inline-grid; place-items: center; flex: none; width: 16px; height: 16px; border-radius: 50%; margin-right: 6px;
  background: var(--fg); color: var(--vscode-editor-background, #1e1e1e); font-size: 10px; font-weight: 700; vertical-align: 1px; }
code { font-family: var(--vscode-editor-font-family, monospace); font-size: .92em; padding: 0 3px; border-radius: 3px; background: var(--track); }
@keyframes flash { from { box-shadow: 0 0 0 2px var(--vscode-focusBorder); } to { box-shadow: 0 0 0 2px transparent; } }
[data-focus] { animation: flash 2.4s ease-out; }
svg .grid { stroke: var(--track); stroke-width: 1; }
svg .axis { fill: var(--muted); font-size: 10px; }
svg .limit { stroke: var(--crit); stroke-width: 1.2; }
svg .limit-t { fill: var(--crit); font-size: 10px; }
svg .area { fill: var(--warn); opacity: .16; }
svg .line { fill: none; stroke: var(--warn); stroke-width: 2; stroke-linejoin: round; }
svg .proj { fill: none; stroke: var(--warn); stroke-width: 1.6; stroke-dasharray: 4 3; }
svg .dot { fill: var(--warn); } svg .xdot { fill: var(--crit); }
svg .val { fill: var(--fg); font-size: 10.5px; font-weight: 600; }
`;

export function page(body: string, nonce: string, cspSource: string, extraCss = ''): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${CSS}${extraCss}</style></head><body>${body}
<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-cmd]');
    if (b && b.tagName !== 'SELECT') { vscode.postMessage({ cmd: b.dataset.cmd, arg: b.dataset.arg }); }
  });
  const focused = document.querySelector('[data-focus]');
  if (focused) { focused.scrollIntoView({ block: 'center' }); }
  document.addEventListener('change', e => {
    const s = e.target.closest('select[data-cmd]');
    if (s) { s.disabled = true; vscode.postMessage({ cmd: s.dataset.cmd, arg: s.value }); }
  });
</script></body></html>`;
}

function statusPill(s: Summary): string {
  if (!s.is_current_month) { return '<span class="pill final">final</span>'; }
  if (s.status === 'over_limit') { return '<span class="pill crit">limit reached</span>'; }
  const cls = s.status === 'over_pace' ? 'crit' : s.status === 'watch' ? 'warn' : 'ok';
  return `<span class="pill ${cls}">pace ${moneyShort(s.projected_dollars)}</span>`;
}

function meterClass(s: Summary): string {
  return s.status === 'over_limit' || s.status === 'over_pace' ? 'crit' : s.status === 'watch' ? 'warn' : 'ok';
}

export function paceSentence(s: Summary): string {
  if (!s.is_current_month) { return `Final total for ${periodName(s)}.`; }
  if (s.reached_limit_on) { return `You reached your limit on ${day(s.reached_limit_on)}.`; }
  if (s.projected_reach_limit_date) { return `At this pace you'd reach your limit around ${day(s.projected_reach_limit_date)}.`; }
  return `On pace for ${money(s.projected_dollars)} this month.`;
}

function meter(s: Summary): string {
  const used = Math.min(100, (s.spent_dollars / s.limit_dollars) * 100);
  const even = s.is_current_month ? `<b style="left:${Math.min(100, s.even_pace_today_dollars / s.limit_dollars * 100).toFixed(1)}%" title="Where an even pace would be today"></b>` : '';
  return `<div class="meter" role="img" aria-label="${pct(s.spent_dollars / s.limit_dollars)} of limit used"><i class="${meterClass(s)}" style="width:${used.toFixed(1)}%"></i>${even}</div>`;
}

function viewingAs(s: Summary, viewAs: string): string {
  return viewAs ? `<div class="banner">Admin preview: viewing ${esc(s.name || s.email)} (${esc(s.email)})</div>` : '';
}

/* ---------------- sidebar ---------------- */

const SIDEBAR_CSS = `
body { padding: 4px 14px 16px; }
.sec { display: grid; gap: 8px; padding: 10px 0 14px; border-bottom: 1px solid var(--line); }
.sec:last-of-type { border-bottom: 0; }
.amt { font-size: 16px; } .amt span { font-weight: 400; font-size: 13px; color: var(--muted); }
.row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.fact { display: grid; grid-template-columns: minmax(0,1fr) auto; gap: 0 8px; font-size: 12.5px; }
.fact .sub { grid-column: 1 / -1; font-size: 11.5px; color: var(--muted); }
.foot { font-size: 11px; color: var(--muted); padding-top: 4px; }
.card { border: 1px solid var(--line); border-radius: 6px; padding: 9px 11px 10px 13px; display: grid; gap: 6px; position: relative;
  overflow: hidden; font-size: 12.5px; background: color-mix(in srgb, var(--fg) 3%, transparent); }
.card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--stripe, var(--accent)); }
.card.crit { --stripe: var(--crit); } .card.warn { --stripe: var(--warn); } .card.ok { --stripe: var(--ok); }
.card .t { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; font-weight: 600; font-size: 13px; }
.card .t > span:first-child { display: flex; align-items: baseline; }
.card p { margin: 0; }
.acts { display: flex; gap: 5px; flex-wrap: wrap; }
.acts button { font-size: 11.5px; padding: 3px 7px; }
.notice { font-size: 12.5px; display: grid; gap: 2px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
.notice:last-child { border-bottom: 0; padding-bottom: 0; }
.notice .when { font-size: 11px; color: var(--muted); }
`;

/** Escaped text with `code` spans, and the chat's start time filled in. */
function rich(text: string, tip?: Tip): string {
  const filled = tip?.chat_started ? text.replace('{chat_started}', dateTime(tip.chat_started)) : text;
  return esc(filled).replace(/`([^`]+)`/g, '<code>$1</code>');
}

function tipCard(t: Tip, i: number): string {
  const pill = `<span class="pill ${t.severity}" title="${esc(t.pill.title)}">${t.pill.saving ? '~' : ''}${moneyShort(t.pill.dollars)}</span>`;
  const acts = t.actions.map((a, j) =>
    `<button class="${a.primary ? 'primary' : ''}" data-cmd="tip" data-arg="${i}:${j}">${esc(a.label)}</button>`).join('');
  return `<div class="card ${t.severity}"><div class="t"><span><span class="tipno">${i + 1}</span><span>${rich(t.title)}</span></span>${pill}</div>
    <p>${rich(t.body, t)}</p><div class="acts">${acts}</div></div>`;
}

function coachHtml(s: Summary): string {
  const c = s.coach;
  if (!c?.tips.length) { return ''; }
  const n = c.tips.length;
  const saves = c.saving_month_dollars >= 1
    ? `<small title="Rough estimate at your current pace">saves about ${moneyShort(c.saving_month_dollars)}/mo</small>` : '';
  return `<div class="sec"><h4>${n} thing${n === 1 ? '' : 's'} to change ${saves}</h4>${c.tips.map(tipCard).join('')}</div>`;
}

function keepDoingHtml(s: Summary): string {
  const k = s.coach?.keep_doing ?? [];
  return k.length ? `<div class="sec"><h4>Keep doing</h4>${k.map(x =>
    `<div class="card ok"><div class="t"><span>${rich(x.title)}</span></div><p>${rich(x.body)}</p></div>`).join('')}</div>` : '';
}

function noticesHtml(s: Summary): string {
  const n = s.notices ?? [];
  return n.length ? `<div class="sec"><h4>From your Cursor admin</h4>${n.map(x =>
    `<div class="notice"><span class="when">${esc(day(x.created_at))}</span><span>${rich(x.text)}</span></div>`).join('')}</div>` : '';
}

const orgName = (s: Summary) => s.org_name || 'your organization';

function modelUpdatesHtml(s: Summary): string {
  const u = s.model_updates ?? [];
  return u.length ? `<div class="sec"><h4>Model updates <small title="Worked out from ${esc(orgName(s))}'s Cursor usage">from ${esc(orgName(s))}'s usage</small></h4>${u.map(x =>
    `<div class="notice"><span class="when">${esc(day(x.date))}</span><span>${rich(x.text.replace('{date}', day(x.date)))}</span></div>`).join('')}</div>` : '';
}

export function sidebarHtml(s: Summary, viewAs: string, nonce: string, csp: string): string {
  const chat = s.top_chats[0];
  const model = s.by_model[0];
  const facts = [
    chat ? `<div class="fact"><span>Chat started ${esc(dateTime(chat.started))}</span><strong class="tnum">${money(chat.dollars)}</strong>
      <span class="sub">${openFor(chat.open_days)} open · ${chat.prompts_total} prompts · ${pct(chat.share)} of your month</span></div>` : '',
    model ? `<div class="fact"><span class="mono">${esc(model.model)}</span><strong class="tnum">${money(model.dollars)}</strong>
      <span class="sub">Your top model · ${pct(model.share)} of your month</span></div>` : '',
    s.top_prompt ? `<div class="fact"><span>Most expensive prompt</span><strong class="tnum">${money(s.top_prompt.dollars)}</strong>
      <span class="sub">${esc(dateTime(s.top_prompt.ts))} · re-read ${tokens(s.top_prompt.cache_read_tokens)} tokens</span></div>` : '',
  ].join('');
  const body = `
  <div class="sec">
    ${viewingAs(s, viewAs)}
    <div class="row"><strong class="amt tnum">${money(s.spent_dollars)} <span>of ${moneyShort(s.limit_dollars)}</span></strong>${statusPill(s)}</div>
    ${meter(s)}
    <div class="muted">${esc(paceSentence(s))}</div>
  </div>
  ${coachHtml(s) || (facts ? `<div class="sec"><h4>Biggest costs <small>${esc(periodName(s))}</small></h4>${facts}</div>` : '')}
  ${keepDoingHtml(s)}
  <div class="sec"><button class="primary wide" data-cmd="breakdown">Show breakdown</button></div>
  ${noticesHtml(s)}
  ${modelUpdatesHtml(s)}
  <div class="foot">Updated ${ago(s.last_sync_at)}${s.data_through ? ` · data through ${esc(dateTime(s.data_through))}` : ''}</div>`;
  return page(body, nonce, csp, SIDEBAR_CSS);
}

export function messageHtml(title: string, detail: string, actions: [string, string][], nonce: string, csp: string): string {
  const btns = actions.map(([cmd, label], i) => `<button class="${i === 0 ? 'primary' : ''}" data-cmd="${cmd}">${esc(label)}</button>`).join(' ');
  return page(`<div style="display:grid;gap:10px;padding-top:12px"><strong>${esc(title)}</strong><span class="muted">${esc(detail)}</span><div>${btns}</div></div>`,
    nonce, csp, SIDEBAR_CSS);
}

/* ---------------- breakdown tab ---------------- */

const BREAKDOWN_CSS = `
body { padding: 20px 26px 32px; max-width: 1100px; }
main { display: grid; gap: 20px; }
.head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
.nav { display: flex; gap: 6px; align-items: center; }
.stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--line); border-radius: 6px; }
.stats > div { padding: 10px 14px; border-left: 1px solid var(--line); display: grid; gap: 1px; font-size: 12px; min-width: 0; }
.stats > div:first-child { border-left: 0; }
.lbl { font-size: 10.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.val { font-size: 20px; font-weight: 600; }
.val.crit { color: var(--crit); } .val.warn { color: var(--warn); }
.grid2 { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); gap: 28px; }
.sec { display: grid; gap: 10px; align-content: start; min-width: 0; }
.tbl { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 560px; font-size: 12.5px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 10.5px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.r { text-align: right; }
tr.hl td { background: color-mix(in srgb, var(--crit) 14%, transparent); }
.bar .tipno { margin-right: 4px; }
.tok-mix { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 6px 10px; align-items: center; font-size: 11.5px; max-width: 720px; }
.tok-bar { display: flex; height: 12px; border-radius: 3px; overflow: hidden; background: var(--track); }
.tok-bar i { display: block; height: 100%; }
.tok-bar i + i { box-shadow: -1px 0 0 var(--vscode-editor-background, transparent); }
.sw { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 6px; }
.k-input { background: var(--accent); } .k-cache_write { background: var(--vscode-charts-purple, #b180d7); }
.k-cache_read { background: var(--warn); } .k-output { background: var(--vscode-charts-green, #89d185); } .k-other { background: var(--muted); }
td.desc { color: var(--muted); max-width: 46ch; }
tr.total td { border-bottom: 0; font-weight: 600; }
tr.hl-warn td { background: color-mix(in srgb, var(--warn) 14%, transparent); }
.whatif { display: flex; gap: 6px 16px; align-items: baseline; flex-wrap: wrap; padding: 8px 12px; border: 1px dashed var(--line); border-radius: 6px; font-size: 12.5px; }
.whatif .save { color: var(--ok); font-weight: 600; }
.read { border: 1px solid var(--line); border-left: 3px solid var(--accent); border-radius: 6px; padding: 12px 14px; display: grid; gap: 8px;
  font-size: 12.5px; background: color-mix(in srgb, var(--accent) 7%, transparent); }
.read h5 { margin: 0; font-size: 13.5px; font-weight: 600; }
.read p { margin: 0; max-width: 80ch; }
.read ul { margin: 0; padding-left: 18px; display: grid; gap: 4px; max-width: 80ch; }
.read .src { font-size: 11px; color: var(--muted); }
.note { font-size: 12px; color: var(--muted); }
.dev { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 8px 10px; border: 1px dashed var(--warn); border-radius: 4px; font-size: 12px; }
.devtag { font-size: 10px; font-weight: 700; letter-spacing: .08em; color: var(--warn); }
.dev select { font: inherit; min-width: 0; max-width: 100%; padding: 3px 6px; border-radius: 2px;
  color: var(--vscode-dropdown-foreground); background: var(--vscode-dropdown-background); border: 1px solid var(--vscode-dropdown-border, var(--line)); }
.dev select:focus-visible { outline: 1px solid var(--vscode-focusBorder); }
@media (max-width: 760px) {
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .stats > div:nth-child(3) { border-left: 0; }
  .stats > div:nth-child(n+3) { border-top: 1px solid var(--line); }
  .grid2 { grid-template-columns: minmax(0, 1fr); }
}
`;

function niceStep(raw: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}

/** Cumulative spend, with the month-end projection and the limit, drawn to one scale. */
export function chartSvg(s: Summary, W = 460, H = 200): string {
  const dim = s.days_in_month;
  let c = 0;
  const cum = s.daily.map(d => (c += d.dollars));
  const last = cum.length;
  const top = Math.max(s.limit_dollars, s.projected_dollars, c, 1);
  const step = niceStep(top / 4);
  const ymax = Math.ceil((top * 1.08) / step) * step;
  const L = 44, R = 10, T = 12, B = 24;
  const x = (d: number) => L + ((d - 1) / Math.max(dim - 1, 1)) * (W - L - R);
  const y = (v: number) => T + (1 - v / ymax) * (H - T - B);
  const start = Date.parse(`${(s.period_start ?? `${s.month}-01`).slice(0, 10)}T00:00:00Z`);
  const dateOf = (n: number) => new Date(start + (n - 1) * 86_400_000).toISOString().slice(0, 10);   // day n of the period
  const dayOf = (iso: string) => Math.round((Date.parse(`${iso.slice(0, 10)}T00:00:00Z`) - start) / 86_400_000) + 1;
  let out = '';
  for (let v = 0; v <= ymax + 1e-9; v += step) {
    out += `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/>`;
    out += `<text class="axis" x="${L - 6}" y="${y(v) + 3.5}" text-anchor="end">$${Math.round(v).toLocaleString('en-US')}</text>`;
  }
  [1, 8, 15, 22, 29].filter(d => d <= dim).forEach(d => {
    out += `<text class="axis" x="${x(d)}" y="${H - 6}" text-anchor="middle">${day(dateOf(d))}</text>`;
  });
  out += `<line class="limit" x1="${L}" x2="${W - R}" y1="${y(s.limit_dollars)}" y2="${y(s.limit_dollars)}"/>`;
  out += `<text class="limit-t" x="${L + 4}" y="${y(s.limit_dollars) - 4}">limit ${moneyShort(s.limit_dollars)}</text>`;
  if (last > 0) {
    const pts = cum.map((v, i) => `${x(i + 1).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
    out += `<polygon class="area" points="${x(1)},${y(0)} ${pts} ${x(last)},${y(0)}"/>`;
    out += `<polyline class="line" points="${pts}"/>`;
    if (s.is_current_month && last < dim) {
      out += `<line class="proj" x1="${x(last)}" y1="${y(c)}" x2="${x(dim)}" y2="${y(s.projected_dollars)}"/>`;
      out += `<text class="val" x="${x(dim)}" y="${y(s.projected_dollars) - 6}" text-anchor="end">${moneyShort(s.projected_dollars)}</text>`;
    }
    out += `<circle class="dot" cx="${x(last)}" cy="${y(c)}" r="3.2"/>`;
    out += `<text class="val" x="${x(last) - 5}" y="${y(c) - 8}" text-anchor="end">${moneyShort(c)}</text>`;
  }
  const crossing = s.reached_limit_on ?? s.projected_reach_limit_date;
  if (crossing) {
    const cx = x(dayOf(crossing));
    out += `<circle class="xdot" cx="${cx}" cy="${y(s.limit_dollars)}" r="3"/>`;
    out += `<text class="limit-t" x="${cx}" y="${y(s.limit_dollars) + 14}" text-anchor="middle">${s.reached_limit_on ? '' : '~'}${day(crossing)}</text>`;
  }
  const label = `Cumulative spend ${money(c)}; ${s.is_current_month ? `projected ${money(s.projected_dollars)}` : 'final'}; limit ${money(s.limit_dollars)}`;
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label)}">${out}</svg>`;
}

export const PICKER_SORTS = {
  az: { label: 'A–Z', group: 'A–Z' },
  za: { label: 'Z–A', group: 'Z–A' },
  spendDesc: { label: 'Spend ↓', group: 'spend, high to low' },
  spendAsc: { label: 'Spend ↑', group: 'spend, low to high' },
  pctDesc: { label: '% of limit ↓', group: '% of limit, high to low' },
} as const;
export type PickerSort = keyof typeof PICKER_SORTS;

export interface Picker { users: DevUser[]; selected: string; meName: string; sort: PickerSort }

function sortUsers(users: DevUser[], sort: PickerSort): DevUser[] {
  const byName = (a: DevUser, b: DevUser) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' });
  const pctUsed = (u: DevUser) => u.spent_dollars / (u.limit_dollars || 1);
  const cmp: Record<PickerSort, (a: DevUser, b: DevUser) => number> = {
    az: byName,
    za: (a, b) => byName(b, a),
    spendDesc: (a, b) => b.spent_dollars - a.spent_dollars || byName(a, b),
    spendAsc: (a, b) => a.spent_dollars - b.spent_dollars || byName(a, b),
    pctDesc: (a, b) => pctUsed(b) - pctUsed(a) || byName(a, b),
  };
  return [...users].sort(cmp[sort]);
}

/** Dev tools only: switch whose usage is shown. Top spenders first, then everyone in the chosen order. */
function pickerHtml(p: Picker): string {
  const opt = (u: DevUser, sel: boolean) =>
    `<option value="${esc(u.email)}"${sel ? ' selected' : ''}>${esc(u.name)} · ${money(u.spent_dollars)} of ${moneyShort(u.limit_dollars)}` +
    `${p.sort === 'pctDesc' ? ` (${pct(u.spent_dollars / (u.limit_dollars || 1))})` : ''}</option>`;
  const top = sortUsers(p.users, 'spendDesc').slice(0, 10);
  const inTop = top.some(u => u.email === p.selected);
  const sorts = (Object.keys(PICKER_SORTS) as PickerSort[]).map(k =>
    `<option value="${k}"${k === p.sort ? ' selected' : ''}>${PICKER_SORTS[k].label}</option>`).join('');
  return `<div class="dev"><span class="devtag">DEV</span><label for="viewas">View as</label>
    <select id="viewas" data-cmd="viewAs"><option value=""${p.selected ? '' : ' selected'}>Me (${esc(p.meName)})</option>
    <optgroup label="Top spenders this month">${top.map(u => opt(u, u.email === p.selected)).join('')}</optgroup>
    <optgroup label="Everyone (${PICKER_SORTS[p.sort].group})">${sortUsers(p.users, p.sort).map(u => opt(u, !inTop && u.email === p.selected)).join('')}</optgroup></select>
    <label for="viewas-sort" class="muted">Sort everyone</label>
    <select id="viewas-sort" data-cmd="devSort" aria-label="Sort the Everyone list">${sorts}</select>
    <span class="muted">Testing only. Shown because the API runs with DEV_TOOLS=true.</span></div>`;
}

const TOKEN_TYPES: Record<string, { name: string; desc: string }> = {
  input: { name: 'Input', desc: 'New text sent to the model: your message, attached files and tool results that aren\u2019t cached yet.' },
  cache_write: { name: 'Cache writes', desc: 'New context saved so later prompts can reuse it. Not every model charges for it.' },
  cache_read: { name: 'Cache reads', desc: 'The whole chat so far, sent again with every prompt. Cheaper per token than input, but it grows with every prompt.' },
  output: { name: 'Output', desc: 'What the model writes back, including its thinking. Max and xhigh effort write more.' },
};

/** Names up to two models: '`a`', '`a` and `b`'. */
function codeList(names: string[]): string {
  const n = names.slice(0, 2).map(m => `<code>${esc(m)}</code>`);
  return n.join(' and ') + (names.length > 2 ? ' and others' : '');
}

/** Which of the person's models charge for cache writes, from the API's fitted prices. */
function cacheWriteDesc(t: Tokens): string {
  const m = t.cache_write_models;
  if (!m || (!m.charged.length && !m.free.length)) { return TOKEN_TYPES.cache_write.desc; }
  const base = 'New context saved so later prompts can reuse it.';
  const paid = m.charged.length ? ` ${codeList(m.charged)} charge${m.charged.length === 1 ? 's' : ''} for it` : '';
  const free = m.free.length ? `${paid ? ';' : ''} ${codeList(m.free)} ${m.free.length === 1 ? 'doesn\u2019t' : 'don\u2019t'}` : '';
  return `${base}${paid}${free}.`;
}

function vol(m: number): string {
  return m >= 1000 ? `${(m / 1000).toFixed(1)}B` : m >= 10 ? `${Math.round(m)}M` : `${m.toFixed(1)}M`;
}

/** "Where your money goes": tokens and cost by type, the -fast what-if, and how to read it. */
function tokensHtml(s: Summary, mark: (key: string) => { no: string; attr: string }): string {
  const t: Tokens | undefined = s.tokens;
  if (!t || t.total_dollars <= 0) { return ''; }
  const rows = t.rows.filter(r => r.tokens_m > 0 || r.dollars > 0);
  const share = (v: number, of: number) => of ? v / of : 0;
  const bar = (key: 'tokens_m' | 'dollars', of: number, label: string) =>
    `<div class="tok-bar" role="img" aria-label="${esc(label)}: ${rows.map(r => `${TOKEN_TYPES[r.type].name} ${pct(share(r[key], of))}`).join(', ')}">` +
    rows.map(r => `<i class="k-${r.type}" style="width:${(share(r[key], of) * 100).toFixed(2)}%"></i>`).join('') +
    (key === 'dollars' && t.other_dollars > 0 ? `<i class="k-other" style="width:${(share(t.other_dollars, of) * 100).toFixed(2)}%"></i>` : '') + '</div>';
  const cr = mark('row:cache_read');
  const body = rows.map(r => {
    const k = r.type === 'cache_read' ? cr : { no: '', attr: '' };
    return `<tr${k.no ? ' class="hl-warn"' : ''}${k.attr}><td style="white-space:nowrap">${k.no}<span class="sw k-${r.type}"></span>${TOKEN_TYPES[r.type].name}</td>
      <td class="desc">${r.type === 'cache_write' ? cacheWriteDesc(t) : TOKEN_TYPES[r.type].desc}</td><td class="r tnum">${vol(r.tokens_m)}</td>
      <td class="r tnum">${r.rate_per_m === null ? '–' : `$${r.rate_per_m.toFixed(2)}/M`}</td>
      <td class="r tnum"><strong>${money(r.dollars)}</strong></td><td class="r tnum">${pct(share(r.dollars, t.total_dollars))}</td></tr>`;
  }).join('') + (t.other_dollars > 0 ? `<tr><td style="white-space:nowrap"><span class="sw k-other"></span>Other</td>
      <td class="desc">Charges that come without token counts, such as usage corrections.</td><td class="r">–</td><td class="r">–</td>
      <td class="r tnum"><strong>${money(t.other_dollars)}</strong></td><td class="r tnum">${pct(share(t.other_dollars, t.total_dollars))}</td></tr>` : '');

  const w = t.fast_what_if;
  const fm = mark('whatif:fast');
  const whatIf = w ? `<div class="whatif"${fm.attr}><span>${fm.no}Same tokens on ${w.from_model
      ? `<code>${esc(w.to_model)}</code> instead of <code>${esc(w.from_model)}</code>` : 'the normal-speed versions of your <code>-fast</code> models'}</span>
      <span><strong class="tnum">${money(w.normal_dollars)}</strong> <span class="muted">instead of ${money(w.actual_dollars)}</span></span>
      <span class="save">${money(w.saving_dollars)} less ${s.is_current_month ? 'this month' : `in ${esc(periodName(s))}`}</span></div>` : '';

  const crRow = t.rows.find(r => r.type === 'cache_read');
  const crTok = crRow ? share(crRow.tokens_m, t.total_tokens_m) : 0;
  const crCost = crRow ? share(crRow.dollars, t.total_dollars) : 0;
  const head = crTok >= 0.5
    ? `${pct(crTok)} of your tokens are your chats re-reading themselves, and they're ${pct(crCost)} of your cost`
    : 'How to read this';
  const chat = s.top_chats[0];
  const example = chat && chat.prompts_total >= 10
    ? ` Prompt ${chat.prompts_total} in your chat from ${esc(dateTime(chat.started))} re-sent everything from the ${chat.prompts_total - 1} prompts before it.` : '';
  const tipNo = (key: string) => mark(key).no;
  const ex = w?.example;
  const priced = ex && ex.fast_cache_read !== null && ex.normal_cache_read !== null && ex.normal_cache_read > 0;
  const ratio = priced ? Math.round(ex!.fast_cache_read! / ex!.normal_cache_read! * 2) / 2 : 2;
  const fastLine = priced
    ? ` Cache reads are $${ex!.fast_cache_read!.toFixed(2)}/M on <code>${esc(ex!.fast_model)}</code> and $${ex!.normal_cache_read!.toFixed(2)}/M on <code>${esc(ex!.normal_model)}</code>.` : '';
  const times = ratio === 2 ? 'about twice as much' : `about ${ratio}× as much`;
  const read = `<div class="read">
      <h5>${esc(head)}</h5>
      <p>Every prompt sends the whole chat so far back to the model, and those tokens are billed as cache reads. Each one is cheap, but they add up.${example} This row grows with how long your chats run, not with how much new work you ask for.</p>
      <ul>
        <li>${tipNo('row:cache_read')}<strong>Shrink this row.</strong> In a long chat on the same task, type <code>/summarize</code>. Later prompts then re-send the summary instead of every earlier prompt. For a new task, start a new chat, and type <code>@</code> and choose <b>Chats</b> if you need the old one.</li>
        <li>Do it at about ${s.coach?.long_chat_prompts ?? 20} prompts. The context ring next to the chat input shows how full the chat is. Cursor only summarizes on its own when the chat is close to full, and by then each prompt re-sends hundreds of thousands of tokens.</li>
        <li>${tipNo('whatif:fast')}<strong>Lower the rate.</strong> ${priced ? `Every row costs ${times} on <code>${esc(ex!.fast_model)}</code> as on the normal version.` : 'Every row costs about twice as much on <code>-fast</code> models.'}${fastLine}</li>
        <li>A large output share points to effort, not chat length. Max and xhigh write more thinking for each answer.</li>
      </ul>
      <span class="src">Your rate is the average across the models you used, worked out from what ${esc(orgName(s))} was charged, including any per-token fee Cursor adds. The cost column adds up to your actual spend; free prompts aren't counted.</span>
    </div>`;
  return `<div class="sec"><h4>Where your money goes <small>by token type · ${esc(periodName(s))}</small></h4>
    <div class="tok-mix"><span class="muted">Tokens</span>${bar('tokens_m', t.total_tokens_m, 'Share of tokens')}<span class="muted">Cost</span>${bar('dollars', t.total_dollars, 'Share of cost')}</div>
    <div class="tbl"><table><thead><tr><th>Token type</th><th>What it is</th><th class="r">Tokens</th><th class="r">Your rate</th><th class="r">Cost</th><th class="r">Of month</th></tr></thead>
    <tbody>${body}<tr class="total"><td>Total</td><td></td><td class="r tnum">${vol(t.total_tokens_m)}</td><td></td><td class="r tnum">${money(t.total_dollars)}</td><td class="r tnum">100%</td></tr></tbody></table></div>
    ${whatIf}${read}</div>`;
}

export function breakdownHtml(s: Summary, viewAs: string, canGoNext: boolean, nonce: string, csp: string, picker?: Picker, focusTip?: number): string {
  // tip numbers go on the chat or model each tip is about; "See in breakdown" scrolls to the first one
  const marks = new Map<string, number>();
  (s.coach?.tips ?? []).forEach((t, i) => {
    t.target?.ids.forEach(id => { const k = `${t.target!.kind}:${id}`; if (!marks.has(k)) { marks.set(k, i + 1); } });
    if (t.id === 'big_context' && !marks.has('prompt:top')) { marks.set('prompt:top', i + 1); }
    if ((t.id === 'long_chat' || t.id === 'big_context') && !marks.has('row:cache_read')) { marks.set('row:cache_read', i + 1); }
    if (t.id === 'fast') { marks.set('whatif:fast', i + 1); }
  });
  const focused = new Set<number>();
  const mark = (key: string) => {
    const n = marks.get(key);
    if (!n) { return { no: '', attr: '' }; }
    const attr = n === focusTip && !focused.has(n) ? ' data-focus' : '';
    if (attr) { focused.add(n); }
    return { no: `<span class="tipno" title="Tip ${n} in the sidebar">${n}</span>`, attr };
  };
  const reachVal = s.reached_limit_on ? day(s.reached_limit_on)
    : s.projected_reach_limit_date ? `~${day(s.projected_reach_limit_date)}` : 'Not this month';
  const reachSub = s.reached_limit_on ? 'limit reached' : s.is_current_month
    ? `${Math.max(0, Math.ceil(s.days_in_month - s.days_elapsed))} days left in month` : 'month is over';
  const projCls = s.status === 'over_pace' || s.status === 'over_limit' ? 'crit' : s.status === 'watch' ? 'warn' : '';
  const maxModel = s.by_model[0]?.dollars || 1;
  const models = s.by_model.slice(0, 8).map(m => { const k = mark(`model:${m.model}`); return `<div class="bar"${k.attr}><span class="mono" title="${esc(m.model)}">${k.no}${esc(m.model)}</span>
    <span class="tnum">${money(m.dollars)} · ${pct(m.share)}</span><div class="track"><i style="width:${(m.dollars / maxModel * 100).toFixed(1)}%"></i></div></div>`; }).join('');
  const chats = s.top_chats.map(c => { const k = mark(`chat:${c.conversation_id}`); return `<tr${k.no ? ' class="hl"' : ''}${k.attr}><td>${k.no}${esc(dateTime(c.started))}</td><td>${openFor(c.open_days)}</td>
    <td class="tnum">${c.prompts_this_month}${c.prompts_total !== c.prompts_this_month ? ` <span class="muted">(${c.prompts_total} total)</span>` : ''}</td>
    <td class="mono">${c.models.map(esc).join(', ')}</td><td class="r tnum"><strong>${money(c.dollars)}</strong></td><td class="r tnum">${pct(c.share)}</td></tr>`; }).join('');
  const tp = mark('prompt:top');
  const perPrompt = s.cost_per_prompt_7d === null ? '–' : money(s.cost_per_prompt_7d);
  const body = `<main>
  ${picker ? pickerHtml(picker) : viewingAs(s, viewAs)}
  <div class="head">
    <div style="display:grid;gap:2px"><h2>${esc(periodName(s))} usage</h2>
      <span class="muted">Updated ${ago(s.last_sync_at)}${s.data_through ? ` · data through ${esc(dateTime(s.data_through))}` : ''}</span></div>
    <div class="nav"><button data-cmd="month" data-arg="-1" aria-label="Previous month">‹ Previous</button>
      ${canGoNext ? '<button data-cmd="month" data-arg="1" aria-label="Next month">Next ›</button>'
                  : '<button disabled aria-label="Next month (this is the current month)" title="This is the current month">Next ›</button>'}
      <button data-cmd="refresh">Refresh</button></div>
  </div>
  <div class="stats">
    <div><span class="lbl">Spent</span><span class="val tnum">${money(s.spent_dollars)}</span><span class="muted">of ${moneyShort(s.limit_dollars)} · ${pct(s.spent_dollars / s.limit_dollars)}</span></div>
    <div><span class="lbl">${s.is_current_month ? 'Projected' : 'Month total'}</span><span class="val tnum ${projCls}">${money(s.projected_dollars)}</span><span class="muted">${s.is_current_month ? 'if this pace continues' : 'final'}</span></div>
    <div><span class="lbl">Reaches limit</span><span class="val">${reachVal}</span><span class="muted">${reachSub}</span></div>
    <div><span class="lbl">Per prompt (7 days)</span><span class="val tnum">${perPrompt}</span><span class="muted">${s.team_median_cost_per_prompt_7d !== null ? `team median ${money(s.team_median_cost_per_prompt_7d)}` : ''}</span></div>
  </div>
  <div class="grid2">
    <div class="sec"><h4>Spend so far ${s.is_current_month ? '<small>dashed = projection</small>' : ''}</h4>${chartSvg(s)}</div>
    <div class="sec"><h4>By model <small>${s.prompts} prompts</small></h4><div class="bars">${models || '<span class="muted">No usage yet.</span>'}</div></div>
  </div>
  <div class="sec"><h4>Most expensive chats</h4>
    ${chats ? `<div class="tbl"><table><thead><tr><th>Chat started</th><th>Open</th><th>Prompts</th><th>Models</th><th class="r">Cost</th><th class="r">Of month</th></tr></thead>
    <tbody>${chats}</tbody></table></div>` : '<span class="muted">No chats this month.</span>'}
    ${s.top_prompt ? `<div class="note"${tp.attr}>${tp.no}Most expensive prompt: <strong>${money(s.top_prompt.dollars)}</strong> on ${esc(dateTime(s.top_prompt.ts))} (${esc(s.top_prompt.model)}). It re-read ${tokens(s.top_prompt.cache_read_tokens)} tokens of history.</div>` : ''}
    <div class="note">Chats are named by when they started; Cursor's usage data doesn't include chat titles. Times are local; days and the month follow your team's Cursor billing cycle, in UTC.</div>
  </div>
  ${tokensHtml(s, mark)}
</main>`;
  return page(body, nonce, csp, BREAKDOWN_CSS);
}

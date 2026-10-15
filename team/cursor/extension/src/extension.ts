import * as vscode from 'vscode';
import { api, ApiError, DevUser, Me, Summary, Tip } from './api';
import { initAuth, provider, signInHint, signOut } from './auth';
import { ago, day, money, moneyShort, pct, periodName, shiftMonth } from './format';
import { breakdownHtml, messageHtml, paceSentence, PICKER_SORTS, PickerSort, sidebarHtml } from './render';

function nonce(): string {
  let s = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) { s += chars.charAt(Math.floor(Math.random() * chars.length)); }
  return s;
}

function needsSignIn(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

/** Latest summary for the current month, shared by every view. */
class UsageStore {
  me?: Me;
  current?: Summary;
  error?: Error;
  lastRefresh = 0;
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  async refresh(interactive = false): Promise<void> {
    try {
      if (!this.me || interactive) {
        this.me = await api.me(interactive);
        if (!this.me.dev_tools && api.viewingAs()) { api.setViewAs(''); }   // picker is off: back to your own usage
      }
      this.current = await api.summary(undefined, interactive);
      this.error = undefined;
    } catch (e) {
      this.error = e instanceof Error ? e : new Error(String(e));
    }
    this.lastRefresh = Date.now();
    this.changed.fire();
  }
}

/* ---------------- status bar ---------------- */

function updateStatusBar(item: vscode.StatusBarItem, store: UsageStore): void {
  const s = store.current;
  if (store.error || !s) {
    item.text = '$(dashboard) Usage';
    item.tooltip = store.error ? `Cursor Usage: ${store.error.message}` : 'Cursor Usage: loading…';
    item.backgroundColor = undefined;
    item.command = needsSignIn(store.error) ? 'cursorUsage.signIn' : 'cursorUsage.refresh';
    item.show();
    return;
  }
  const nTips = s.coach?.tips.length ?? 0;
  item.text = `$(dashboard) ${moneyShort(s.spent_dollars)} / ${moneyShort(s.limit_dollars)}${nTips ? ` · ${nTips} tip${nTips === 1 ? '' : 's'}` : ''}`;
  item.backgroundColor = s.status === 'over_limit' ? new vscode.ThemeColor('statusBarItem.errorBackground')
    : s.status === 'over_pace' ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
  const md = new vscode.MarkdownString(undefined, true);
  md.isTrusted = { enabledCommands: ['cursorUsage.showBreakdown', 'cursorUsage.refresh'] };
  md.appendMarkdown(`**Cursor usage · ${periodName(s)}**${api.viewingAs() ? ` (viewing ${s.email})` : ''}\n\n`);
  md.appendMarkdown(`${money(s.spent_dollars)} of ${moneyShort(s.limit_dollars)} (${pct(s.spent_dollars / s.limit_dollars)})\n\n`);
  md.appendMarkdown(`${paceSentence(s)}\n\n`);
  if (nTips) {
    md.appendMarkdown(`**${nTips} thing${nTips === 1 ? '' : 's'} to change**\n\n`);
    s.coach.tips.forEach((t, i) => md.appendMarkdown(`${i + 1}. ${t.title}\n`));
    md.appendMarkdown('\n');
  } else if (s.top_chats[0]) { md.appendMarkdown(`Biggest cost: one chat, ${money(s.top_chats[0].dollars)} (${pct(s.top_chats[0].share)})\n\n`); }
  md.appendMarkdown(`[Show breakdown](command:cursorUsage.showBreakdown) · [Refresh](command:cursorUsage.refresh) · updated ${ago(s.last_sync_at)}`);
  item.tooltip = md;
  item.command = 'cursorUsage.showBreakdown';
  item.show();
}

/* ---------------- alerts ---------------- */

async function maybeNotify(ctx: vscode.ExtensionContext, s: Summary): Promise<void> {
  const enabled = vscode.workspace.getConfiguration('cursorUsage').get<boolean>('notifications', true);
  if (!enabled || api.viewingAs() || !s.is_current_month) { return; }
  const used = s.spent_dollars / s.limit_dollars;
  const daysLeft = Math.max(0, Math.ceil(s.days_in_month - s.days_elapsed));
  // least to most serious; only the most serious new one is shown
  const levels: [string, boolean, string][] = [
    ['pace', s.status === 'over_pace' && !!s.projected_reach_limit_date,
      `At this pace you'll reach your ${moneyShort(s.limit_dollars)} Cursor limit around ${day(s.projected_reach_limit_date ?? s.month + '-01')}. You've used ${money(s.spent_dollars)} so far.`],
    ['watch', used >= (s.alerts?.watch_share ?? 0.8) && used < 1,
      `You've used ${pct(used)} of your ${moneyShort(s.limit_dollars)} Cursor limit, with ${daysLeft} days left in ${periodName(s)}.`],
    ['limit', used >= 1, `You've reached your ${moneyShort(s.limit_dollars)} Cursor limit for ${periodName(s)}.`],
  ];
  const key = `notified:${s.email}:${s.month}`;
  const shown = ctx.globalState.get<string[]>(key, []);
  const due = levels.filter(([, hit]) => hit);
  const top = due[due.length - 1];
  if (!top || shown.includes(top[0])) { return; }
  await ctx.globalState.update(key, [...new Set([...shown, ...due.map(([k]) => k)])]);
  const pick = await vscode.window.showWarningMessage(top[2], 'Show breakdown');
  if (pick) { await vscode.commands.executeCommand('cursorUsage.showBreakdown'); }
}

/* ---------------- tip actions ---------------- */

const plain = (s: string) => s.replace(/`/g, '');

async function runTipAction(store: UsageStore, arg: string): Promise<void> {
  const [i, j] = arg.split(':').map(Number);
  const tip: Tip | undefined = store.current?.coach?.tips[i];
  const a = tip?.actions[j];
  if (!tip || !a) { return; }
  if (a.cmd === 'copy' && a.text) {
    await vscode.env.clipboard.writeText(a.text);
    vscode.window.showInformationMessage('Restart prompt copied. Paste it into that chat, then start a new chat and paste the summary it gives you.');
  } else if (a.cmd === 'how' && a.text) {
    const extra = a.copy_label && a.copy_text ? [a.copy_label] : [];
    const pick = await vscode.window.showInformationMessage(plain(a.title || tip.title), { modal: true, detail: plain(a.text) }, ...extra);
    if (pick && a.copy_text) {
      await vscode.env.clipboard.writeText(a.copy_text);
      vscode.window.showInformationMessage('Restart prompt copied. Paste it into that chat, then start a new chat and paste the summary it gives you.');
    }
  } else if (a.cmd === 'see') {
    vscode.commands.executeCommand('cursorUsage.showBreakdown', i + 1);
  }
}

/* ---------------- sidebar ---------------- */

class SidebarProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  constructor(private readonly store: UsageStore) {
    store.onDidChange(() => this.render());
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.onDidReceiveMessage(m => {
      if (m.cmd === 'breakdown') { vscode.commands.executeCommand('cursorUsage.showBreakdown'); }
      if (m.cmd === 'refresh') { vscode.commands.executeCommand('cursorUsage.refresh'); }
      if (m.cmd === 'signIn') { vscode.commands.executeCommand('cursorUsage.signIn'); }
      if (m.cmd === 'tip') { runTipAction(this.store, String(m.arg ?? '')); }
    });
    view.onDidChangeVisibility(() => { if (view.visible) { this.render(); } });
    this.render();
  }

  private render(): void {
    if (!this.view) { return; }
    const w = this.view.webview;
    const s = this.store.current;
    const e = this.store.error;
    if (e) {
      w.html = needsSignIn(e)
        ? messageHtml('Sign in to see your usage', signInHint(), [['signIn', 'Sign in']], nonce(), w.cspSource)
        : messageHtml("Couldn't load your usage", e.message, [['refresh', 'Try again']], nonce(), w.cspSource);
    } else if (s) {
      w.html = sidebarHtml(s, api.viewingAs(), nonce(), w.cspSource);
    } else {
      w.html = messageHtml('Loading your usage…', '', [], nonce(), w.cspSource);
    }
  }
}

/* ---------------- breakdown tab ---------------- */

class BreakdownPanel {
  private static panel?: BreakdownPanel;
  private month?: string;   // undefined = current month (kept in sync with the store)

  private static devUsers?: { at: number; users: DevUser[] };

  static show(store: UsageStore, ctx: vscode.ExtensionContext, focusTip?: number): void {
    const extensionUri = ctx.extensionUri;
    const open = BreakdownPanel.panel;
    if (open) {
      open.p.reveal();
      if (focusTip) { open.month = undefined; open.focusTip = focusTip; open.render(); }
      return;
    }
    const p = vscode.window.createWebviewPanel('cursorUsage.breakdown', 'Cursor Usage', vscode.ViewColumn.Active, { enableScripts: true });
    p.iconPath = vscode.Uri.joinPath(extensionUri, 'media', 'gauge.svg');
    BreakdownPanel.panel = new BreakdownPanel(p, store, ctx, focusTip);
  }

  private constructor(private readonly p: vscode.WebviewPanel, private readonly store: UsageStore,
                      private readonly ctx: vscode.ExtensionContext, private focusTip?: number) {
    const sub = store.onDidChange(() => { if (!this.month) { this.render(); } });
    p.onDidDispose(() => { sub.dispose(); BreakdownPanel.panel = undefined; });
    p.webview.onDidReceiveMessage(async m => {
      if (m.cmd === 'refresh') { await store.refresh(); if (this.month) { await this.render(); } }
      if (m.cmd === 'devSort' && store.me?.dev_tools && m.arg in PICKER_SORTS) {
        await this.ctx.globalState.update('devSort', m.arg);
        await this.render();
      }
      if (m.cmd === 'viewAs' && store.me?.dev_tools) {
        api.setViewAs(String(m.arg ?? ''));
        await this.ctx.globalState.update('viewAs', api.viewingAs());
        this.month = undefined;
        await store.refresh();   // status bar, sidebar and this tab all follow
      }
      if (m.cmd === 'month') {
        const cur = store.current?.month;
        const next = shiftMonth(this.month ?? cur ?? new Date().toISOString().slice(0, 7), Number(m.arg));
        this.month = next === cur ? undefined : next;
        await this.render();
      }
    });
    this.render();
  }

  private async picker() {
    const me = this.store.me;
    if (!me?.dev_tools) { return undefined; }
    const cache = BreakdownPanel.devUsers;
    if (!cache || Date.now() - cache.at > 10 * 60_000) {
      try { BreakdownPanel.devUsers = { at: Date.now(), users: await api.devUsers() }; } catch { return undefined; }
    }
    const sort = this.ctx.globalState.get<PickerSort>('devSort', 'az');
    return { users: BreakdownPanel.devUsers!.users, selected: api.viewingAs(), meName: me.name || me.email,
             sort: sort in PICKER_SORTS ? sort : 'az' };
  }

  private async render(): Promise<void> {
    const w = this.p.webview;
    try {
      const s = this.month ? await api.summary(this.month) : this.store.current;
      if (!s) { throw this.store.error ?? new Error('Loading…'); }
      const focus = this.focusTip;
      this.focusTip = undefined;   // scroll to it once
      w.html = breakdownHtml(s, api.viewingAs(), !!this.month, nonce(), w.cspSource, await this.picker(), focus);
    } catch (e) {
      w.html = messageHtml("Couldn't load usage", e instanceof Error ? e.message : String(e), [['refresh', 'Try again']], nonce(), w.cspSource);
    }
  }
}

/* ---------------- admin notices ---------------- */

async function postNotice(store: UsageStore): Promise<void> {
  if (!store.me?.is_admin) { vscode.window.showWarningMessage('Only Cursor admins can post notices.'); return; }
  const text = await vscode.window.showInputBox({
    title: 'Post a notice (1/2)', prompt: 'Shown under "From your Cursor admin" in the sidebar. Use `backticks` for model names.',
    validateInput: v => v.trim().length > 400 ? 'Keep it under 400 characters' : undefined,
  });
  if (!text?.trim()) { return; }
  const who = await vscode.window.showQuickPick(
    [{ label: 'Everyone', target: '*' }, { label: 'One person…', target: '' }], { title: 'Post a notice (2/2): who sees it?' });
  if (!who) { return; }
  let target = who.target;
  if (!target) {
    target = (await vscode.window.showInputBox({ title: 'Their email', placeHolder: `name@${store.me?.email.split('@')[1] ?? 'example.com'}`,
      validateInput: v => /^\S+@\S+$/.test(v.trim()) ? undefined : 'Enter an email address' }))?.trim() ?? '';
    if (!target) { return; }
  }
  try {
    await api.postNotice(text.trim(), target);
    vscode.window.showInformationMessage(`Notice posted for ${target === '*' ? 'everyone' : target}.`);
    await store.refresh();
  } catch (e) {
    vscode.window.showErrorMessage(`Couldn't post the notice: ${e instanceof Error ? e.message : e}`);
  }
}

async function removeNotice(store: UsageStore): Promise<void> {
  if (!store.me?.is_admin) { vscode.window.showWarningMessage('Only Cursor admins can remove notices.'); return; }
  try {
    const all = await api.notices();
    if (!all.length) { vscode.window.showInformationMessage('There are no notices.'); return; }
    const pick = await vscode.window.showQuickPick(all.map(n => ({
      label: n.text, description: `${n.target === '*' ? 'everyone' : n.target} · ${day(n.created_at)}`, id: n.id })),
      { title: 'Remove a notice' });
    if (!pick) { return; }
    await api.deleteNotice(pick.id);
    vscode.window.showInformationMessage('Notice removed.');
    await store.refresh();
  } catch (e) {
    vscode.window.showErrorMessage(`Couldn't remove the notice: ${e instanceof Error ? e.message : e}`);
  }
}

/* ---------------- activation ---------------- */

export function activate(ctx: vscode.ExtensionContext): void {
  initAuth(ctx);
  const store = new UsageStore();
  const item = vscode.window.createStatusBarItem('cursorUsage.status', vscode.StatusBarAlignment.Right, 100);
  item.name = 'Cursor Usage';

  ctx.subscriptions.push(
    item,
    store.onDidChange(() => {
      updateStatusBar(item, store);
      if (store.current && !store.error) { maybeNotify(ctx, store.current); }
    }),
    vscode.window.registerWebviewViewProvider('cursorUsage.sidebar', new SidebarProvider(store)),
    vscode.commands.registerCommand('cursorUsage.showBreakdown', (tip?: number) =>
      BreakdownPanel.show(store, ctx, typeof tip === 'number' ? tip : undefined)),
    vscode.commands.registerCommand('cursorUsage.postNotice', () => postNotice(store)),
    vscode.commands.registerCommand('cursorUsage.removeNotice', () => removeNotice(store)),
    vscode.commands.registerCommand('cursorUsage.refresh', () => store.refresh()),
    vscode.commands.registerCommand('cursorUsage.signIn', () => store.refresh(true)),
    vscode.commands.registerCommand('cursorUsage.signOut', async () => {
      await signOut();
      if (provider() === 'microsoft') {
        vscode.window.showInformationMessage('To sign out of Microsoft, use the Accounts menu at the bottom of the activity bar.');
      }
      store.refresh();
    }),
    vscode.commands.registerCommand('cursorUsage.openSidebar', () => vscode.commands.executeCommand('workbench.view.extension.cursorUsage')),
  );

  let timer: NodeJS.Timeout | undefined;
  const schedule = () => {
    if (timer) { clearInterval(timer); }
    const minutes = Math.max(2, vscode.workspace.getConfiguration('cursorUsage').get<number>('refreshMinutes', 10));
    timer = setInterval(() => store.refresh(), minutes * 60_000);
  };
  schedule();
  ctx.subscriptions.push(
    { dispose: () => timer && clearInterval(timer) },
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('cursorUsage')) { schedule(); store.refresh(); }
    }),
    // catch up when you come back to the window after a while
    vscode.window.onDidChangeWindowState(st => {
      if (st.focused && Date.now() - store.lastRefresh > 2 * 60_000) { store.refresh(); }
    }),
  );

  api.setViewAs(ctx.globalState.get<string>('viewAs', ''));   // dropped on refresh unless dev tools are on
  updateStatusBar(item, store);
  store.refresh();
}

export function deactivate(): void { /* subscriptions are disposed by VS Code */ }

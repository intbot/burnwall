import * as vscode from "vscode";

import { cliAvailable, runStatusJson } from "./cli";
import { StatusJson, statusBarText, summarize, tooltip } from "./format";

const INSTALL_URL = "https://github.com/intbot/burnwall#install";

let item: vscode.StatusBarItem;
let timer: ReturnType<typeof setInterval> | undefined;

export function activate(context: vscode.ExtensionContext): void {
  item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  item.command = "burnwall.showBreakdown";
  context.subscriptions.push(item);

  context.subscriptions.push(
    vscode.commands.registerCommand("burnwall.refresh", refresh),
    vscode.commands.registerCommand("burnwall.showBreakdown", showBreakdown),
    vscode.commands.registerCommand("burnwall.install", () =>
      vscode.env.openExternal(vscode.Uri.parse(INSTALL_URL)),
    ),
  );

  void refresh();
  startTimer(context);
  item.show();
}

function config() {
  return vscode.workspace.getConfiguration("burnwall");
}

function cliPath(): string {
  return config().get<string>("cliPath", "burnwall");
}

function startTimer(context: vscode.ExtensionContext): void {
  const seconds = Math.max(5, config().get<number>("refreshSeconds", 30));
  timer = setInterval(() => void refresh(), seconds * 1000);
  context.subscriptions.push({ dispose: () => timer && clearInterval(timer) });
}

async function refresh(): Promise<void> {
  const path = cliPath();
  if (!(await cliAvailable(path))) {
    item.text = "$(flame) Burnwall: install CLI";
    item.tooltip = "The burnwall CLI was not found. Click to see install instructions.";
    item.command = "burnwall.install";
    return;
  }
  try {
    const json = JSON.parse(await runStatusJson(path)) as StatusJson;
    const summary = summarize(json);
    item.text = statusBarText(summary);
    item.tooltip = tooltip(summary);
    item.command = "burnwall.showBreakdown";
  } catch (err) {
    item.text = "$(flame) Burnwall: error";
    item.tooltip = `Failed to read burnwall status: ${err}`;
    item.command = "burnwall.refresh";
  }
}

function showBreakdown(): void {
  // Open the full table in a terminal — the CLI already renders it nicely.
  const terminal = vscode.window.createTerminal("Burnwall");
  terminal.show();
  terminal.sendText(`${cliPath()} status`);
}

export function deactivate(): void {
  if (timer) {
    clearInterval(timer);
  }
}

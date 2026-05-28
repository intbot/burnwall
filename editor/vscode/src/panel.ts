// Inline "Burnwall" panel (v0.9.1): a webview surfacing the window digest
// (cost by model, security blocks, MCP tools) + today's status, built from the
// local CLI JSON. The pure HTML builder lives in panel_view.ts (testable);
// this module is the `vscode`-dependent wiring.

import * as vscode from "vscode";

import { runJson } from "./cli";
import { Digest, panelHtml, Status } from "./panel_view";

async function safeJson<T>(cliPath: string, args: string[]): Promise<T> {
  try {
    return JSON.parse(await runJson(cliPath, args)) as T;
  } catch {
    return {} as T;
  }
}

export async function showPanel(cliPath: string): Promise<void> {
  const [digest, status] = await Promise.all([
    safeJson<Digest>(cliPath, ["digest", "--json"]),
    safeJson<Status>(cliPath, ["status", "--json"]),
  ]);
  const panel = vscode.window.createWebviewPanel(
    "burnwall",
    "Burnwall",
    vscode.ViewColumn.Active,
    { enableScripts: false },
  );
  panel.webview.html = panelHtml(digest, status);
}

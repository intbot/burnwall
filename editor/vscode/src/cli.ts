// Thin wrapper around the burnwall CLI. The extension shells out to the same
// binary the user runs, rather than reading the SQLite DB directly — so there
// is no native dependency to bundle and the schema stays owned by the CLI.

import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

/** Run `burnwall status --json` and return its stdout. */
export async function runStatusJson(cliPath: string): Promise<string> {
  return runJson(cliPath, ["status", "--json"]);
}

/** Run `burnwall <args>` and return its stdout (args should include `--json`). */
export async function runJson(cliPath: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync(cliPath, args, {
    timeout: 10_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  return stdout;
}

/** True if the CLI is runnable at `cliPath` (probes `--version`). */
export async function cliAvailable(cliPath: string): Promise<boolean> {
  try {
    await execFileAsync(cliPath, ["--version"], { timeout: 5_000 });
    return true;
  } catch {
    return false;
  }
}

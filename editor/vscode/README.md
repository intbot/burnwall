# Burnwall for VS Code

Shows today's AI spend, cache hit rate, and blocked-request count in the status
bar — for Cursor, Windsurf, and VSCodium too. It reads your local
[Burnwall](https://github.com/intbot/burnwall) CLI; no data leaves your machine.

## How it works

The extension shells out to the `burnwall` CLI (`burnwall status --json`) on a
timer and renders a compact status-bar item:

```
$(flame) $3.47  ·  cache 62%  ·  $(shield) 2
```

Click it to open the full `burnwall status` table in a terminal. If the CLI
isn't installed, the item links to the install instructions.

## Settings

- `burnwall.cliPath` — path to the `burnwall` binary (default: `burnwall`, i.e. on PATH).
- `burnwall.refreshSeconds` — status-bar refresh interval (default: 30).

## Develop

```
npm install
npm run compile   # tsc -> out/
npm test          # node --test on the pure format logic
```

The status-bar parsing/formatting lives in `src/format.ts` with no `vscode`
dependency, so it is unit-tested under plain Node. The extension-host glue
(`src/extension.ts`) requires a VS Code instance to exercise interactively.

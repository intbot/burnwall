# Listing the Burnwall MCP firewall

Burnwall's MCP firewall (`burnwall mcp-watch`) is a local pass-through proxy that
sits in front of your MCP servers: it detects tool-poisoning and silent
"rug-pull" definition changes, enforces an approval workflow, and applies the
path/command/secret denylist to `tools/call` arguments — all locally, never
modifying responses.

## Run it

```
burnwall mcp-watch --upstream <your-mcp-server-url> [--port 4101] [--require-approval]
```

Point your MCP client at the watcher's local address instead of the upstream
directly. Multiple servers can be fronted via `[[mcp.servers]]` in
`~/.burnwall/config.toml`; auto-approve/deny globs go under `[mcp]` (run
`burnwall config show` to see the current MCP section).

## Registry manifest

`packaging/mcp/server.json` is the [MCP registry](https://registry.modelcontextprotocol.io/)
manifest. To publish, install the registry CLI and run `mcp-publisher` from this
repo against `packaging/mcp/server.json` (per the registry's current docs). The
firewall is a security/observability proxy, not a tool server — the manifest
points users at the `burnwall mcp-watch` invocation above.

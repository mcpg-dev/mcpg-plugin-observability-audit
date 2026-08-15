# Audit Log — `dev.mcpg.audit`

> class `tool_gate` · `native` · package `mcpg-plugin-observability-audit` · artifact `libmcpg_plugin_observability_audit.so` · Apache-2.0

Append-only, per-request audit trail for an MCP gateway. The plugin sits in the
tool-gate chain and writes one structured JSON record for every tool call —
caller identity, tool, surface, transport, argument digest, result summary,
timing, and a monotonic sequence number — to stdout or an append-only file. It
never denies a request: it always returns `Allow` and emits records as a side
effect, so a slow or broken sink degrades logging rather than traffic. Reach for
it when you need a forensic or compliance record of who called what, and the
gateway's own log stream is too lossy or too chatty to serve as evidence.

## What it does
- Emits a `pre_dispatch` record before the tool runs and a `post_dispatch`
  record after it returns, correlated by `request_id` and ordered by an
  incrementing `sequence`.
- Always returns `Allow` — the gate exists to observe, never to block.
- Hands records to a bounded channel drained by a dedicated writer thread, so
  request handling never waits on sink I/O. A full buffer drops the record and
  increments a counter instead of applying back-pressure.
- Captures the caller's `kind`, `trust_level`, `subject_id`, `auth_provider`,
  `issuer`, and the `roles` / `groups` / `scopes` lists.
- Defaults to privacy: raw arguments and raw results stay out of the record; a
  SHA-256 digest of the arguments and a result summary go in instead.
- Copies a backend's `_meta.audit` object onto the record when the tool result
  carries one, so engine-specific context (SQL driver, query reference, and
  similar) lands in the same entry as the call itself.
- Filters by tool name with `*` / `?` glob patterns when auditing every surface
  is more than you want.
- Declares no required capabilities — it opens no sockets and reads no secrets.

## Configuration
Loaded from the flat top-level `plugins:` list. This plugin is a tool gate, not
an audit sink: it is independent of the gateway's `governance.audit.sinks[]`
fan-out, and the two can run side by side.

```yaml
plugins:
  - id: dev.mcpg.audit
    kind: native
    class: tool_gate
    source:
      path: ./plugins/libmcpg_plugin_observability_audit.so
    config:
      sink:
        kind: file                       # stdout (default) | file
        path: /var/log/mcpg/audit.jsonl
      include_arguments: false
      include_arguments_hash: true
      include_results: false
      include_result_summary: true
      include_result_meta: true
      tools_filter: ["orders.*", "admin.*"]
      buffer_size: 8192
```

| Field | Type | Default | Description |
|---|---|---|---|
| `sink` | object | `{kind: stdout}` | Destination. `{kind: stdout}` writes JSON lines to stdout; `{kind: file, path: …}` appends JSON lines to `path`. |
| `include_arguments` | bool | `false` | Write the redacted argument object into each record. |
| `include_arguments_hash` | bool | `true` | Write `arguments_hash` as `sha256:<hex>` over the redacted arguments, serialised to JSON. |
| `include_results` | bool | `false` | Write the redacted tool result into the post-dispatch record. |
| `include_result_summary` | bool | `true` | Write `result_summary` — `is_error`, `content_count`, and the sorted set of content `type` values. |
| `include_result_meta` | bool | `true` | Copy the tool result's `_meta.audit` object onto the record. |
| `tools_filter` | string[] or null | `null` | Glob patterns (`*`, `?`); a call is audited when any pattern matches the tool name. `null` audits everything. |
| `buffer_size` | integer | `8192` | Capacity of the bounded record channel. Clamped to a minimum of 1. |

### Rotation is external
The `file` sink enforces **no size limit** and never rotates `path` itself —
rotate it externally with `logrotate` or an equivalent, and size-cap it there.
The sink opens `path` create-and-append per record, so it picks up a rotated
path on the next record with no reload or signal; that per-record open is the
reason it tolerates rotation, and is deliberately not cached.

The gateway's own built-in sink (`dev.mcpg.builtin.audit.local-file`, configured
under `governance.audit.sinks[]`) is likewise rotated externally. It holds one
long-lived handle for throughput, and follows a rotated path by comparing file
identity at each write batch (Unix; elsewhere it only recreates a path that has
vanished).

`max_size_mb` was accepted but never enforced; it is now **rejected at boot** so
a config that relies on it fails loudly instead of silently growing without
bound.

Unknown fields are rejected on both sink kinds. A `config:` block that is
present but does not parse refuses the plugin at boot rather than silently
reverting to defaults; an absent or empty block yields the defaults above.

## Security
- **Redaction is unconditional.** Every payload the plugin captures — arguments,
  results, and the copied `_meta.audit` object — passes through the same
  credential scrubber before it reaches a sink. Credential-shaped keys
  (`Authorization`, `x-api-key`, `password`, `jwt`, and peers) become
  `[redacted]`, and userinfo embedded in URL-shaped string values is stripped.
- **The digest is computed after redaction**, so `arguments_hash` is stable
  across calls that differ only in their secret material and cannot be used to
  recover a scrubbed value.
- **`_meta.audit` is untrusted input.** It comes from whichever backend served
  the call, so it is scrubbed exactly like an argument payload.
- Turning on `include_arguments` or `include_results` puts request and response
  bodies into the audit stream. Redaction removes credentials, not business
  data — treat the sink as a system of record and secure it accordingly.

## Observability
The plugin records three counters through the `metrics` crate:
`mcpg_audit_events_total` (records offered to the sink),
`mcpg_audit_events_dropped_total` (records lost to a full buffer), and
`mcpg_audit_sink_write_errors_total` (sink write failures). A non-zero drop
counter means `buffer_size` is too small for the call rate, or the sink is too
slow; a dropped record is also logged at `warn`, and a failed sink write at
`warn` with the underlying error. On shutdown the plugin waits up to one second
for the writer to drain.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; naming the feature explicitly keeps the command
unambiguous:

```bash
cargo build -p mcpg-plugin-observability-audit --features cdylib-export --release   # → target/release/libmcpg_plugin_observability_audit.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the loading contract: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Gateway audit configuration: <https://mcpg.dev/docs/security/audit>
- Per-call debug logging rather than an evidence trail: `libs/plugins/observability/call-logger`
- WORM-durable audit storage: `libs/plugins/observability/audit-s3-worm`

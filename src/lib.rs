//! Audit logging ToolGate plugin for MCPG.
//!
//! Emits structured audit events as a side effect of pre/post dispatch.
//! Never blocks requests — records are pushed onto a bounded sync channel
//! whose receiver runs on a dedicated `std::thread` that writes to the
//! configured sink. Always returns `Allow`.
//!
//! Distributed as a `native-cdylib-v1` plugin. The cdylib does not
//! bundle tokio — all I/O is std-sync, which keeps the artefact small
//! and removes the per-plugin runtime setup that the earlier
//! statically-linked build relied on.

mod sinks;

use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::thread::JoinHandle;
use tracing::{debug, warn};

pub use sinks::{AuditSink, FileSink, StdoutSink};

const PLUGIN_ID: &str = "dev.mcpg.audit";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Which sink to write audit events to.
    #[serde(default)]
    pub sink: AuditSinkConfig,
    /// Include raw arguments in audit events. Default: false (privacy).
    #[serde(default)]
    pub include_arguments: bool,
    /// Include SHA-256 hash of arguments. Default: true.
    #[serde(default = "default_true")]
    pub include_arguments_hash: bool,
    /// Include raw results in audit events. Default: false.
    #[serde(default)]
    pub include_results: bool,
    /// Include result summary (type counts, error status). Default: true.
    #[serde(default = "default_true")]
    pub include_result_summary: bool,
    /// Include binding-level `_meta.audit` in the audit event.
    /// Default: true. Binding plugins that want to annotate
    /// audit records with engine-specific context (SQL: `driver`,
    /// `query_ref`; future: HTTP response codes, NATS subject, …)
    /// populate the tool result's `_meta.audit` object. The audit
    /// plugin copies it onto the emitted `AuditEvent.meta` so
    /// downstream SIEM ingestion sees one unified record per call.
    #[serde(default = "default_true")]
    pub include_result_meta: bool,
    /// Tool filter: glob patterns. None = audit all tools.
    #[serde(default)]
    pub tools_filter: Option<Vec<String>>,
    /// Event buffer size. Default: 8192.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_true() -> bool {
    true
}
fn default_buffer_size() -> usize {
    8192
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sink: AuditSinkConfig::default(),
            include_arguments: false,
            include_arguments_hash: true,
            include_results: false,
            include_result_summary: true,
            include_result_meta: true,
            tools_filter: None,
            buffer_size: default_buffer_size(),
        }
    }
}

/// Where the plugin writes audit records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AuditSinkConfig {
    /// JSON-lines to stdout.
    #[default]
    Stdout,
    /// Append-only JSON-lines file. The sink opens `path`
    /// create-and-append per record, enforces no size limit, and never
    /// rotates: rotation is external (`logrotate` or equivalent), and
    /// the per-record open is what lets writes follow it.
    File { path: String },
}

/// Sink options that are refused rather than ignored, each with the
/// reason an operator needs to act on it.
///
/// A knob that parses but does nothing is worse than one that does not
/// parse — `max_size_mb` read as a working size cap for as long as it
/// was accepted. Retiring a key therefore means rejecting it loudly,
/// not dropping it.
const REJECTED_SINK_KEYS: &[(&str, &str)] = &[(
    "max_size_mb",
    "the file sink does not enforce a size limit and never rotates `path`; \
     rotation is external (`logrotate` or equivalent). Remove the key and \
     size-cap the file through the rotation tool instead",
)];

impl<'de> Deserialize<'de> for AuditSinkConfig {
    /// Hand-written rather than `#[serde(tag = "kind")]` because an
    /// internally-tagged enum silently accepts unknown keys on its unit
    /// variants even under `deny_unknown_fields`, and because a retired
    /// key deserves an error that explains itself instead of a bare
    /// "unknown field".
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Kind {
            Stdout,
            File,
        }

        #[derive(Deserialize)]
        struct Raw {
            kind: Kind,
            #[serde(flatten)]
            rest: serde_json::Map<String, serde_json::Value>,
        }

        let Raw { kind, mut rest } = Raw::deserialize(deserializer)?;

        let sink = match kind {
            Kind::Stdout => Self::Stdout,
            Kind::File => {
                let path = rest
                    .remove("path")
                    .ok_or_else(|| D::Error::missing_field("path"))?;
                let path = path
                    .as_str()
                    .ok_or_else(|| D::Error::custom("audit sink `path` must be a string"))?
                    .to_owned();
                Self::File { path }
            }
        };

        // Retired keys before generic unknowns, so the operator gets the
        // specific explanation when both are present.
        for (key, why) in REJECTED_SINK_KEYS {
            if rest.contains_key(*key) {
                return Err(D::Error::custom(format!(
                    "audit sink option `{key}` is no longer accepted: {why}"
                )));
            }
        }
        if let Some(key) = rest.keys().next() {
            return Err(D::Error::custom(format!(
                "unknown audit sink option `{key}`"
            )));
        }

        Ok(sink)
    }
}

// ---------------------------------------------------------------------------
// Audit Event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub version: &'static str,
    pub timestamp: String,
    pub event_id: String,
    pub phase: &'static str,
    pub request_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub surface: String,
    pub identity: AuditIdentity,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<ResultSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    pub gate_decision: &'static str,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditIdentity {
    pub kind: String,
    pub trust_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultSummary {
    pub is_error: bool,
    pub content_count: usize,
    pub content_types: Vec<String>,
}

impl From<&mcpg_plugin_protocol::PluginIdentity> for AuditIdentity {
    fn from(id: &mcpg_plugin_protocol::PluginIdentity) -> Self {
        Self {
            kind: id.kind.clone(),
            trust_level: id.trust_level.clone(),
            subject_id: id.subject_id.clone(),
            auth_provider: id.auth_provider.clone(),
            issuer: id.issuer.clone(),
            roles: id.roles.clone(),
            groups: id.groups.clone(),
            scopes: id.scopes.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/// Audit logging plugin. Emits structured events as a side effect of
/// pre/post dispatch. Never blocks requests: events are pushed onto a
/// bounded std::sync::mpsc channel; a background thread drains the
/// receiver and writes to the configured sink.
pub struct AuditPlugin {
    manifest: PluginManifest,
    config: AuditConfig,
    sink_tx: SyncSender<AuditEvent>,
    sequence: AtomicU64,
    // Option so `shutdown` can `take()` it and join; wrapped in Mutex
    // because `SyncToolGate::shutdown` takes `&self`.
    writer_handle: Mutex<Option<JoinHandle<()>>>,
}

impl AuditPlugin {
    /// Construct the plugin from a parsed config. Spins up the
    /// background writer thread; shutting down the plugin drops the
    /// sender (closing the channel) and joins the thread.
    pub fn new(config: AuditConfig) -> Self {
        let buffer_size = config.buffer_size.max(1);
        let (tx, rx) = mpsc::sync_channel::<AuditEvent>(buffer_size);

        let sink: Box<dyn AuditSink> = match &config.sink {
            AuditSinkConfig::Stdout => Box::new(StdoutSink),
            AuditSinkConfig::File { path } => Box::new(FileSink::new(path.clone())),
        };

        let handle = std::thread::Builder::new()
            .name("mcpg-audit-writer".into())
            .spawn(move || background_writer(rx, sink))
            .expect("spawn audit writer thread");

        Self {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "Audit Log".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            config,
            sink_tx: tx,
            sequence: AtomicU64::new(0),
            writer_handle: Mutex::new(Some(handle)),
        }
    }

    /// Macro factory: parses the operator config JSON. Fails CLOSED on a
    /// present-but-malformed `config:` block (the factory panics → null
    /// handle → host boot rejection) per the SDK convention; an empty /
    /// absent block still yields `Default`.
    pub fn from_config_json(config_json: &str) -> Self {
        let config: AuditConfig = mcpg_plugin_sdk::fail_closed_config!(config_json, AuditConfig);
        Self::new(config)
    }

    /// Apply redaction semantics to the raw argument payload the
    /// auditor emits when `include_arguments: true`.
    fn redact_for_emission(&self, arguments: &serde_json::Value) -> serde_json::Value {
        redact_credentials_value(arguments)
    }

    fn should_audit(&self, tool_name: &str) -> bool {
        match &self.config.tools_filter {
            None => true,
            Some(patterns) => patterns.iter().any(|p| glob_match(p, tool_name)),
        }
    }

    fn hash_arguments(&self, arguments: &serde_json::Value) -> String {
        let redacted = redact_credentials_value(arguments);
        let canonical = serde_json::to_string(&redacted).unwrap_or_default();
        let hash = Sha256::digest(canonical.as_bytes());
        format!("sha256:{}", hex_encode(&hash))
    }

    fn build_result_summary(&self, result: &serde_json::Value) -> ResultSummary {
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let (content_count, content_types) =
            if let Some(contents) = result.get("content").and_then(|v| v.as_array()) {
                let types: Vec<String> = contents
                    .iter()
                    .filter_map(|c| c.get("type").and_then(|t| t.as_str()).map(|s| s.to_owned()))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                (contents.len(), types)
            } else {
                (0, Vec::new())
            };
        ResultSummary {
            is_error,
            content_count,
            content_types,
        }
    }

    fn emit(&self, event: AuditEvent) {
        if self.sink_tx.try_send(event).is_err() {
            metrics::counter!("mcpg_audit_events_dropped_total").increment(1);
            warn!("audit event buffer full — dropping event");
        }
        metrics::counter!("mcpg_audit_events_total").increment(1);
    }
}

impl SyncToolGate for AuditPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {
        if !self.should_audit(&ctx.tool_name) {
            return GateDecision::allow();
        }

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let event = AuditEvent {
            version: "1.0",
            timestamp: now_iso8601(),
            event_id: uuid::Uuid::now_v7().to_string(),
            phase: "pre_dispatch",
            request_id: ctx.request_id.clone(),
            session_id: ctx.session_id.clone(),
            tool_name: ctx.tool_name.clone(),
            surface: ctx.surface.clone(),
            identity: AuditIdentity::from(&ctx.identity),
            transport: ctx.transport.clone(),
            arguments_hash: if self.config.include_arguments_hash {
                Some(self.hash_arguments(arguments))
            } else {
                None
            },
            arguments: if self.config.include_arguments {
                Some(self.redact_for_emission(arguments))
            } else {
                None
            },
            execution_duration_ms: None,
            result_summary: None,
            result: None,
            meta: None,
            gate_decision: "allow",
            sequence: seq,
        };
        self.emit(event);

        GateDecision::allow()
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        result: &serde_json::Value,
        execution_duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {
        if !self.should_audit(&ctx.tool_name) {
            return GateDecision::allow();
        }

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let event = AuditEvent {
            version: "1.0",
            timestamp: now_iso8601(),
            event_id: uuid::Uuid::now_v7().to_string(),
            phase: "post_dispatch",
            request_id: ctx.request_id.clone(),
            session_id: ctx.session_id.clone(),
            tool_name: ctx.tool_name.clone(),
            surface: ctx.surface.clone(),
            identity: AuditIdentity::from(&ctx.identity),
            transport: ctx.transport.clone(),
            arguments_hash: if self.config.include_arguments_hash {
                Some(self.hash_arguments(arguments))
            } else {
                None
            },
            arguments: if self.config.include_arguments {
                Some(self.redact_for_emission(arguments))
            } else {
                None
            },
            execution_duration_ms: Some(execution_duration_ms),
            result_summary: if self.config.include_result_summary {
                Some(self.build_result_summary(result))
            } else {
                None
            },
            result: if self.config.include_results {
                Some(self.redact_for_emission(result))
            } else {
                None
            },
            meta: if self.config.include_result_meta {
                // Backend-supplied `_meta.audit` is untrusted; scrub it like
                // every other captured field so a buggy/compromised backend
                // can't land secrets/PII in the audit log in cleartext.
                result
                    .get("_meta")
                    .and_then(|m| m.get("audit"))
                    .map(redact_credentials_value)
            } else {
                None
            },
            gate_decision: "allow",
            sequence: seq,
        };
        self.emit(event);

        GateDecision::allow()
    }

    fn shutdown(&self) {
        // Close the channel so the background writer's
        // `recv()`-until-Disconnected loop exits cleanly, then join
        // the thread. `take()` ensures shutdown is idempotent.
        if let Ok(mut slot) = self.writer_handle.lock()
            && let Some(handle) = slot.take()
        {
            // Drop our sender to signal EOF. The plugin struct still
            // holds `sink_tx`, but after shutdown no further evaluate
            // calls can race because the host guarantees shutdown →
            // drop_instance ordering.
            //
            // We can't drop the stored sender from `&self` without
            // interior mutability; the sender on `self.sink_tx` is
            // closed by `drop_instance` when the plugin struct itself
            // drops. Good enough: our mpsc::Receiver sees Disconnected
            // there. We still want to wait for the writer to flush
            // buffered events before that drop completes, which is why
            // we join here rather than in Drop. Poll for at most 1s
            // before giving up.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            std::thread::spawn(move || {
                let _ = handle.join();
            });
            while std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            tracing::info!("audit plugin shutdown drain complete");
        }
    }
}

impl Drop for AuditPlugin {
    fn drop(&mut self) {
        // Channel closes when `sink_tx` drops; the writer thread
        // (if still alive after `shutdown`) exits its loop.
        debug!("audit plugin dropped");
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: AuditPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| AuditPlugin::from_config_json(cfg),
        }
    ],
}

fn background_writer(rx: mpsc::Receiver<AuditEvent>, sink: Box<dyn AuditSink>) {
    for event in rx.iter() {
        if let Err(e) = sink.emit(&event) {
            metrics::counter!("mcpg_audit_sink_write_errors_total").increment(1);
            warn!(error = %e, "audit sink write failed");
        }
    }
    debug!("audit background writer shutting down");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

use mcpg_glob::glob_match;

/// Redact credential-shaped values from an argument/result payload before
/// it is emitted to an audit sink. Delegates to the shared key list and
/// JSON walk in `mcpg-sensitive`, scrubbing URL userinfo from ordinary
/// string leaves via `mcpg-plugin-protocol`, so this and the gateway's
/// notification redactor cannot drift apart.
fn redact_credentials_value(value: &serde_json::Value) -> serde_json::Value {
    mcpg_sensitive::redact::redact_credentials_with(
        value,
        mcpg_plugin_protocol::redact::redact_in_text,
    )
}

fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    format!("{}.{millis:03}Z", chrono_lite_format(secs))
}

fn chrono_lite_format(unix_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86400;
    const DAYS_PER_YEAR: u64 = 365;

    let days = unix_secs / SECS_PER_DAY;
    let time_of_day = unix_secs % SECS_PER_DAY;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap_year(year) {
            366
        } else {
            DAYS_PER_YEAR
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u64;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            month = i as u64 + 1;
            break;
        }
        remaining_days -= dim;
    }
    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}")
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;

    fn test_ctx(tool: &str) -> PluginContext {
        PluginContext {
            request_id: "req-test".to_owned(),
            session_id: Some("sess-test".to_owned()),
            tool_name: tool.to_owned(),
            surface: "tool".to_owned(),
            identity: PluginIdentity {
                kind: "verified".to_owned(),
                trust_level: "verified".to_owned(),
                subject_id: Some("user@test.com".to_owned()),
                auth_provider: Some("okta".to_owned()),
                issuer: Some("https://company.okta.com".to_owned()),
                roles: vec!["admin".to_owned()],
                groups: vec!["engineering".to_owned()],
                scopes: vec!["read".to_owned()],
                attributes: Default::default(),
            },
            transport: "http".to_owned(),
        }
    }

    #[test]
    fn pre_dispatch_emits_event_and_returns_allow() {
        let plugin = AuditPlugin::new(AuditConfig::default());
        let ctx = test_ctx("get_user");
        let result = plugin.evaluate_pre(
            &ctx,
            &serde_json::json!({"q": "test"}),
            None,
            &serde_json::json!({}),
        );
        assert!(result.is_allow());
    }

    #[test]
    fn post_dispatch_emits_event_with_duration() {
        let plugin = AuditPlugin::new(AuditConfig::default());
        let ctx = test_ctx("get_user");
        let tool_result =
            serde_json::json!({"content": [{"type": "text", "text": "ok"}], "isError": false});
        let result = plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &tool_result,
            42,
            &serde_json::json!({}),
        );
        assert!(result.is_allow());
    }

    #[test]
    fn tool_filter_excludes_unmatched() {
        let config = AuditConfig {
            tools_filter: Some(vec!["audit.*".to_owned()]),
            ..Default::default()
        };
        let plugin = AuditPlugin::new(config);
        let ctx = test_ctx("other_tool");
        let result =
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(result.is_allow());
    }

    #[test]
    fn arguments_hashed_not_raw_by_default() {
        let plugin = AuditPlugin::new(AuditConfig::default());
        assert!(plugin.config.include_arguments_hash);
        assert!(!plugin.config.include_arguments);
    }

    #[test]
    fn redaction_strips_bearer_and_sensitive_keys() {
        let input = serde_json::json!({
            "Authorization": "Bearer secrettoken",
            "headers": {
                "x-api-key": "abcd1234",
                "accept": "application/json"
            },
            "params": {
                "password": "hunter2",
                "jwt": "abcdefgh.ijklmnop.qrstuvwx",
                "note": "plain text stays"
            }
        });
        let out = redact_credentials_value(&input);
        assert_eq!(out["Authorization"], "[redacted]");
        assert_eq!(out["headers"]["x-api-key"], "[redacted]");
        assert_eq!(out["headers"]["accept"], "application/json");
        assert_eq!(out["params"]["password"], "[redacted]");
        assert_eq!(out["params"]["jwt"], "[redacted]");
        assert_eq!(out["params"]["note"], "plain text stays");
    }

    #[test]
    fn result_meta_audit_is_redacted_like_other_fields() {
        // The `_meta.audit` copy path must scrub secrets the same way
        // `result`/`arguments` do.
        let meta_audit = serde_json::json!({
            "driver": "postgres",
            "password": "hunter2",
            "Authorization": "Bearer leak",
            "note": "keep"
        });
        let out = redact_credentials_value(&meta_audit);
        assert_eq!(out["password"], "[redacted]");
        assert_eq!(out["Authorization"], "[redacted]");
        assert_eq!(out["driver"], "postgres");
        assert_eq!(out["note"], "keep");
    }

    #[test]
    fn hash_arguments_is_stable_under_redaction() {
        let plugin = AuditPlugin::new(AuditConfig::default());
        let a = serde_json::json!({"Authorization": "Bearer one"});
        let b = serde_json::json!({"Authorization": "Bearer two"});
        assert_eq!(plugin.hash_arguments(&a), plugin.hash_arguments(&b));
    }

    #[test]
    fn result_summary_construction() {
        let plugin = AuditPlugin::new(AuditConfig::default());
        let result = serde_json::json!({
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "image", "data": "..."},
                {"type": "text", "text": "world"},
            ],
            "isError": false
        });
        let summary = plugin.build_result_summary(&result);
        assert!(!summary.is_error);
        assert_eq!(summary.content_count, 3);
        assert!(summary.content_types.contains(&"text".to_owned()));
        assert!(summary.content_types.contains(&"image".to_owned()));
    }

    #[test]
    fn from_config_json_parses_full_config() {
        let json = r#"{"include_arguments":true,"include_arguments_hash":false,"buffer_size":42}"#;
        let plugin = AuditPlugin::from_config_json(json);
        assert!(plugin.config.include_arguments);
        assert!(!plugin.config.include_arguments_hash);
        assert_eq!(plugin.config.buffer_size, 42);
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn from_config_json_fails_closed_on_malformed() {
        // A present-but-unparseable config refuses the plugin rather than
        // silently degrading to defaults (SDK fail-closed convention).
        let _ = AuditPlugin::from_config_json("not json");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn from_config_json_rejects_unknown_key() {
        // A stray / typo'd / renamed config key is a hard parse error
        // (deny_unknown_fields) → fail-closed: the plugin is refused at
        // boot rather than silently ignoring the misconfiguration.
        let json = r#"{"include_argumentss":true}"#; // typo: trailing extra 's'
        let _ = AuditPlugin::from_config_json(json);
    }

    #[test]
    #[should_panic(expected = "`max_size_mb` is no longer accepted")]
    fn from_config_json_rejects_retired_max_size_mb() {
        // The knob parsed and did nothing for as long as it existed;
        // refusing it at boot is the only way an operator relying on it
        // finds out.
        let json =
            r#"{"sink":{"kind":"file","path":"/var/log/mcpg/audit.jsonl","max_size_mb":100}}"#;
        let _ = AuditPlugin::from_config_json(json);
    }

    #[test]
    fn retired_max_size_mb_error_explains_itself() {
        let err = serde_json::from_str::<AuditSinkConfig>(
            r#"{"kind":"file","path":"/x","max_size_mb":100}"#,
        )
        .expect_err("retired key rejected");
        let msg = err.to_string();
        assert!(msg.contains("max_size_mb"), "names the key: {msg}");
        assert!(msg.contains("does not enforce a size limit"), "{msg}");
        assert!(msg.contains("never rotates"), "{msg}");
        assert!(msg.contains("rotation is external"), "{msg}");
    }

    #[test]
    fn sink_config_rejects_unknown_keys_on_both_variants() {
        // The hand-written deserializer exists because an
        // internally-tagged enum ignores extra keys on a unit variant;
        // both variants must reject them.
        for json in [
            r#"{"kind":"stdout","max_size_mb":1}"#,
            r#"{"kind":"stdout","nonsense":1}"#,
            r#"{"kind":"file","path":"/x","nonsense":1}"#,
        ] {
            assert!(
                serde_json::from_str::<AuditSinkConfig>(json).is_err(),
                "must reject: {json}"
            );
        }
    }

    #[test]
    fn sink_config_accepts_the_supported_shapes() {
        assert_eq!(
            serde_json::from_str::<AuditSinkConfig>(r#"{"kind":"stdout"}"#).unwrap(),
            AuditSinkConfig::Stdout
        );
        assert_eq!(
            serde_json::from_str::<AuditSinkConfig>(r#"{"kind":"file","path":"/x"}"#).unwrap(),
            AuditSinkConfig::File {
                path: "/x".to_owned()
            }
        );
        // A file sink without a path is a hard error, not a silent stdout.
        assert!(serde_json::from_str::<AuditSinkConfig>(r#"{"kind":"file"}"#).is_err());
    }

    #[test]
    fn from_config_json_empty_block_uses_defaults() {
        // An empty / absent / unit config block opts out — still Default.
        for empty in ["", "{}", "null"] {
            let plugin = AuditPlugin::from_config_json(empty);
            assert!(plugin.config.include_arguments_hash); // default true
            assert_eq!(plugin.config.buffer_size, default_buffer_size());
            assert!(!plugin.config.include_arguments); // default false
        }
    }
}

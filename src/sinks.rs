//! Audit event sink implementations.
//!
//! Sinks are driven from a dedicated `std::thread::spawn`'d background
//! writer (see the crate root). The writer receives on a
//! `std::sync::mpsc::Receiver<AuditEvent>` and calls `sink.emit(event)`
//! per record — sync so the cdylib carries no tokio runtime.

use std::fs::OpenOptions;
use std::io::Write;

use crate::AuditEvent;

/// Trait for audit event sinks.
pub trait AuditSink: Send + Sync {
    /// Write a single audit event. Called from the background writer
    /// thread; may block on I/O.
    fn emit(&self, event: &AuditEvent) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Stdout Sink
// ---------------------------------------------------------------------------

/// Writes audit events as JSON lines to stdout.
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    fn emit(&self, event: &AuditEvent) -> Result<(), String> {
        let json = serde_json::to_string(event)
            .map_err(|e| format!("failed to serialize audit event: {e}"))?;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{json}").map_err(|e| format!("failed to write to stdout: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// File Sink
// ---------------------------------------------------------------------------

/// Appends audit events as JSON lines to a file.
pub struct FileSink {
    path: String,
}

impl FileSink {
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl AuditSink for FileSink {
    fn emit(&self, event: &AuditEvent) -> Result<(), String> {
        let json = serde_json::to_string(event)
            .map_err(|e| format!("failed to serialize audit event: {e}"))?;
        let line = format!("{json}\n");

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("failed to open audit file '{}': {e}", self.path))?;
        file.write_all(line.as_bytes())
            .map_err(|e| format!("failed to write to audit file: {e}"))?;

        Ok(())
    }
}

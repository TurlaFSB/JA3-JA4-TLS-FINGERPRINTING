// © Pranav Verma | 2026
// engine.rs

//! The engine's resource limits as the operator set them.
//!
//! Like the rules file and alert destinations, these are global flags read
//! once at start-up, so every path that builds a pipeline (a capture file, a
//! live interface, the dashboard, the report) honors them without each
//! function growing three more parameters.

use std::sync::OnceLock;

use clap::Args;
use tlsfp_core::PipelineConfig;

/// Limits that trade memory for how much of a busy network is read.
#[derive(Debug, Clone, Copy, Args)]
pub struct EngineArgs {
    /// Conversations tracked at once. When the table is full the stalest are
    /// shed (and counted). Raise it on a busy link; each costs a few KiB.
    #[arg(
        long,
        global = true,
        env = "TLSFP_MAX_FLOWS",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1_024..=10_000_000),
        default_value_t = PipelineConfig::DEFAULT_MAX_FLOWS as u32
    )]
    pub max_flows: u32,

    /// Seconds a conversation may stay silent before it can be shed.
    #[arg(
        long,
        global = true,
        env = "TLSFP_IDLE_TIMEOUT",
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u32).range(1..=86_400),
        default_value_t = (PipelineConfig::DEFAULT_IDLE_TIMEOUT_NANOS / 1_000_000_000) as u32
    )]
    pub idle_timeout: u32,

    /// Bytes read from the start of each direction of a conversation, in KiB.
    /// A ClientHello or a certificate chain larger than this is clipped (and
    /// counted). Raising it reads fatter certificate chains.
    #[arg(
        long,
        global = true,
        env = "TLSFP_STREAM_LIMIT_KIB",
        value_name = "KIB",
        value_parser = clap::value_parser!(u32).range(4..=65_536),
        default_value_t = (PipelineConfig::DEFAULT_MAX_ASSEMBLED_BYTES / 1024) as u32
    )]
    pub stream_limit_kib: u32,
}

impl EngineArgs {
    fn config(self) -> PipelineConfig {
        PipelineConfig {
            max_flows: self.max_flows as usize,
            idle_timeout_nanos: u64::from(self.idle_timeout) * 1_000_000_000,
            max_assembled_bytes: self.stream_limit_kib as usize * 1024,
            ..PipelineConfig::default()
        }
    }
}

static CONFIG: OnceLock<PipelineConfig> = OnceLock::new();

/// Records the limits for the run. Called once, before any command.
pub fn init(args: EngineArgs) {
    let _ = CONFIG.set(args.config());
}

/// The pipeline configuration for this run: the operator's limits, or the
/// defaults when none were set (as in tests).
pub fn config() -> PipelineConfig {
    CONFIG.get().copied().unwrap_or_default()
}

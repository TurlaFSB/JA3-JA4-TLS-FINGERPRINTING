// © Pranav Verma | 2026
// net.rs

//! The network type lives in the engine crate, where the traffic table also
//! needs it; it is re-exported here so existing paths keep working.

pub use tlsfp_core::net::Network;

//! Briefcase daemon API types and a small client.
//!
//! This crate exists so the daemon, MCP gateway, and CLI share a stable contract.

pub mod client;
pub mod types;

pub use client::{BriefcaseClient, BriefcaseClientError, DaemonEndpoint};
pub use types::*;

/// Default Windows named pipe path used for local IPC.
///
/// We derive this from the daemon auth token to avoid predictable global pipe names on multi-user
/// hosts (prevents trivial pipe hijacking / token phishing).
#[cfg(windows)]
pub fn default_named_pipe_name(auth_token: &str) -> String {
    let digest = briefcase_core::util::sha256_hex(auth_token.as_bytes());
    let short = &digest[..16];
    format!(r"\\.\pipe\briefcased-{short}")
}

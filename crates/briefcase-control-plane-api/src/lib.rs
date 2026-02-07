//! Control plane API types + a small client.
//!
//! This is a reference implementation contract for Phase 11 (enterprise control plane).

pub mod client;
pub mod types;

pub use client::ControlPlaneClient;
pub use types::*;

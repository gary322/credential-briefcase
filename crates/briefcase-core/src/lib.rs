//! Core types shared across the credential briefcase workspace.
//!
//! This crate intentionally avoids pulling in heavy runtime dependencies so it can
//! be shared by the daemon, gateways, and CLIs.

pub mod sensitive;
pub mod tool_manifest;
pub mod types;
pub mod util;

pub use sensitive::Sensitive;
pub use tool_manifest::*;
pub use types::*;

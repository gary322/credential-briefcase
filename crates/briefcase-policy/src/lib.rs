//! Policy engine: authorization and approval gating.
//!
//! For v1, we use Cedar for allow/deny decisions and derive "require approval"
//! by evaluating a stricter secondary action.

mod cedar_engine;

pub use cedar_engine::{
    CedarPolicyEngine, CedarPolicyEngineError, CedarPolicyEngineOptions, ToolPolicyContext,
};

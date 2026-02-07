use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::Context as _;
use briefcase_core::{ApprovalKind, PolicyDecision, ToolCategory, ToolSpec};
use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use thiserror::Error;

/// Additional tool metadata used for policy evaluation.
///
/// The Briefcase derives this from per-tool manifests at runtime so policy can distinguish
/// "high risk writes" (e.g. tools that can touch the filesystem or the network) from purely local
/// writes (e.g. writing to an internal DB table).
#[derive(Debug, Clone, Copy, Default)]
pub struct ToolPolicyContext {
    /// True if the tool is configured with any outbound network egress.
    pub net_access: bool,
    /// True if the tool is configured with any filesystem allowlist.
    pub fs_access: bool,
}

#[derive(Debug, Clone)]
pub struct CedarPolicyEngineOptions {
    /// Cedar policies as a single string.
    pub policy_text: String,
}

impl CedarPolicyEngineOptions {
    pub fn default_policies() -> Self {
        // NOTE: Cedar has only allow/deny. We encode "approval required" and "mobile signer required"
        // by evaluating stricter actions:
        //
        // - `CallWithoutApproval`: if forbidden, an approval record is required.
        // - `CallWithoutSigner`: if forbidden, that approval must be satisfied by a paired mobile signer.
        //
        // If `Call` is permitted but `CallWithoutApproval` is forbidden -> approval required.
        // If `CallWithoutApproval` is forbidden and `CallWithoutSigner` is forbidden -> mobile signer required.
        //
        // Defaults:
        // - allow calling all tools except category=="admin"
        // - allow no-approval calls only for cheap read tools
        // - require mobile signer only for "high risk writes" (write tools with net/fs access)
        Self {
            policy_text: r#"
// Allow calling any non-admin tool.
permit(principal, action == Action::"Call", resource)
when { resource.category != "admin" };

// Forbid all admin tools.
forbid(principal, action == Action::"Call", resource)
when { resource.category == "admin" };

// Allow calls without approval only for cheap read tools.
permit(principal, action == Action::"CallWithoutApproval", resource)
when {
  resource.category == "read" &&
  resource.cost_microusd <= 10000
};

// Allow calls without a mobile signer unless this is a "high risk write"
// (i.e. a write tool with network or filesystem access configured).
permit(principal, action == Action::"CallWithoutSigner", resource)
when {
  !(resource.is_write && (resource.net_access || resource.fs_access))
};
"#
            .to_string(),
        }
    }
}

#[derive(Debug)]
pub struct CedarPolicyEngine {
    authorizer: Authorizer,
    policies: PolicySet,
}

#[derive(Debug, Error)]
pub enum CedarPolicyEngineError {
    #[error("invalid cedar policy: {0}")]
    Policy(Box<cedar_policy::ParseErrors>),
    #[error("cedar evaluation error: {0}")]
    Eval(String),
    #[error("other error: {0}")]
    Other(#[from] anyhow::Error),
}

impl From<cedar_policy::ParseErrors> for CedarPolicyEngineError {
    fn from(value: cedar_policy::ParseErrors) -> Self {
        Self::Policy(Box::new(value))
    }
}

impl CedarPolicyEngine {
    pub fn new(opts: CedarPolicyEngineOptions) -> Result<Self, CedarPolicyEngineError> {
        let policies = PolicySet::from_str(&opts.policy_text)?;
        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
        })
    }

    pub fn decide(
        &self,
        principal: &str,
        tool: &ToolSpec,
        ctx: ToolPolicyContext,
    ) -> Result<PolicyDecision, CedarPolicyEngineError> {
        let entities = Entities::from_entities([tool_entity(tool, ctx)?], None)
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?;

        let principal_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("User")
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
            EntityId::from_str(principal)
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        );
        let resource_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Tool")
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
            EntityId::from_str(&tool.id)
                .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        );

        let ctx = Context::empty();

        let call = make_request(
            principal_uid.clone(),
            resource_uid.clone(),
            "Call",
            ctx.clone(),
        )?;
        let call_decision = self
            .authorizer
            .is_authorized(&call, &self.policies, &entities);
        if call_decision.decision() == cedar_policy::Decision::Deny {
            return Ok(PolicyDecision::Deny {
                reason: "policy denied tool call".to_string(),
            });
        }

        let call_wo_approval = make_request(
            principal_uid.clone(),
            resource_uid.clone(),
            "CallWithoutApproval",
            ctx.clone(),
        )?;
        let wo_decision =
            self.authorizer
                .is_authorized(&call_wo_approval, &self.policies, &entities);

        if wo_decision.decision() == cedar_policy::Decision::Allow {
            return Ok(PolicyDecision::Allow);
        }

        let call_wo_signer = make_request(principal_uid, resource_uid, "CallWithoutSigner", ctx)?;
        let signer_decision =
            self.authorizer
                .is_authorized(&call_wo_signer, &self.policies, &entities);

        let kind = if signer_decision.decision() == cedar_policy::Decision::Allow {
            ApprovalKind::Local
        } else {
            ApprovalKind::MobileSigner
        };

        Ok(PolicyDecision::RequireApproval {
            reason: "tool call requires approval".to_string(),
            kind,
        })
    }
}

fn make_request(
    principal: EntityUid,
    resource: EntityUid,
    action_id: &str,
    ctx: Context,
) -> Result<Request, CedarPolicyEngineError> {
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action")
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        EntityId::from_str(action_id)
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );

    Request::new(principal, action, resource, ctx, None)
        .map_err(|e| CedarPolicyEngineError::Eval(format!("{e}")))
}

fn tool_entity(tool: &ToolSpec, ctx: ToolPolicyContext) -> Result<Entity, CedarPolicyEngineError> {
    // Cedar numeric type is Long. Use micro-USD as integer to avoid floats.
    let cost_microusd: i64 = (tool.cost.estimated_usd * 1_000_000.0).round() as i64;

    let mut attrs = HashMap::new();
    attrs.insert(
        "category".to_string(),
        RestrictedExpression::from_str(&format!("\"{}\"", tool.category.as_str()))
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );
    attrs.insert(
        "cost_microusd".to_string(),
        RestrictedExpression::from_str(&cost_microusd.to_string())
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );
    attrs.insert(
        "is_write".to_string(),
        RestrictedExpression::from_str(if matches!(tool.category, ToolCategory::Write) {
            "true"
        } else {
            "false"
        })
        .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );
    attrs.insert(
        "net_access".to_string(),
        RestrictedExpression::from_str(if ctx.net_access { "true" } else { "false" })
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );
    attrs.insert(
        "fs_access".to_string(),
        RestrictedExpression::from_str(if ctx.fs_access { "true" } else { "false" })
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );

    let uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Tool")
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
        EntityId::from_str(&tool.id)
            .map_err(|e| CedarPolicyEngineError::Other(anyhow::anyhow!("{e}")))?,
    );

    Entity::new(uid, attrs, HashSet::new())
        .with_context(|| format!("build cedar entity for tool {}", tool.id))
        .map_err(CedarPolicyEngineError::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcase_core::{OutputFirewall, ToolCost};

    fn tool(id: &str, category: ToolCategory, cost: f64) -> ToolSpec {
        ToolSpec {
            id: id.to_string(),
            name: id.to_string(),
            description: id.to_string(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: serde_json::json!({"type":"object"}),
            category,
            cost: ToolCost {
                estimated_usd: cost,
            },
            output_firewall: OutputFirewall::allow_all(),
        }
    }

    #[test]
    fn cheap_read_is_allowed_without_approval() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let ctx = ToolPolicyContext::default();
        let d = engine
            .decide("me", &tool("echo", ToolCategory::Read, 0.0), ctx)
            .unwrap();
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn expensive_read_requires_local_approval() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let ctx = ToolPolicyContext::default();
        let d = engine
            .decide("me", &tool("read", ToolCategory::Read, 0.02), ctx)
            .unwrap();
        assert!(matches!(
            d,
            PolicyDecision::RequireApproval {
                kind: ApprovalKind::Local,
                ..
            }
        ));
    }

    #[test]
    fn local_write_requires_local_approval() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let ctx = ToolPolicyContext::default();
        let d = engine
            .decide("me", &tool("write", ToolCategory::Write, 0.0), ctx)
            .unwrap();
        assert!(matches!(
            d,
            PolicyDecision::RequireApproval {
                kind: ApprovalKind::Local,
                ..
            }
        ));
    }

    #[test]
    fn high_risk_write_requires_mobile_signer_approval() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let ctx = ToolPolicyContext {
            net_access: true,
            fs_access: false,
        };
        let d = engine
            .decide("me", &tool("write", ToolCategory::Write, 0.0), ctx)
            .unwrap();
        assert!(matches!(
            d,
            PolicyDecision::RequireApproval {
                kind: ApprovalKind::MobileSigner,
                ..
            }
        ));
    }

    #[test]
    fn admin_is_denied() {
        let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions::default_policies()).unwrap();
        let ctx = ToolPolicyContext::default();
        let d = engine
            .decide("me", &tool("admin", ToolCategory::Admin, 0.0), ctx)
            .unwrap();
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }
}

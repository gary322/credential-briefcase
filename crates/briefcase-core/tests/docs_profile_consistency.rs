#[test]
fn docs_profile_consistency() {
    let profile = include_str!("../../../docs/COMPATIBILITY_PROFILE.md");
    assert!(
        profile.contains(briefcase_core::COMPATIBILITY_PROFILE_VERSION),
        "COMPATIBILITY_PROFILE.md must mention current profile id"
    );
    assert!(
        profile.contains("approvalToken") && profile.contains("ToolCall.approval_token"),
        "COMPATIBILITY_PROFILE.md must describe approval token retry semantics for MCP + daemon API"
    );
    assert!(
        profile.contains("x-briefcase-compatibility-profile"),
        "COMPATIBILITY_PROFILE.md must describe provider profile markers"
    );

    let caps = include_str!("../../../docs/CAPABILITY_TOKENS.md");
    for term in [
        "x-briefcase-compatibility-profile",
        "compatibility_profile",
        "cnf.jkt",
        "x-briefcase-pop-pub",
        "jti",
        "max_calls",
        "scope",
    ] {
        assert!(
            caps.contains(term),
            "CAPABILITY_TOKENS.md missing required term: {term}"
        );
    }

    // Spot-check that the reference gateway implementation still contains the expected wiring
    // referenced by the docs (drift guard).
    let aag = include_str!("../../../apps/agent-access-gateway/src/main.rs");
    for term in [
        "cnf",
        "jti",
        "max_calls",
        "x-briefcase-pop-pub",
        "x-briefcase-compatibility-profile",
    ] {
        assert!(
            aag.contains(term),
            "agent-access-gateway implementation missing expected term: {term}"
        );
    }

    // Ensure daemon OpenAPI includes the profile/diagnostics surfaces required by AACP v1.
    let openapi = include_str!("../../../openapi/briefcased.yaml");
    for path in [
        "/v1/profile",
        "/v1/diagnostics/compat",
        "/v1/diagnostics/security",
    ] {
        assert!(
            openapi.contains(path),
            "openapi/briefcased.yaml missing required path: {path}"
        );
    }
    for schema in [
        "ProfileMode",
        "ProfileResponse",
        "CompatibilityDiagnosticsResponse",
    ] {
        assert!(
            openapi.contains(schema),
            "openapi/briefcased.yaml missing required schema: {schema}"
        );
    }
}

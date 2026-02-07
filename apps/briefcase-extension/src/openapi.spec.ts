import { describe, expect, it } from "vitest";

import type { paths } from "./gen/briefcased";

describe("briefcased OpenAPI types", () => {
  it("includes key daemon endpoints", () => {
    type HasTools = "/v1/tools" extends keyof paths ? true : false;
    type HasCallTool = "/v1/tools/call" extends keyof paths ? true : false;
    type HasApprovals = "/v1/approvals" extends keyof paths ? true : false;
    type HasMcpServers = "/v1/mcp/servers" extends keyof paths ? true : false;
    type HasMcpOauthStart =
      "/v1/mcp/servers/{id}/oauth/start" extends keyof paths ? true : false;
    type HasMcpOauthExchange =
      "/v1/mcp/servers/{id}/oauth/exchange" extends keyof paths ? true : false;
    type HasMcpOauthRevoke =
      "/v1/mcp/servers/{id}/oauth/revoke" extends keyof paths ? true : false;
    type HasProviderOauthRevoke =
      "/v1/providers/{id}/oauth/revoke" extends keyof paths ? true : false;
    type HasSignerPairStart =
      "/v1/signer/pair/start" extends keyof paths ? true : false;
    type HasPolicy = "/v1/policy" extends keyof paths ? true : false;
    type HasPolicyCompile = "/v1/policy/compile" extends keyof paths ? true : false;
    type HasPolicyApply =
      "/v1/policy/proposals/{id}/apply" extends keyof paths ? true : false;
    type HasAiAnomalies = "/v1/ai/anomalies" extends keyof paths ? true : false;
    type HasControlPlane = "/v1/control-plane" extends keyof paths ? true : false;
    type HasControlPlaneEnroll =
      "/v1/control-plane/enroll" extends keyof paths ? true : false;
    type HasControlPlaneSync =
      "/v1/control-plane/sync" extends keyof paths ? true : false;

    const hasTools: HasTools = true;
    const hasCallTool: HasCallTool = true;
    const hasApprovals: HasApprovals = true;
    const hasMcpServers: HasMcpServers = true;
    const hasMcpOauthStart: HasMcpOauthStart = true;
    const hasMcpOauthExchange: HasMcpOauthExchange = true;
    const hasMcpOauthRevoke: HasMcpOauthRevoke = true;
    const hasProviderOauthRevoke: HasProviderOauthRevoke = true;
    const hasSignerPairStart: HasSignerPairStart = true;
    const hasPolicy: HasPolicy = true;
    const hasPolicyCompile: HasPolicyCompile = true;
    const hasPolicyApply: HasPolicyApply = true;
    const hasAiAnomalies: HasAiAnomalies = true;
    const hasControlPlane: HasControlPlane = true;
    const hasControlPlaneEnroll: HasControlPlaneEnroll = true;
    const hasControlPlaneSync: HasControlPlaneSync = true;

    // Runtime assertions are intentionally trivial; this test mainly ensures type generation stays in sync.
    expect(
      hasTools &&
        hasCallTool &&
        hasApprovals &&
        hasMcpServers &&
        hasMcpOauthStart &&
        hasMcpOauthExchange &&
        hasMcpOauthRevoke &&
        hasProviderOauthRevoke &&
        hasSignerPairStart &&
        hasPolicy &&
        hasPolicyCompile &&
        hasPolicyApply &&
        hasAiAnomalies &&
        hasControlPlane &&
        hasControlPlaneEnroll &&
        hasControlPlaneSync,
    ).toBe(true);
  });
});

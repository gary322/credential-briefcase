import { describe, expect, it } from "vitest";

import type { paths } from "./gen/briefcased";

describe("briefcased OpenAPI types", () => {
  it("includes key daemon endpoints", () => {
    type HasTools = "/v1/tools" extends keyof paths ? true : false;
    type HasCallTool = "/v1/tools/call" extends keyof paths ? true : false;
    type HasApprovals = "/v1/approvals" extends keyof paths ? true : false;
    type HasMcpServers = "/v1/mcp/servers" extends keyof paths ? true : false;

    const hasTools: HasTools = true;
    const hasCallTool: HasCallTool = true;
    const hasApprovals: HasApprovals = true;
    const hasMcpServers: HasMcpServers = true;

    // Runtime assertions are intentionally trivial; this test mainly ensures type generation stays in sync.
    expect(hasTools && hasCallTool && hasApprovals && hasMcpServers).toBe(true);
  });
});

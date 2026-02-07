import { expect, test } from "@playwright/test";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";

function contentType(filePath: string): string {
  if (filePath.endsWith(".html")) return "text/html; charset=utf-8";
  if (filePath.endsWith(".css")) return "text/css; charset=utf-8";
  if (filePath.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (filePath.endsWith(".map")) return "application/json; charset=utf-8";
  if (filePath.endsWith(".json")) return "application/json; charset=utf-8";
  return "application/octet-stream";
}

async function startStaticServer(rootDir: string): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const server = http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      const reqPath = decodeURIComponent(u.pathname);
      const rel = (reqPath === "/" ? "popup.html" : reqPath).replace(/^\/+/, "");

      // Prevent path traversal.
      const p = path.join(rootDir, rel);
      const resolved = path.resolve(p);
      const rootResolved = path.resolve(rootDir);
      if (!resolved.startsWith(rootResolved + path.sep)) {
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
        res.end("bad request");
        return;
      }

      const body = await readFile(resolved);
      res.writeHead(200, { "content-type": contentType(resolved) });
      res.end(body);
    } catch {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found");
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("failed to get server address");
  }
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

let baseUrl: string;
let closeServer: (() => Promise<void>) | null = null;

test.beforeAll(async () => {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const rootDir = path.join(__dirname, "..", "extension");
  const started = await startStaticServer(rootDir);
  baseUrl = started.baseUrl;
  closeServer = started.close;
});

test.afterAll(async () => {
  await closeServer?.();
});

test("popup flows: servers/providers/approvals/receipts/budgets", async ({ page }) => {
  await page.addInitScript(() => {
    type McpServerSummary = {
      id: string;
      endpoint_url: string;
      has_oauth_refresh: boolean;
    };
    type ProviderSummary = {
      id: string;
      base_url: string;
      has_oauth_refresh: boolean;
      has_vc: boolean;
      vc_expires_at_rfc3339: string | null;
    };

    const state: {
      servers: McpServerSummary[];
      providers: ProviderSummary[];
      approvals: unknown[];
      anomalies: unknown[];
      receipts: unknown[];
      budgets: { category: string; daily_limit_microusd: number }[];
      control_plane: any;
    } = {
      servers: [
        {
          id: "remote-1",
          endpoint_url: "https://example.invalid/mcp",
          has_oauth_refresh: false,
        },
      ],
      providers: [
        {
          id: "prov-1",
          base_url: "http://127.0.0.1:9099",
          has_oauth_refresh: false,
          has_vc: false,
          vc_expires_at_rfc3339: null,
        },
      ],
      approvals: [
        {
          id: "00000000-0000-0000-0000-000000000000",
          created_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-01-01T00:10:00Z",
          tool_id: "demo.write",
          reason: "requires_approval",
          summary: {
            action: "write",
            cost_microusd: 30,
            copilot_summary: "Approve write tool call: demo.write | reason=requires_approval",
          },
        },
      ],
      anomalies: [
        {
          kind: "output_poisoning",
          severity: "high",
          message: "tool output contained suspicious instruction signals",
          receipt_id: 1,
          ts_rfc3339: "2026-01-01T00:00:00Z",
        },
      ],
      receipts: [
        {
          id: 1,
          ts: "2026-01-01T00:00:00Z",
          prev_hash_hex: "00",
          hash_hex: "11",
          event: { kind: "tool_call", tool_id: "demo.read", ok: true },
        },
      ],
      budgets: [{ category: "default", daily_limit_microusd: 123 }],
      control_plane: { status: "not_enrolled" },
    };

    function ok(result: unknown) {
      return { ok: true, result };
    }

    // Minimal MV3-ish `chrome` shim; popup talks to background via `runtime.sendMessage`.
    (globalThis as any).chrome = {
      runtime: {
        sendMessage: async (msg: any) => {
          if (!msg || typeof msg !== "object") return { ok: false, error: "bad_msg" };

          if (msg.type === "rpc") {
            const method = msg.method;
            const params = msg.params ?? {};

            switch (method) {
              case "control_plane_status":
                return ok(state.control_plane);
              case "control_plane_enroll": {
                const { base_url, device_name } = params;
                state.control_plane = {
                  status: "enrolled",
                  base_url,
                  device_id: "00000000-0000-0000-0000-000000000123",
                  policy_signing_pubkey_b64: "pubkey",
                  last_policy_bundle_id: 1,
                  last_receipt_upload_id: 0,
                  last_sync_at_rfc3339: null,
                  last_error: null,
                  updated_at_rfc3339: "2026-01-01T00:00:00Z",
                  device_name,
                };
                return ok(state.control_plane);
              }
              case "control_plane_sync": {
                if (state.control_plane.status === "not_enrolled") {
                  return ok({ status: "not_enrolled" });
                }
                state.control_plane.last_sync_at_rfc3339 = "2026-01-01T00:00:01Z";
                state.control_plane.last_receipt_upload_id += 1;
                return ok({
                  status: "synced",
                  policy_applied: false,
                  receipts_uploaded: 1,
                });
              }
              case "list_mcp_servers":
                return ok({ servers: state.servers });
              case "upsert_mcp_server": {
                const { server_id, endpoint_url } = params;
                const idx = state.servers.findIndex((s) => s.id === server_id);
                const next = {
                  id: server_id,
                  endpoint_url,
                  has_oauth_refresh: false,
                };
                if (idx >= 0) state.servers[idx] = next;
                else state.servers.push(next);
                return ok(next);
              }
              case "delete_mcp_server": {
                const { server_id } = params;
                state.servers = state.servers.filter((s) => s.id !== server_id);
                return ok({ server_id });
              }
              case "list_providers":
                return ok({ providers: state.providers });
              case "upsert_provider": {
                const { provider_id, base_url } = params;
                const idx = state.providers.findIndex((p) => p.id === provider_id);
                const next = {
                  id: provider_id,
                  base_url,
                  has_oauth_refresh: false,
                  has_vc: false,
                  vc_expires_at_rfc3339: null,
                };
                if (idx >= 0) state.providers[idx] = next;
                else state.providers.push(next);
                return ok(next);
              }
              case "fetch_vc": {
                const { provider_id } = params;
                const p = state.providers.find((x) => x.id === provider_id);
                if (p) {
                  p.has_vc = true;
                  p.vc_expires_at_rfc3339 = "2026-12-31T00:00:00Z";
                }
                return ok({ provider_id });
              }
              case "delete_provider": {
                const { provider_id } = params;
                state.providers = state.providers.filter((p) => p.id !== provider_id);
                return ok({ provider_id });
              }
              case "list_approvals":
                return ok({ approvals: state.approvals });
              case "approve": {
                const { id } = params;
                state.approvals = state.approvals.filter((a: any) => a.id !== id);
                return ok({ id });
              }
              case "ai_anomalies":
                return ok({ anomalies: state.anomalies });
              case "list_receipts": {
                const limit = Number(params.limit ?? 50);
                const offset = Number(params.offset ?? 0);
                const sliced = state.receipts.slice(offset, offset + limit);
                return ok({ receipts: sliced });
              }
              case "verify_receipts":
                return ok({ ok: true });
              case "list_budgets":
                return ok({ budgets: state.budgets });
              case "set_budget": {
                const { category, daily_limit_microusd } = params;
                const idx = state.budgets.findIndex((b) => b.category === category);
                const next = { category, daily_limit_microusd };
                if (idx >= 0) state.budgets[idx] = next;
                else state.budgets.push(next);
                return ok(next);
              }
              default:
                return { ok: false, error: `unknown_method:${method}` };
            }
          }

          if (msg.type === "connect_mcp_oauth") {
            const server_id = msg.server_id;
            const s = state.servers.find((x) => x.id === server_id);
            if (s) s.has_oauth_refresh = true;
            return ok({ servers: state.servers });
          }

          return { ok: false, error: "unknown_request" };
        },
      },
    };
  });

  await page.goto(`${baseUrl}/popup.html`);

  // Default tab: MCP.
  await expect(page.getByText("remote-1")).toBeVisible();

  // Add server.
  await page.getByLabel("Server ID").fill("remote-2");
  await page.getByLabel("Endpoint URL").fill("https://example.invalid/mcp2");
  await page.getByRole("button", { name: "Add Server" }).click();
  await expect(page.getByText("remote-2")).toBeVisible();

  // Connect OAuth (pure stub).
  await page.getByRole("button", { name: "Connect OAuth" }).first().click();
  await expect(page.getByText("OAuth connected.")).toBeVisible();

  // Providers tab.
  await page.getByRole("button", { name: "Providers" }).click();
  await expect(page.getByText("prov-1")).toBeVisible();

  // Fetch VC.
  await page.getByRole("button", { name: "Fetch VC" }).click();
  await expect(page.getByText("VC: yes")).toBeVisible();

  // Approvals tab.
  await page.getByRole("button", { name: "Approvals" }).click();
  await expect(page.getByText("demo.write", { exact: true })).toBeVisible();
  await expect(
    page
      .locator("#approvals div.url")
      .filter({ hasText: "Approve write tool call: demo.write" })
      .first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("No pending approvals.")).toBeVisible();

  // Alerts tab.
  await page.getByRole("button", { name: "Alerts" }).click();
  await expect(
    page.getByText("tool output contained suspicious instruction signals"),
  ).toBeVisible();

  // Enterprise tab.
  await page.getByRole("button", { name: "Enterprise" }).click();
  await expect(page.getByText("Not enrolled.")).toBeVisible();
  await page.getByLabel("Control Plane Base URL").fill("http://127.0.0.1:9999");
  await page.getByLabel("Admin Token").fill("admin-token");
  await page.getByLabel("Device Name").fill("laptop-1");
  await page.getByRole("button", { name: "Enroll" }).click();
  await expect(page.getByText("Enrolled.")).toBeVisible();
  await expect(page.getByText("base_url: http://127.0.0.1:9999")).toBeVisible();
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByText("Sync complete.", { exact: false })).toBeVisible();

  // Receipts tab.
  await page.getByRole("button", { name: "Receipts" }).click();
  await expect(page.getByText("tool_call:demo.read")).toBeVisible();
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText("Receipt chain OK.")).toBeVisible();

  // Budgets tab.
  await page.getByRole("button", { name: "Budgets" }).click();
  await expect(page.locator("#budgets").getByText("default", { exact: true })).toBeVisible();
  await page.getByLabel("Category").fill("research");
  await page.getByLabel("Daily Limit (micro-USD)").fill("999");
  await page.getByRole("button", { name: "Set Budget" }).click();
  await expect(page.getByText("research")).toBeVisible();
});

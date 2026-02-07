import { nativeCall } from "./native";

type PopupRequest =
  | { type: "rpc"; method: string; params?: unknown }
  | { type: "connect_mcp_oauth"; server_id: string; scope?: string };

type PopupResponse =
  | { ok: true; result: unknown }
  | { ok: false; error: string };

const ALLOWED_RPC_METHODS = new Set([
  "health",
  "identity",
  "control_plane_status",
  "control_plane_enroll",
  "control_plane_sync",
  "list_tools",
  "list_providers",
  "upsert_provider",
  "fetch_vc",
  "delete_provider",
  "revoke_provider_oauth",
  "list_mcp_servers",
  "upsert_mcp_server",
  "delete_mcp_server",
  "revoke_mcp_oauth",
  "list_budgets",
  "set_budget",
  "policy_get",
  "policy_compile",
  "policy_apply",
  "list_approvals",
  "approve",
  "list_receipts",
  "verify_receipts",
  "ai_anomalies",
]);

function parseOAuthRedirectUrl(urlStr: string): { code: string; state: string } {
  const u = new URL(urlStr);
  const code = u.searchParams.get("code") || "";
  const state = u.searchParams.get("state") || "";
  if (!code || !state) {
    throw new Error("missing code/state in redirect url");
  }
  return { code, state };
}

async function connectOAuth(server_id: string, scope?: string): Promise<void> {
  const redirect_uri = chrome.identity.getRedirectURL("mcp_oauth_cb");

  const started = await nativeCall<{
    authorization_url: string;
    state: string;
  }>("mcp_oauth_start", {
    server_id,
    client_id: "briefcase-extension",
    redirect_uri,
    scope,
  });

  const redirect = await chrome.identity.launchWebAuthFlow({
    url: started.authorization_url,
    interactive: true,
  });
  if (!redirect) {
    throw new Error("oauth flow canceled");
  }

  const { code, state } = parseOAuthRedirectUrl(redirect);
  if (state !== started.state) {
    throw new Error("oauth state mismatch");
  }

  await nativeCall("mcp_oauth_exchange", { server_id, code, state });
}

chrome.runtime.onMessage.addListener((msg: unknown, sender, sendResponse) => {
  // Only accept messages from our own popup UI. This reduces the blast radius if a
  // content script is ever added in the future.
  const popupUrl = chrome.runtime.getURL("popup.html");
  const senderUrlOk = sender.url ? sender.url.startsWith(popupUrl) : true;
  if (sender.id !== chrome.runtime.id || !senderUrlOk) {
    sendResponse({ ok: false, error: "sender_not_allowed" } satisfies PopupResponse);
    return false;
  }

  const req = msg as PopupRequest;

  (async () => {
    try {
      if (req.type === "rpc") {
        if (!ALLOWED_RPC_METHODS.has(req.method)) {
          sendResponse({ ok: false, error: "method_not_allowed" } satisfies PopupResponse);
          return;
        }
        const result = await nativeCall(req.method, req.params ?? {});
        sendResponse({ ok: true, result } satisfies PopupResponse);
        return;
      }
      if (req.type === "connect_mcp_oauth") {
        await connectOAuth(req.server_id, req.scope);
        const result = await nativeCall("list_mcp_servers", {});
        sendResponse({ ok: true, result } satisfies PopupResponse);
        return;
      }

      sendResponse({ ok: false, error: "unknown_request" } satisfies PopupResponse);
    } catch (e) {
      const msg =
        e instanceof Error ? e.message : typeof e === "string" ? e : "unknown_error";
      sendResponse({ ok: false, error: msg } satisfies PopupResponse);
    }
  })();

  // Keep the message channel open for async response.
  return true;
});

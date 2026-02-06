import { nativeCall } from "./native";

type McpServerSummary = {
  id: string;
  endpoint_url: string;
  has_oauth_refresh: boolean;
};

type ListMcpServersResponse = {
  servers: McpServerSummary[];
};

type PopupRequest =
  | { type: "load" }
  | { type: "add_server"; server_id: string; endpoint_url: string }
  | { type: "connect_oauth"; server_id: string; scope?: string };

type PopupResponse =
  | { ok: true; servers: McpServerSummary[] }
  | { ok: false; error: string };

async function listServers(): Promise<McpServerSummary[]> {
  const res = await nativeCall<ListMcpServersResponse>("list_mcp_servers", {});
  return res.servers;
}

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

chrome.runtime.onMessage.addListener((msg: unknown, _sender, sendResponse) => {
  const req = msg as PopupRequest;

  (async () => {
    try {
      if (req.type === "load") {
        const servers = await listServers();
        sendResponse({ ok: true, servers } satisfies PopupResponse);
        return;
      }
      if (req.type === "add_server") {
        await nativeCall("upsert_mcp_server", {
          server_id: req.server_id,
          endpoint_url: req.endpoint_url,
        });
        const servers = await listServers();
        sendResponse({ ok: true, servers } satisfies PopupResponse);
        return;
      }
      if (req.type === "connect_oauth") {
        await connectOAuth(req.server_id, req.scope);
        const servers = await listServers();
        sendResponse({ ok: true, servers } satisfies PopupResponse);
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


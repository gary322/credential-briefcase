type McpServerSummary = {
  id: string;
  endpoint_url: string;
  has_oauth_refresh: boolean;
};

type PopupResponse =
  | { ok: true; servers: McpServerSummary[] }
  | { ok: false; error: string };

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing element: ${id}`);
  return e as T;
}

function setStatus(text: string): void {
  el<HTMLDivElement>("status").innerText = text;
}

async function send(req: unknown): Promise<PopupResponse> {
  const resp = await chrome.runtime.sendMessage(req);
  return resp as PopupResponse;
}

function renderServers(servers: McpServerSummary[]): void {
  const root = el<HTMLDivElement>("servers");
  root.innerHTML = "";

  if (servers.length === 0) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No servers configured.";
    root.appendChild(p);
    return;
  }

  for (const s of servers) {
    const box = document.createElement("div");
    box.className = "server";

    const top = document.createElement("div");
    top.className = "row";

    const id = document.createElement("div");
    id.className = "id";
    id.innerText = s.id;

    const pill = document.createElement("div");
    pill.className = `pill ${s.has_oauth_refresh ? "ok" : "no"}`;
    pill.innerText = s.has_oauth_refresh ? "OAuth connected" : "No OAuth";

    top.appendChild(id);
    top.appendChild(pill);
    box.appendChild(top);

    const url = document.createElement("div");
    url.className = "url";
    url.innerText = s.endpoint_url;
    box.appendChild(url);

    const actions = document.createElement("div");
    actions.className = "actions";

    const connect = document.createElement("button");
    connect.className = "connect";
    connect.innerText = "Connect OAuth";
    connect.addEventListener("click", async () => {
      setStatus(`Starting OAuth for ${s.id}...`);
      const resp = await send({ type: "connect_oauth", server_id: s.id, scope: "mcp.read" });
      if (!resp.ok) {
        setStatus(`Error: ${resp.error}`);
        return;
      }
      renderServers(resp.servers);
      setStatus("OAuth connected.");
    });

    const refresh = document.createElement("button");
    refresh.className = "refresh";
    refresh.innerText = "Refresh";
    refresh.addEventListener("click", async () => {
      setStatus("Refreshing...");
      const resp = await send({ type: "load" });
      if (!resp.ok) {
        setStatus(`Error: ${resp.error}`);
        return;
      }
      renderServers(resp.servers);
      setStatus("");
    });

    actions.appendChild(connect);
    actions.appendChild(refresh);
    box.appendChild(actions);

    root.appendChild(box);
  }
}

async function main(): Promise<void> {
  setStatus("Connecting to Briefcase...");
  const resp = await send({ type: "load" });
  if (!resp.ok) {
    setStatus(`Error: ${resp.error}`);
    return;
  }
  renderServers(resp.servers);
  setStatus("");

  const form = el<HTMLFormElement>("add-server-form");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const server_id = el<HTMLInputElement>("server-id").value.trim();
    const endpoint_url = el<HTMLInputElement>("endpoint-url").value.trim();
    if (!server_id || !endpoint_url) {
      setStatus("Error: missing server_id or endpoint_url");
      return;
    }

    setStatus("Adding server...");
    const res = await send({ type: "add_server", server_id, endpoint_url });
    if (!res.ok) {
      setStatus(`Error: ${res.error}`);
      return;
    }
    renderServers(res.servers);
    setStatus("Server added.");
  });
}

main().catch((e) => {
  const msg = e instanceof Error ? e.message : "unknown_error";
  setStatus(`Error: ${msg}`);
});


type RpcEnvelope =
  | { ok: true; result: unknown }
  | { ok: false; error: string };

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

type BudgetRecord = {
  category: string;
  daily_limit_microusd: number;
};

type ApprovalKind = "local" | "mobile_signer";

type ApprovalRequest = {
  id: string;
  created_at: string;
  expires_at: string;
  tool_id: string;
  reason: string;
  kind: ApprovalKind;
  summary: unknown;
};

type ReceiptRecord = {
  id: number;
  ts: string;
  prev_hash_hex: string;
  hash_hex: string;
  event: unknown;
};

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing element: ${id}`);
  return e as T;
}

function setStatus(text: string): void {
  el<HTMLDivElement>("status").innerText = text;
}

async function send(msg: unknown): Promise<RpcEnvelope> {
  const resp = await chrome.runtime.sendMessage(msg);
  return resp as RpcEnvelope;
}

async function rpc<T>(method: string, params: unknown = {}): Promise<T> {
  const resp = await send({ type: "rpc", method, params });
  if (!resp.ok) throw new Error(resp.error || "rpc_error");
  return resp.result as T;
}

async function connectMcpOAuth(
  server_id: string,
  scope?: string,
): Promise<{ servers: McpServerSummary[] }> {
  const resp = await send({ type: "connect_mcp_oauth", server_id, scope });
  if (!resp.ok) throw new Error(resp.error || "oauth_error");
  return resp.result as { servers: McpServerSummary[] };
}

function prettyJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function setActiveTab(tab: string): void {
  for (const b of document.querySelectorAll<HTMLButtonElement>("button.tab")) {
    const t = b.dataset.tab || "";
    b.classList.toggle("active", t === tab);
  }
  for (const pane of document.querySelectorAll<HTMLElement>(".tabpane")) {
    const isActive = pane.id === `tab-${tab}`;
    pane.classList.toggle("hidden", !isActive);
  }
}

function mkPill(ok: boolean, okText: string, noText: string): HTMLDivElement {
  const pill = document.createElement("div");
  pill.className = `pill ${ok ? "ok" : "no"}`;
  pill.innerText = ok ? okText : noText;
  return pill;
}

function mkItem(): HTMLDivElement {
  const box = document.createElement("div");
  box.className = "item";
  return box;
}

function mkRowLeftRight(leftText: string, right: HTMLElement): HTMLDivElement {
  const row = document.createElement("div");
  row.className = "row";

  const left = document.createElement("div");
  left.className = "id";
  left.innerText = leftText;

  row.appendChild(left);
  row.appendChild(right);
  return row;
}

async function loadServers(): Promise<void> {
  const res = await rpc<{ servers: McpServerSummary[] }>("list_mcp_servers");
  await loadServersFrom(res.servers);
}

async function loadServersFrom(servers: McpServerSummary[]): Promise<void> {
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
    const box = mkItem();
    box.appendChild(
      mkRowLeftRight(
        s.id,
        mkPill(s.has_oauth_refresh, "OAuth connected", "No OAuth"),
      ),
    );

    const url = document.createElement("div");
    url.className = "url";
    url.innerText = s.endpoint_url;
    box.appendChild(url);

    const actions = document.createElement("div");
    actions.className = "actions";

    const connect = document.createElement("button");
    connect.className = "connect";
    connect.type = "button";
    connect.innerText = "Connect OAuth";
    connect.addEventListener("click", async () => {
      setStatus(`Starting OAuth for ${s.id}...`);
      try {
        const out = await connectMcpOAuth(s.id, "mcp.read");
        await renderAfter(() => loadServersFrom(out.servers));
        setStatus("OAuth connected.");
      } catch (e) {
        setStatus(errorMessage(e));
      }
    });

    const del = document.createElement("button");
    del.className = "refresh";
    del.type = "button";
    del.innerText = "Delete";
    del.addEventListener("click", async () => {
      setStatus(`Deleting server ${s.id}...`);
      try {
        await rpc("delete_mcp_server", { server_id: s.id });
        await renderAfter(loadServers);
        setStatus("Server deleted.");
      } catch (e) {
        setStatus(errorMessage(e));
      }
    });

    actions.appendChild(connect);
    actions.appendChild(del);
    box.appendChild(actions);
    root.appendChild(box);
  }
}

async function loadProviders(): Promise<void> {
  const root = el<HTMLDivElement>("providers");
  root.innerHTML = "";

  const res = await rpc<{ providers: ProviderSummary[] }>("list_providers");
  if (res.providers.length === 0) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No providers configured.";
    root.appendChild(p);
    return;
  }

  for (const p of res.providers) {
    const box = mkItem();
    box.appendChild(mkRowLeftRight(p.id, mkPill(true, "Configured", "Configured")));

    const url = document.createElement("div");
    url.className = "url";
    url.innerText = p.base_url;
    box.appendChild(url);

    const meta = document.createElement("div");
    meta.className = "url";
    const oauth = p.has_oauth_refresh ? "OAuth: yes" : "OAuth: no";
    const vc = p.has_vc
      ? `VC: yes (${p.vc_expires_at_rfc3339 ?? "unknown"})`
      : "VC: no";
    meta.innerText = `${oauth} | ${vc}`;
    box.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "actions";

    const fetchVc = document.createElement("button");
    fetchVc.className = "connect";
    fetchVc.type = "button";
    fetchVc.innerText = "Fetch VC";
    fetchVc.addEventListener("click", async () => {
      setStatus(`Fetching VC for ${p.id}...`);
      try {
        await rpc("fetch_vc", { provider_id: p.id });
        await renderAfter(loadProviders);
        setStatus("VC fetched.");
      } catch (e) {
        setStatus(errorMessage(e));
      }
    });

    const del = document.createElement("button");
    del.className = "refresh";
    del.type = "button";
    del.innerText = "Delete";
    del.addEventListener("click", async () => {
      setStatus(`Deleting provider ${p.id}...`);
      try {
        await rpc("delete_provider", { provider_id: p.id });
        await renderAfter(loadProviders);
        setStatus("Provider deleted.");
      } catch (e) {
        setStatus(errorMessage(e));
      }
    });

    actions.appendChild(fetchVc);
    actions.appendChild(del);
    box.appendChild(actions);

    root.appendChild(box);
  }
}

async function loadApprovals(): Promise<void> {
  const root = el<HTMLDivElement>("approvals");
  root.innerHTML = "";

  const res = await rpc<{ approvals: ApprovalRequest[] }>("list_approvals");
  if (res.approvals.length === 0) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No pending approvals.";
    root.appendChild(p);
    return;
  }

  for (const a of res.approvals) {
    const box = mkItem();
    box.appendChild(mkRowLeftRight(a.tool_id, mkPill(false, "", a.reason)));

    const detail = document.createElement("div");
    detail.className = "url";
    detail.innerText = `kind: ${a.kind} | expires: ${a.expires_at}`;
    box.appendChild(detail);

    const pre = document.createElement("pre");
    pre.className = "url";
    pre.innerText = prettyJson(a.summary);
    box.appendChild(pre);

    const actions = document.createElement("div");
    actions.className = "actions";

    const approve = document.createElement("button");
    approve.className = "connect";
    approve.type = "button";
    const needsSigner = a.kind === "mobile_signer";
    approve.innerText = needsSigner ? "Mobile signer required" : "Approve";
    approve.disabled = needsSigner;
    if (needsSigner) {
      approve.title = "Approve this request from the paired mobile signer app.";
    } else {
      approve.addEventListener("click", async () => {
        setStatus(`Approving ${a.id}...`);
        try {
          await rpc("approve", { id: a.id });
          await renderAfter(loadApprovals);
          setStatus("Approved. Retry the tool call with approval_token=approval_id.");
        } catch (e) {
          setStatus(errorMessage(e));
        }
      });
    }

    actions.appendChild(approve);
    box.appendChild(actions);

    root.appendChild(box);
  }
}

function receiptTitle(r: ReceiptRecord): string {
  if (!r.event || typeof r.event !== "object") return `receipt:${r.id}`;
  const e = r.event as Record<string, unknown>;
  const kind = typeof e.kind === "string" ? e.kind : "event";
  const tool_id = typeof e.tool_id === "string" ? e.tool_id : "";
  return tool_id ? `${kind}:${tool_id}` : kind;
}

async function loadReceipts(): Promise<void> {
  const root = el<HTMLDivElement>("receipts");
  root.innerHTML = "";

  const res = await rpc<{ receipts: ReceiptRecord[] }>("list_receipts", {
    limit: 50,
    offset: 0,
  });
  if (res.receipts.length === 0) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No receipts yet.";
    root.appendChild(p);
    return;
  }

  for (const r of res.receipts) {
    const box = mkItem();
    box.appendChild(mkRowLeftRight(receiptTitle(r), mkPill(true, r.ts, r.ts)));

    const pre = document.createElement("pre");
    pre.className = "url";
    pre.innerText = prettyJson(r.event);
    box.appendChild(pre);

    root.appendChild(box);
  }
}

async function loadBudgets(): Promise<void> {
  const root = el<HTMLDivElement>("budgets");
  root.innerHTML = "";

  const res = await rpc<{ budgets: BudgetRecord[] }>("list_budgets");
  if (res.budgets.length === 0) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No budgets configured.";
    root.appendChild(p);
    return;
  }

  for (const b of res.budgets) {
    const box = mkItem();
    box.appendChild(
      mkRowLeftRight(
        b.category,
        mkPill(true, `${b.daily_limit_microusd}`, `${b.daily_limit_microusd}`),
      ),
    );
    root.appendChild(box);
  }
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? `Error: ${e.message}` : "Error: unknown_error";
}

async function renderAfter(fn: () => Promise<void>): Promise<void> {
  await fn();
}

function setupTabs(): void {
  let approvalsTimer: number | null = null;

  function stopApprovalsPolling(): void {
    if (approvalsTimer !== null) {
      clearInterval(approvalsTimer);
      approvalsTimer = null;
    }
  }

  function startApprovalsPolling(): void {
    if (approvalsTimer !== null) return;
    approvalsTimer = window.setInterval(() => {
      loadApprovals().catch(() => {
        // Avoid spamming status while polling.
      });
    }, 2000);
  }

  async function activate(tab: string): Promise<void> {
    setActiveTab(tab);
    stopApprovalsPolling();
    try {
      if (tab === "mcp") await loadServers();
      if (tab === "providers") await loadProviders();
      if (tab === "approvals") {
        await loadApprovals();
        startApprovalsPolling();
      }
      if (tab === "receipts") await loadReceipts();
      if (tab === "budgets") await loadBudgets();
      setStatus("");
    } catch (e) {
      setStatus(errorMessage(e));
    }
  }

  for (const b of document.querySelectorAll<HTMLButtonElement>("button.tab")) {
    b.addEventListener("click", () => {
      const tab = b.dataset.tab || "mcp";
      void activate(tab);
    });
  }

  void activate("mcp");
}

function setupActions(): void {
  el<HTMLButtonElement>("refresh-servers").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadServers()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("refresh-providers").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadProviders()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("refresh-approvals").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadApprovals()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("refresh-receipts").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadReceipts()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("refresh-budgets").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadBudgets()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("verify-receipts").addEventListener("click", () => {
    setStatus("Verifying receipt chain...");
    rpc<{ ok: boolean }>("verify_receipts")
      .then((r) => {
        setStatus(r.ok ? "Receipt chain OK." : "Receipt chain FAILED.");
      })
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("export-receipts").addEventListener("click", () => {
    setStatus("Exporting...");
    rpc<{ receipts: ReceiptRecord[] }>("list_receipts", { limit: 500, offset: 0 })
      .then((r) => {
        const blob = new Blob([prettyJson(r)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "briefcase-receipts.json";
        a.click();
        URL.revokeObjectURL(url);
        setStatus("Exported.");
      })
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLFormElement>("add-server-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const server_id = el<HTMLInputElement>("server-id").value.trim();
    const endpoint_url = el<HTMLInputElement>("endpoint-url").value.trim();
    if (!server_id || !endpoint_url) {
      setStatus("Error: missing server_id or endpoint_url");
      return;
    }

    setStatus("Adding server...");
    rpc("upsert_mcp_server", { server_id, endpoint_url })
      .then(() => loadServers())
      .then(() => setStatus("Server added."))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLFormElement>("add-provider-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const provider_id = el<HTMLInputElement>("provider-id").value.trim();
    const base_url = el<HTMLInputElement>("provider-base-url").value.trim();
    if (!provider_id || !base_url) {
      setStatus("Error: missing provider_id or base_url");
      return;
    }

    setStatus("Adding provider...");
    rpc("upsert_provider", { provider_id, base_url })
      .then(() => loadProviders())
      .then(() => setStatus("Provider added."))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLFormElement>("set-budget-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const category = el<HTMLInputElement>("budget-category").value.trim();
    const daily = el<HTMLInputElement>("budget-limit").value.trim();
    const daily_limit_microusd = Number.parseInt(daily, 10);
    if (!category || !Number.isFinite(daily_limit_microusd) || daily_limit_microusd < 0) {
      setStatus("Error: invalid category or limit");
      return;
    }

    setStatus("Setting budget...");
    rpc("set_budget", { category, daily_limit_microusd })
      .then(() => loadBudgets())
      .then(() => setStatus("Budget set."))
      .catch((e) => setStatus(errorMessage(e)));
  });
}

function main(): void {
  setupTabs();
  setupActions();
}

main();

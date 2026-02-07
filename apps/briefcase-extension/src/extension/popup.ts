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

type PolicyGetResponse = {
  policy_text: string;
  policy_hash_hex: string;
  updated_at_rfc3339: string;
};

type PolicyDiffOp = "context" | "add" | "remove";

type PolicyDiffLine = {
  op: PolicyDiffOp;
  text: string;
};

type PolicyProposal = {
  id: string;
  created_at_rfc3339: string;
  expires_at_rfc3339: string;
  prompt: string;
  base_policy_hash_hex: string;
  proposed_policy_hash_hex: string;
  diff: PolicyDiffLine[];
  proposed_policy_text: string;
};

type PolicyCompileResponse = {
  proposal: PolicyProposal;
};

type PolicyApplyResponse =
  | { status: "applied"; policy_hash_hex: string; updated_at_rfc3339: string }
  | { status: "approval_required"; approval: ApprovalRequest }
  | { status: "denied"; reason: string }
  | { status: "error"; message: string };

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

type AiSeverity = "low" | "medium" | "high";

type AiAnomalyKind =
  | "spend_spike"
  | "output_poisoning"
  | "expensive_call"
  | "new_domain";

type AiAnomaly = {
  kind: AiAnomalyKind;
  severity: AiSeverity;
  message: string;
  receipt_id: number | null;
  ts_rfc3339: string | null;
};

type ControlPlaneStatusResponse =
  | { status: "not_enrolled" }
  | {
      status: "enrolled";
      base_url: string;
      device_id: string;
      policy_signing_pubkey_b64: string;
      last_policy_bundle_id: number | null;
      last_receipt_upload_id: number;
      last_sync_at_rfc3339: string | null;
      last_error: string | null;
      updated_at_rfc3339: string;
    };

type ControlPlaneSyncResponse =
  | { status: "not_enrolled" }
  | { status: "synced"; policy_applied: boolean; receipts_uploaded: number };

let lastPolicyProposal: PolicyProposal | null = null;

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

function mkSeverityPill(sev: AiSeverity): HTMLDivElement {
  const pill = document.createElement("div");
  pill.className = `pill ${sev === "high" ? "no" : "ok"}`;
  pill.innerText = sev;
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

    const disconnect = document.createElement("button");
    disconnect.className = "refresh";
    disconnect.type = "button";
    disconnect.innerText = "Disconnect OAuth";
    disconnect.addEventListener("click", async () => {
      setStatus(`Disconnecting OAuth for ${s.id}...`);
      try {
        await rpc("revoke_mcp_oauth", { server_id: s.id });
        await renderAfter(loadServers);
        setStatus("OAuth disconnected.");
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

    if (s.has_oauth_refresh) {
      actions.appendChild(disconnect);
    } else {
      actions.appendChild(connect);
    }
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

    const disconnect = document.createElement("button");
    disconnect.className = "refresh";
    disconnect.type = "button";
    disconnect.innerText = "Disconnect OAuth";
    disconnect.disabled = !p.has_oauth_refresh;
    disconnect.addEventListener("click", async () => {
      setStatus(`Disconnecting OAuth for ${p.id}...`);
      try {
        await rpc("revoke_provider_oauth", { provider_id: p.id });
        await renderAfter(loadProviders);
        setStatus("OAuth disconnected.");
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
    actions.appendChild(disconnect);
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

    const summaryObj =
      a.summary && typeof a.summary === "object" ? (a.summary as any) : null;
    const copilot =
      summaryObj && typeof summaryObj.copilot_summary === "string"
        ? String(summaryObj.copilot_summary)
        : "";
    if (copilot) {
      const s = document.createElement("div");
      s.className = "url";
      s.innerText = copilot;
      box.appendChild(s);
    }

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

async function loadAlerts(): Promise<void> {
  const root = el<HTMLDivElement>("alerts");
  root.innerHTML = "";

  const res = await rpc<{ anomalies: AiAnomaly[] }>("ai_anomalies", { limit: 200 });
  if (res.anomalies.length === 0) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No alerts.";
    root.appendChild(p);
    return;
  }

  for (const a of res.anomalies) {
    const box = mkItem();
    box.appendChild(mkRowLeftRight(a.kind, mkSeverityPill(a.severity)));

    const msg = document.createElement("div");
    msg.className = "url";
    msg.innerText = a.message;
    box.appendChild(msg);

    const meta = document.createElement("div");
    meta.className = "url";
    const rid = a.receipt_id !== null ? `receipt=${a.receipt_id}` : "receipt=-";
    const ts = a.ts_rfc3339 ?? "-";
    meta.innerText = `${rid} | ts=${ts}`;
    box.appendChild(meta);

    root.appendChild(box);
  }
}

function renderControlPlaneStatus(res: ControlPlaneStatusResponse): void {
  const root = el<HTMLDivElement>("cp-status");
  root.innerHTML = "";

  if (res.status === "not_enrolled") {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "Not enrolled.";
    root.appendChild(p);
    return;
  }

  const box = mkItem();
  box.appendChild(mkRowLeftRight("enrolled", mkPill(true, "yes", "no")));

  const base = document.createElement("div");
  base.className = "url";
  base.innerText = `base_url: ${res.base_url}`;
  box.appendChild(base);

  const dev = document.createElement("div");
  dev.className = "url";
  dev.innerText = `device_id: ${res.device_id}`;
  box.appendChild(dev);

  const bundle = document.createElement("div");
  bundle.className = "url";
  bundle.innerText = `last_bundle_id: ${res.last_policy_bundle_id ?? "-"}`;
  box.appendChild(bundle);

  const receipts = document.createElement("div");
  receipts.className = "url";
  receipts.innerText = `last_receipt_upload_id: ${res.last_receipt_upload_id}`;
  box.appendChild(receipts);

  const sync = document.createElement("div");
  sync.className = "url";
  sync.innerText = `last_sync_at: ${res.last_sync_at_rfc3339 ?? "-"}`;
  box.appendChild(sync);

  if (res.last_error) {
    const err = document.createElement("div");
    err.className = "url";
    err.innerText = `last_error: ${res.last_error}`;
    box.appendChild(err);
  }

  root.appendChild(box);
}

async function loadControlPlaneStatus(): Promise<void> {
  const res = await rpc<ControlPlaneStatusResponse>("control_plane_status");
  renderControlPlaneStatus(res);
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

function policyDiffText(diff: PolicyDiffLine[]): string {
  const out: string[] = [];
  for (const l of diff) {
    const prefix = l.op === "add" ? "+" : l.op === "remove" ? "-" : " ";
    out.push(`${prefix}${l.text}`);
  }
  return `${out.join("\n")}\n`;
}

function renderPolicyPane(current: PolicyGetResponse): void {
  const root = el<HTMLDivElement>("policy-proposal");
  root.innerHTML = "";

  const cur = mkItem();
  cur.appendChild(
    mkRowLeftRight(
      "current",
      mkPill(true, current.policy_hash_hex.slice(0, 12), "policy"),
    ),
  );
  const meta = document.createElement("div");
  meta.className = "url";
  meta.innerText = `updated: ${current.updated_at_rfc3339}`;
  cur.appendChild(meta);
  const pre = document.createElement("pre");
  pre.className = "diff";
  pre.innerText = current.policy_text;
  cur.appendChild(pre);
  root.appendChild(cur);

  if (!lastPolicyProposal) {
    const p = document.createElement("p");
    p.className = "status";
    p.innerText = "No compiled proposal yet.";
    root.appendChild(p);
    return;
  }

  const prop = lastPolicyProposal;
  const box = mkItem();
  box.appendChild(mkRowLeftRight("proposal", mkPill(true, prop.id, prop.id)));

  const meta2 = document.createElement("div");
  meta2.className = "url";
  meta2.innerText = `expires: ${prop.expires_at_rfc3339}`;
  box.appendChild(meta2);

  const meta3 = document.createElement("div");
  meta3.className = "url";
  meta3.innerText = `base: ${prop.base_policy_hash_hex.slice(0, 12)} | proposed: ${prop.proposed_policy_hash_hex.slice(0, 12)}`;
  box.appendChild(meta3);

  const diff = document.createElement("pre");
  diff.className = "diff";
  diff.innerText = policyDiffText(prop.diff);
  box.appendChild(diff);

  const proposed = document.createElement("pre");
  proposed.className = "diff";
  proposed.innerText = prop.proposed_policy_text;
  box.appendChild(proposed);

  const actions = document.createElement("div");
  actions.className = "actions";

  const apply = document.createElement("button");
  apply.className = "connect";
  apply.type = "button";
  apply.innerText = "Apply (requires approval)";
  apply.addEventListener("click", async () => {
    setStatus("Applying policy proposal...");
    try {
      const res = await rpc<PolicyApplyResponse>("policy_apply", {
        proposal_id: prop.id,
      });
      if (res.status === "applied") {
        lastPolicyProposal = null;
        await renderAfter(loadPolicy);
        setStatus("Policy applied.");
        return;
      }
      if (res.status === "approval_required") {
        const a = res.approval;
        if (a.kind === "local") {
          setStatus("Approval required. Approving locally...");
          await rpc("approve", { id: a.id });
          const res2 = await rpc<PolicyApplyResponse>("policy_apply", {
            proposal_id: prop.id,
          });
          if (res2.status === "applied") {
            lastPolicyProposal = null;
            await renderAfter(loadPolicy);
            setStatus("Policy applied.");
          } else if (res2.status === "approval_required") {
            setStatus("Still pending approval.");
          } else if (res2.status === "denied") {
            setStatus(`Denied: ${res2.reason}`);
          } else {
            setStatus(res2.message);
          }
          return;
        }

        setStatus("Mobile signer approval required. Approve from the signer app, then click Apply again.");
        return;
      }
      if (res.status === "denied") {
        setStatus(`Denied: ${res.reason}`);
        return;
      }
      setStatus(res.message);
    } catch (e) {
      setStatus(errorMessage(e));
    }
  });

  actions.appendChild(apply);
  box.appendChild(actions);
  root.appendChild(box);
}

async function loadPolicy(): Promise<void> {
  const current = await rpc<PolicyGetResponse>("policy_get");
  renderPolicyPane(current);
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
      if (tab === "alerts") await loadAlerts();
      if (tab === "enterprise") await loadControlPlaneStatus();
      if (tab === "receipts") await loadReceipts();
      if (tab === "budgets") await loadBudgets();
      if (tab === "policy") await loadPolicy();
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

  el<HTMLButtonElement>("refresh-alerts").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadAlerts()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("cp-refresh").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadControlPlaneStatus()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLButtonElement>("cp-sync").addEventListener("click", () => {
    setStatus("Syncing...");
    rpc<ControlPlaneSyncResponse>("control_plane_sync", {})
      .then((r) => {
        if (r.status === "not_enrolled") {
          setStatus("Not enrolled.");
          return;
        }
        setStatus(
          `Sync complete. receipts_uploaded=${r.receipts_uploaded} policy_applied=${r.policy_applied}`,
        );
      })
      .then(() => loadControlPlaneStatus())
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

  el<HTMLButtonElement>("policy-refresh").addEventListener("click", () => {
    setStatus("Refreshing...");
    loadPolicy()
      .then(() => setStatus(""))
      .catch((e) => setStatus(errorMessage(e)));
  });

  el<HTMLFormElement>("policy-compile-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const prompt = el<HTMLTextAreaElement>("policy-prompt").value.trim();
    if (!prompt) {
      setStatus("Error: missing prompt");
      return;
    }

    setStatus("Compiling policy...");
    rpc<PolicyCompileResponse>("policy_compile", { prompt })
      .then((r) => {
        lastPolicyProposal = r.proposal;
      })
      .then(() => loadPolicy())
      .then(() => setStatus("Policy compiled. Review and apply."))
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

  el<HTMLFormElement>("cp-enroll-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const base_url = el<HTMLInputElement>("cp-base-url").value.trim();
    const admin_token_el = el<HTMLInputElement>("cp-admin-token");
    const admin_token = admin_token_el.value.trim();
    const device_name = el<HTMLInputElement>("cp-device-name").value.trim();
    if (!base_url || !admin_token || !device_name) {
      setStatus("Error: missing base_url, admin_token, or device_name");
      return;
    }

    setStatus("Enrolling...");
    rpc<ControlPlaneStatusResponse>("control_plane_enroll", {
      base_url,
      admin_token,
      device_name,
    })
      .then(() => {
        // Avoid keeping the token in the DOM longer than needed.
        admin_token_el.value = "";
      })
      .then(() => loadControlPlaneStatus())
      .then(() => setStatus("Enrolled."))
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

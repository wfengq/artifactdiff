(() => {
  const status = document.getElementById("status");
  let sessionToken = null;
  let csrfToken = null;
  let findings = [];
  let selected = -1;
  const fail = () => { status.textContent = "Unable to connect to the local review desk."; };
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);

  if (token === null || !/^[A-Za-z0-9_-]{43}$/.test(token)) { fail(); return; }

  const headers = (mutation = false) => {
    const value = {"X-ArtifactDiff-Session": sessionToken, "X-ArtifactDiff-CSRF": csrfToken};
    if (mutation) value["Content-Type"] = "application/json";
    return value;
  };
  const request = async (path, options = {}) => {
    const response = await fetch(path, options);
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "review request failed");
    return body;
  };
  const listen = (id, event, handler) => {
    const element = document.getElementById(id);
    if (element && typeof element.addEventListener === "function") element.addEventListener(event, handler);
  };

  void fetch("/api/session", {method: "POST", headers: {"X-ArtifactDiff-Session": token}})
    .then((response) => { if (!response.ok) throw new Error("session exchange failed"); return response.json(); })
    .then(async (session) => {
      if (!session || typeof session.csrf_token !== "string") throw new Error("invalid session response");
      sessionToken = token; csrfToken = session.csrf_token; await loadWorkspace();
    }).catch(fail);

  async function loadWorkspace() {
    let overview;
    try {
      overview = await request("/api/bundle", {headers: headers()});
      document.getElementById("bundle-panel").hidden = false;
      renderBundle(overview);
      const page = await request("/api/findings?cursor=0&limit=100", {headers: headers()});
      findings = page.items; renderFindingList(); if (findings.length) await selectFinding(0);
    } catch (_) {
      overview = await request("/api/policy", {headers: headers()});
      document.getElementById("policy-panel").hidden = false;
      document.getElementById("assurance").textContent = `Assurance: ${overview.assurance}`;
    }
    document.body.dataset.state = overview.state;
    status.textContent = "Connected to the local review desk.";
  }

  function renderBundle(bundle) {
    document.getElementById("assurance").textContent = `Assurance: ${bundle.assurance}`;
    document.getElementById("raw-verdict").textContent = `Raw verdict: ${bundle.raw_verdict}`;
    document.getElementById("effective-verdict").textContent = `Effective verdict: ${bundle.effective_verdict.outcome}`;
    document.getElementById("signature-status").textContent = `Signature at creation: ${bundle.signature_status.valid_at_creation ?? "not present"}; current trust: ${bundle.signature_status.currently_trusted ?? "not applicable"}; event chain: ${bundle.signature_status.event_chain_valid ? "valid" : "invalid"}`;
    const history = document.getElementById("event-history"); history.replaceChildren();
    bundle.event_history.forEach((event) => { const item = document.createElement("li"); item.textContent = `${event.sequence}: ${event.event_type}${event.finding_id ? ` · ${event.finding_id}` : ""}${event.decision ? ` · ${event.decision}` : ""}`; history.append(item); });
  }
  function renderFindingList() {
    const list = document.getElementById("finding-list"); list.replaceChildren();
    findings.forEach((finding, index) => {
      const item = document.createElement("li"); const button = document.createElement("button");
      button.type = "button"; button.textContent = `${finding.outcome.toUpperCase()} · ${finding.rule_id} · ${finding.location}`;
      button.addEventListener("click", () => void selectFinding(index)); item.append(button); list.append(item);
    });
  }
  async function selectFinding(index) {
    if (index < 0 || index >= findings.length) return;
    selected = index;
    const finding = await request(`/api/findings/${encodeURIComponent(findings[index].id)}`, {headers: headers()});
    document.getElementById("finding-title").textContent = `${finding.outcome.toUpperCase()} finding`;
    document.getElementById("finding-rule").textContent = `Rule: ${finding.rule_id}`;
    document.getElementById("finding-selector").textContent = `Selector: ${finding.selector_status || "not applicable"}`;
    document.getElementById("before-excerpt").textContent = finding.evidence.before_excerpt || "Unavailable";
    document.getElementById("after-excerpt").textContent = finding.evidence.after_excerpt || "Unavailable";
    document.getElementById("finding-remediation").textContent = finding.remediation;
    const visual = document.getElementById("visual-evidence"); visual.replaceChildren();
    finding.page_crops.forEach((crop) => { const item = document.createElement("li"); const image = document.createElement("img"); image.src = crop.data_url; image.alt = `Changed region evidence: ${crop.path}`; item.append(image); visual.append(item); });
    document.getElementById("approval-form").hidden = !finding.approval_enabled;
    document.getElementById("finding-detail").focus();
  }

  listen("previous-finding", "click", () => void selectFinding(selected - 1));
  listen("next-finding", "click", () => void selectFinding(selected + 1));
  if (typeof document.addEventListener === "function") document.addEventListener("keydown", (event) => {
    if (event.altKey && event.key === "ArrowLeft") void selectFinding(selected - 1);
    if (event.altKey && event.key === "ArrowRight") void selectFinding(selected + 1);
  });
  listen("policy-form", "submit", async (event) => {
    event.preventDefault(); const values = new FormData(event.currentTarget);
    let plugins;
    try { plugins = JSON.parse(values.get("plugins")); } catch (_) { status.textContent = "Required plugins must be valid JSON."; return; }
    const protect = Array.from(document.querySelectorAll('input[name="protect"]:checked'), (input) => input.value);
    const payload = {rule_id: values.get("rule_id"), selector: {clause_label: values.get("clause_label"), heading: values.get("heading"), anchor: values.get("anchor")}, before: values.get("before"), after: values.get("after"), protect, metadata: {non_business_change: values.get("metadata")}, visual: {pagination_reflow: values.get("pagination"), on_unavailable: values.get("visual_unavailable")}, evidence: {mode: values.get("evidence")}, required_plugins: plugins};
    const result = await request("/api/policy", {method: "POST", headers: headers(true), body: JSON.stringify(payload)});
    document.body.dataset.state = result.state;
    document.getElementById("policy-summary").textContent = JSON.stringify(result.summary, null, 2);
    const list = document.getElementById("relaxations"); list.replaceChildren();
    result.summary.relaxations.forEach((relaxation) => { const item = document.createElement("li"); item.textContent = `${relaxation.field}: ${JSON.stringify(relaxation.selected)}`; list.append(item); });
    document.getElementById("freeze-policy").disabled = false;
  });
  listen("freeze-policy", "click", async () => {
    await request("/api/policy/seal", {method: "POST", headers: headers(true), body: JSON.stringify({assurance: "local"})});
    status.textContent = "Policy frozen. The public sealed artifact is ready.";
  });
  listen("approval-form", "submit", async (event) => {
    event.preventDefault(); document.body.dataset.state = "approval-pending";
    const reason = new FormData(event.currentTarget).get("reason");
    const result = await request("/api/approvals", {method: "POST", headers: headers(true), body: JSON.stringify({finding_id: findings[selected].id, reason})});
    document.body.dataset.state = result.state;
    document.getElementById("effective-verdict").textContent = `Effective verdict: ${result.effective_verdict.outcome}`;
    event.currentTarget.hidden = true;
  });
  listen("shutdown", "click", () => void request("/api/shutdown", {method: "POST", headers: headers(true), body: "{}"}));
})();

/**
 * Browser client for the read-only agent thread.
 * Why: keep human interaction strictly GET-only while showing operator runbook data.
 */
const threadStatus = document.getElementById("thread-status");
const messagesElement = document.getElementById("messages");
const refreshButton = document.getElementById("refresh-button");

const dateFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium"
});

let isRefreshing = false;

function toThreadMap(messages) {
  const sorted = [...messages].sort((left, right) => {
    const leftTime = new Date(left.createdAt).getTime();
    const rightTime = new Date(right.createdAt).getTime();
    return leftTime - rightTime;
  });

  const byParent = new Map();
  for (const message of sorted) {
    const key = message.parentId ?? "root";
    if (!byParent.has(key)) {
      byParent.set(key, []);
    }
    byParent.get(key).push(message);
  }

  return byParent;
}

function setThreadStatus(text) {
  threadStatus.textContent = text;
}

function setRefreshButtonBusy(isBusy) {
  refreshButton.disabled = isBusy;
  refreshButton.textContent = isBusy ? "Refreshing..." : "Refresh";
}

function shortHash(hex) {
  if (typeof hex !== "string" || hex.length < 16) {
    return hex ?? "";
  }
  return `${hex.slice(0, 8)}…${hex.slice(-6)}`;
}

function renderProvenance(provenance) {
  const wrapper = document.createElement("footer");
  wrapper.className = "message-provenance";

  const report = provenance.report ?? {};
  const passed = report.passed === true;
  const checksRun = typeof report.checksRun === "number" ? report.checksRun : 0;
  const checksPassed = typeof report.checksPassed === "number" ? report.checksPassed : 0;

  const badge = document.createElement("span");
  badge.className = `provenance-badge ${passed ? "ok" : "warn"}`;
  badge.textContent = passed
    ? `CommitLLM ✓ ${checksPassed}/${checksRun}`
    : `CommitLLM ran ${checksPassed}/${checksRun}`;
  wrapper.append(badge);

  const modelSpan = document.createElement("span");
  modelSpan.className = "provenance-field";
  modelSpan.textContent = `model · ${provenance.model}`;
  wrapper.append(modelSpan);

  const commitSpan = document.createElement("span");
  commitSpan.className = "provenance-field mono";
  commitSpan.textContent = `commit · ${shortHash(provenance.commitHash)}`;
  wrapper.append(commitSpan);

  const keySpan = document.createElement("span");
  keySpan.className = "provenance-field mono";
  keySpan.textContent = `key · ${shortHash(provenance.verifierKeySha256)}`;
  wrapper.append(keySpan);

  const auditSpan = document.createElement("span");
  auditSpan.className = "provenance-field mono";
  auditSpan.textContent = `audit · ${shortHash(provenance.auditBinarySha256)}`;
  wrapper.append(auditSpan);

  if (provenance.modelOutputHint) {
    const prompt = document.createElement("details");
    prompt.className = "provenance-prompt";
    const summary = document.createElement("summary");
    summary.textContent = "Raw model output (signed by agent)";
    prompt.append(summary);
    const pre = document.createElement("pre");
    pre.textContent = provenance.modelOutputHint;
    prompt.append(pre);
    wrapper.append(prompt);
  }

  if (!passed && Array.isArray(report.failures) && report.failures.length > 0) {
    const failures = document.createElement("details");
    failures.className = "provenance-failures";
    const summary = document.createElement("summary");
    summary.textContent = `Verifier flagged ${report.failures.length} check(s)`;
    failures.append(summary);
    const list = document.createElement("ul");
    for (const failure of report.failures.slice(0, 8)) {
      const li = document.createElement("li");
      li.textContent = failure;
      list.append(li);
    }
    failures.append(list);
    wrapper.append(failures);
  }

  return wrapper;
}

function renderMessageNode(message, byParent) {
  const listItem = document.createElement("li");
  listItem.className = "message-item";

  const meta = document.createElement("div");
  meta.className = "message-meta";
  const parentLabel = message.parentId ? `reply:${message.parentId.slice(0, 8)}` : "root";
  meta.textContent = `${message.authorAgentId} · ${dateFormatter.format(new Date(message.createdAt))} · ${parentLabel}`;
  listItem.append(meta);

  const content = document.createElement("p");
  content.className = "message-content";
  content.textContent = message.content;
  listItem.append(content);

  if (message.provenance) {
    listItem.append(renderProvenance(message.provenance));
  }

  const children = byParent.get(message.id) ?? [];
  if (children.length > 0) {
    const nested = document.createElement("ol");
    nested.className = "messages nested";
    for (const child of children) {
      nested.append(renderMessageNode(child, byParent));
    }
    listItem.append(nested);
  }

  return listItem;
}

function renderMessages(messages) {
  messagesElement.innerHTML = "";

  const byParent = toThreadMap(messages);
  const roots = byParent.get("root") ?? [];

  if (roots.length === 0) {
    const empty = document.createElement("li");
    empty.className = "message-empty";
    empty.textContent = "No verified agent messages yet.";
    messagesElement.append(empty);
    return;
  }

  for (const message of roots) {
    messagesElement.append(renderMessageNode(message, byParent));
  }
}

async function refreshMessages() {
  if (isRefreshing) {
    return;
  }

  isRefreshing = true;
  setRefreshButtonBusy(true);

  try {
    const response = await fetch("/api/messages", { method: "GET" });
    if (!response.ok) {
      throw new Error(`${response.status} ${await response.text()}`);
    }

    const data = await response.json();
    const messages = Array.isArray(data.messages) ? data.messages : [];
    renderMessages(messages);

    setThreadStatus(
      `Read-only view · ${messages.length} verified messages · updated ${dateFormatter.format(new Date())}`
    );
  } catch (error) {
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  } finally {
    isRefreshing = false;
    setRefreshButtonBusy(false);
  }
}

refreshButton.addEventListener("click", () => {
  refreshMessages().catch((error) => {
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  });
});

refreshMessages().catch((error) => {
  setThreadStatus(`Initial load failed: ${error.message}`);
});

window.setInterval(() => {
  refreshMessages().catch((error) => {
    // Polling failures must not break the read-only client.
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  });
}, 5000);

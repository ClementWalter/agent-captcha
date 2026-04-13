/**
 * Browser client for the read-only agent thread.
 * Why: keep human interaction strictly GET-only while showing operator runbook data.
 */
const threadStatus = document.getElementById("thread-status");
const messagesElement = document.getElementById("messages");

const dateFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium"
});

let isRefreshing = false;
let hasLoadedOnce = false;

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

// Why: re-rendering the full list every poll destroys <details> toggle state
// (e.g. an expanded "Raw model output"), so we reconcile instead — keep the
// DOM nodes we've already mounted and only append messages we haven't seen.
const renderedMessageIds = new Set();
let emptyNode = null;

function renderMessages(messages) {
  const byParent = toThreadMap(messages);
  const roots = byParent.get("root") ?? [];

  if (roots.length === 0) {
    if (renderedMessageIds.size === 0 && !emptyNode) {
      emptyNode = document.createElement("li");
      emptyNode.className = "message-empty";
      emptyNode.textContent = "No verified agent messages yet.";
      messagesElement.append(emptyNode);
    }
    return;
  }

  if (emptyNode) {
    emptyNode.remove();
    emptyNode = null;
  }

  for (const message of roots) {
    if (renderedMessageIds.has(message.id)) {
      continue;
    }
    messagesElement.append(renderMessageNode(message, byParent));
    renderedMessageIds.add(message.id);
  }
}

async function refreshMessages() {
  if (isRefreshing) {
    return;
  }
  isRefreshing = true;

  try {
    const response = await fetch("/api/messages", { method: "GET" });
    if (!response.ok) {
      throw new Error(`${response.status} ${await response.text()}`);
    }

    const data = await response.json();
    const messages = Array.isArray(data.messages) ? data.messages : [];
    const newMessages = messages.filter((m) => !renderedMessageIds.has(m.id));
    renderMessages(messages);

    // Update the status line on (a) the very first successful load so
    // "Loading thread…" goes away, or (b) when the visible count changes.
    // Background polls against an unchanged thread no-op to keep the UI still.
    if (!hasLoadedOnce || newMessages.length > 0) {
      setThreadStatus(
        `Read-only view · ${messages.length} verified message${messages.length === 1 ? "" : "s"}`
      );
      hasLoadedOnce = true;
    }
  } catch (error) {
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  } finally {
    isRefreshing = false;
  }
}

refreshMessages().catch((error) => {
  setThreadStatus(`Initial load failed: ${error.message}`);
});

window.setInterval(() => {
  refreshMessages().catch((error) => {
    // Polling failures must not break the read-only client.
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  });
}, 3000);

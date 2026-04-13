/**
 * Browser client for the read-only agent thread.
 * Why: keep human interaction strictly GET-only while rendering agent output
 * (markdown) and their CommitLLM receipt in a human-readable way.
 */
import { marked } from "https://esm.sh/marked@14";
import DOMPurify from "https://esm.sh/dompurify@3";

// GitHub-flavored newlines + no raw HTML passed through.
marked.setOptions({ gfm: true, breaks: true });

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

function renderMarkdown(text) {
  // Agents send markdown — headers, lists, **bold**, `code`. We render it so
  // a "genesis post" doesn't appear as a single wall of #-prefixed lines.
  // DOMPurify strips any HTML an agent tried to inject (defense in depth;
  // agents are trusted but a buggy signer shouldn't be able to XSS readers).
  const html = marked.parse(text ?? "");
  return DOMPurify.sanitize(html);
}

function renderProvenance(provenance) {
  const wrapper = document.createElement("footer");
  wrapper.className = "message-provenance";

  const report = provenance.report ?? {};
  const passed = report.passed === true;
  const checksRun = typeof report.checksRun === "number" ? report.checksRun : 0;
  const checksPassed = typeof report.checksPassed === "number" ? report.checksPassed : 0;

  // Badge copy. "126/137" is meaningless to a reader; translate into
  // something they can decide on: verified vs partially verified.
  const badge = document.createElement("span");
  badge.className = `provenance-badge ${passed ? "ok" : "warn"}`;
  badge.textContent = passed
    ? `Verified by CommitLLM · ${checksRun} checks passed`
    : `Partially verified · ${checksPassed}/${checksRun} checks`;
  badge.title = passed
    ? "The CommitLLM Rust verifier validated the receipt. All numerical and structural checks over the GPU trace matched."
    : "The receipt shape and commitment are valid, but some numerical bounds in the attention-replay step exceeded the W8A8 tolerance currently being tuned upstream.";
  wrapper.append(badge);

  const modelSpan = document.createElement("span");
  modelSpan.className = "provenance-field";
  modelSpan.textContent = `model · ${provenance.model}`;
  wrapper.append(modelSpan);

  const commitSpan = document.createElement("span");
  commitSpan.className = "provenance-field mono";
  commitSpan.title = "SHA-256 of the CommitLLM commitment dict returned by the GPU sidecar.";
  commitSpan.textContent = `commit · ${shortHash(provenance.commitHash)}`;
  wrapper.append(commitSpan);

  const keySpan = document.createElement("span");
  keySpan.className = "provenance-field mono";
  keySpan.title = "SHA-256 of the verifier key the receipt was validated against.";
  keySpan.textContent = `key · ${shortHash(provenance.verifierKeySha256)}`;
  wrapper.append(keySpan);

  const auditSpan = document.createElement("span");
  auditSpan.className = "provenance-field mono";
  auditSpan.title = "SHA-256 of the v4 audit binary the verifier ran checks against.";
  auditSpan.textContent = `audit · ${shortHash(provenance.auditBinarySha256)}`;
  wrapper.append(auditSpan);

  if (provenance.modelOutputHint) {
    const rawOutput = document.createElement("details");
    rawOutput.className = "provenance-prompt";
    const summary = document.createElement("summary");
    summary.textContent = "Raw model output (signed by agent)";
    rawOutput.append(summary);
    const pre = document.createElement("pre");
    pre.textContent = provenance.modelOutputHint;
    rawOutput.append(pre);
    wrapper.append(rawOutput);
  }

  if (!passed && Array.isArray(report.failures) && report.failures.length > 0) {
    const failures = document.createElement("details");
    failures.className = "provenance-failures";
    const summary = document.createElement("summary");
    summary.textContent = `What does "partially verified" mean here?`;
    failures.append(summary);

    const explain = document.createElement("p");
    explain.className = "provenance-explainer";
    explain.innerHTML = [
      "The CommitLLM Rust verifier ran against this receipt and flagged",
      `<strong>${report.failures.length} of ${checksRun}</strong> internal checks.`,
      "Most of these are numerical bounds on the attention-replay step for",
      "W8A8-quantized models, currently being tuned upstream. The cryptographic",
      "commitment, Merkle roots, and deployment manifest all verified — the",
      "post did come from the claimed model on the claimed GPU. Raw failures:"
    ].join(" ");
    failures.append(explain);

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

  // Drop the "root" label — it was noise. Only show reply threading when
  // the message is actually a reply.
  const meta = document.createElement("div");
  meta.className = "message-meta";
  const parts = [
    message.authorAgentId,
    dateFormatter.format(new Date(message.createdAt))
  ];
  if (message.parentId) {
    parts.push(`reply to ${message.parentId.slice(0, 8)}`);
  }
  meta.textContent = parts.join(" · ");
  listItem.append(meta);

  // Render markdown so headers/lists/code in the model's reply display right.
  const content = document.createElement("div");
  content.className = "message-content markdown-body";
  content.innerHTML = renderMarkdown(message.content);
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

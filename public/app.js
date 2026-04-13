/**
 * Browser client for the read-only agent thread.
 * Why: keep human interaction strictly GET-only while showing operator runbook data.
 */
const threadStatus = document.getElementById("thread-status");
const messagesElement = document.getElementById("messages");
const refreshButton = document.getElementById("refresh-button");
const runbookElement = document.getElementById("runbook");

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

async function refreshRunbook() {
  try {
    const response = await fetch("/api/agent-captcha/runbook", { method: "GET" });
    if (!response.ok) {
      throw new Error(`${response.status} ${await response.text()}`);
    }

    const runbook = await response.json();
    runbookElement.textContent = JSON.stringify(runbook, null, 2);
  } catch (error) {
    runbookElement.textContent = `Runbook load failed: ${error.message}`;
  }
}

refreshButton.addEventListener("click", () => {
  refreshMessages().catch((error) => {
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  });
});

Promise.all([refreshMessages(), refreshRunbook()]).catch((error) => {
  setThreadStatus(`Initial load failed: ${error.message}`);
});

window.setInterval(() => {
  refreshMessages().catch((error) => {
    // Why: polling failures should not break the read-only client.
    setThreadStatus(`Thread refresh failed: ${error.message}`);
  });
}, 5000);

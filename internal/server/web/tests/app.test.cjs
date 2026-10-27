const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");

function loadBeforePageContent(bodyExists = false, confirmResult = false) {
  const nodes = new Map();
  const document = new EventTarget();
  document.body = bodyExists ? new EventTarget() : null;
  document.getElementById = (id) => nodes.get(id) || null;
  document.querySelector = () => null;
  document.createElement = () => ({
    dataset: {},
    attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; },
  });
  const questions = [];
  const window = { confirm(question) { questions.push(question); return confirmResult; } };
  vm.runInNewContext(source, { document, window, setTimeout, clearTimeout });
  return { document, nodes, questions };
}

function addDeploymentContent(nodes) {
  const dialog = { open: false, showModal() { this.open = true; } };
  const content = { replaceChildren(...children) { this.children = children; } };
  nodes.set("certificate-deploy-dialog", dialog);
  nodes.set("certificate-deploy-content", content);
  nodes.set("deploy-loading-cancel", { content: { firstElementChild: {
    cloneNode: () => ({ textContent: "取消" }),
  } } });
  const trigger = {
    getAttribute: (name) => name === "aria-controls" ? "certificate-deploy-dialog" : null,
    closest: (selector) => selector === "tr" ? { id: "cert-1" } : null,
  };
  return { dialog, content, trigger };
}

test("the app can initialize before the body and dialog exist", () => {
  assert.doesNotThrow(() => loadBeforePageContent());
});

test("a deployment request opens a later-added dialog before any response arrives", () => {
  const { document, nodes } = loadBeforePageContent(true);
  const { dialog, content, trigger } = addDeploymentContent(nodes);
  document.dispatchEvent(new CustomEvent("htmx:beforeRequest", { detail: { elt: trigger } }));
  assert.equal(dialog.open, true);
  assert.equal(content.children[0].textContent, "正在加载 Agent…");
  assert.equal(content.children[1].textContent, "取消");
});

test("a failed form request reports its error inside the open loading dialog", () => {
  const { document, nodes } = loadBeforePageContent();
  const { dialog, content, trigger } = addDeploymentContent(nodes);
  document.dispatchEvent(new CustomEvent("htmx:beforeRequest", { detail: { elt: trigger } }));
  document.querySelector = () => content.children[0];
  document.dispatchEvent(new CustomEvent("htmx:responseError", {
    detail: { elt: trigger, xhr: { responseText: JSON.stringify({ error: "证书正在下发" }) } },
  }));
  assert.equal(dialog.open, true);
  assert.equal(content.children[0].textContent, "证书正在下发");
  assert.equal(content.children[0].attributes.role, "alert");
});

for (const confirmed of [false, true]) {
  test(`deployment only sends the request when confirmation is ${confirmed}`, () => {
    const { document, questions } = loadBeforePageContent(true, confirmed);
    const selected = [{ dataset: { agentName: "香港 Web" }, value: "agent1" }, { dataset: { agentName: "日本 Web" }, value: "agent2" }];
    const form = { querySelectorAll: () => selected };
    const requests = [];
    const event = new CustomEvent("htmx:confirm", { cancelable: true, detail: {
      elt: { closest: () => form },
      question: "警告：是否要对「example.com」执行「下发证书」操作？",
      issueRequest: (skipConfirmation) => requests.push(skipConfirmation),
    } });
    document.dispatchEvent(event);
    assert.equal(event.defaultPrevented, true);
    assert.equal(questions.length, 1);
    assert.match(questions[0], /example\.com/);
    assert.match(questions[0], /下发证书/);
    assert.match(questions[0], /香港 Web\n日本 Web/);
    assert.match(questions[0], /2 台/);
    assert.deepEqual(requests, confirmed ? [true] : []);
  });
}

test("an empty deployment selection never asks for confirmation or sends a request", () => {
  const { document, questions } = loadBeforePageContent();
  const count = {}, submit = {}, error = {};
  const form = {
    dataset: {}, querySelectorAll: () => [],
    querySelector: (selector) => selector === "[data-deploy-count]" ? count : selector === "[data-deploy-submit]" ? submit : error,
  };
  let requests = 0;
  const event = new CustomEvent("htmx:confirm", { cancelable: true, detail: {
    elt: { closest: () => form }, issueRequest: () => requests++,
  } });
  document.dispatchEvent(event);
  assert.equal(event.defaultPrevented, true);
  assert.equal(questions.length, 0);
  assert.equal(requests, 0);
  assert.equal(submit.disabled, true);
  assert.equal(error.hidden, false);
});

test("update cancellation blocks a regular form and identifies its target version", () => {
  const { document, questions } = loadBeforePageContent();
  const form = {
    matches: () => true,
    dataset: { confirmAction: "更新 Agent", confirmTarget: "edge-1" },
    querySelector: () => ({ value: "v1.2.3" }),
  };
  const event = new Event("submit", { cancelable: true });
  Object.defineProperty(event, "target", { value: form });
  document.dispatchEvent(event);
  assert.equal(event.defaultPrevented, true);
  assert.match(questions[0], /edge-1/);
  assert.match(questions[0], /更新 Agent 至 v1\.2\.3/);
});

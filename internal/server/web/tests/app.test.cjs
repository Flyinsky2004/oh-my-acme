const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");

function loadBeforePageContent(bodyExists = false) {
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
  vm.runInNewContext(source, { document, setTimeout, clearTimeout });
  return { document, nodes };
}

function addDeploymentContent(nodes) {
  const dialog = { open: false, showModal() { this.open = true; } };
  const content = { replaceChildren(...children) { this.children = children; } };
  nodes.set("certificate-deploy-dialog", dialog);
  nodes.set("certificate-deploy-content", content);
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

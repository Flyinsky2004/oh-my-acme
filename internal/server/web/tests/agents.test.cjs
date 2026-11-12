const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../static/agents.js"), "utf8");

function createDocument() {
  const document = new EventTarget();
  const nodes = new Map();
  const bodyChildren = [];
  document.body = {
    appendChild(node) {
      bodyChildren.push(node);
    },
    removeChild(node) {
      const index = bodyChildren.indexOf(node);
      if (index >= 0) {
        bodyChildren.splice(index, 1);
      }
    },
  };
  document.nodes = nodes;
  document.bodyChildren = bodyChildren;
  document.getElementById = (id) => nodes.get(id) || null;
  document.execCommand = () => true;
  document.createElement = () => ({
    style: {},
    attributes: {},
    value: "",
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    focus() {
      this.focused = true;
    },
    select() {
      this.selected = true;
    },
  });
  return document;
}

function createTimers() {
  let nextId = 1;
  const pending = new Map();
  return {
    setTimeout(fn, ms) {
      const id = nextId++;
      pending.set(id, { fn, ms });
      return id;
    },
    clearTimeout(id) {
      pending.delete(id);
    },
    runAll() {
      const entries = Array.from(pending.values());
      pending.clear();
      for (const entry of entries) {
        entry.fn();
      }
    },
    size() {
      return pending.size;
    },
  };
}

function loadAgents({
  document = createDocument(),
  window = { isSecureContext: false },
  navigator = {},
  timers = createTimers(),
} = {}) {
  vm.runInNewContext(source, {
    document,
    window,
    navigator,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    console,
  });
  return { document, window, navigator, timers };
}

function dispatch(document, type, target) {
  const event = new Event(type, { cancelable: true });
  Object.defineProperty(event, "target", { value: target });
  document.dispatchEvent(event);
  return event;
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function addCopyButton(document, code) {
  const label = { textContent: "复制" };
  const values = { "data-copy-target": "install-command-code", "aria-label": "复制安装命令" };
  const button = {
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : null;
    },
    setAttribute(name, value) {
      values[name] = value;
    },
    querySelector(selector) {
      return selector === "span" ? label : null;
    },
    closest(selector) {
      return selector === "[data-copy-target]" ? button : null;
    },
  };
  document.nodes.set("install-command-code", code);
  return { button, label };
}

function installCommandSection(document, code, sudo, plain) {
  const section = {
    getAttribute(name) {
      if (name === "data-command-sudo") {
        return sudo;
      }
      if (name === "data-command-plain") {
        return plain;
      }
      return null;
    },
    querySelector(selector) {
      return selector === "code" ? code : null;
    },
  };
  const toggle = {
    checked: true,
    closest(selector) {
      if (selector === "[data-install-sudo]") {
        return toggle;
      }
      if (selector === "[data-install-command]") {
        return section;
      }
      return null;
    },
  };
  document.nodes.set("install-command-code", code);
  return toggle;
}

test("toggling sudo swaps only the displayed backend command", () => {
  const document = createDocument();
  const code = { textContent: "sudo bash -c 'install'" };
  const toggle = installCommandSection(document, code, "sudo bash -c 'install'", "bash -c 'install'");
  loadAgents({ document });

  toggle.checked = false;
  dispatch(document, "change", toggle);
  assert.equal(code.textContent, "bash -c 'install'");

  toggle.checked = true;
  dispatch(document, "change", toggle);
  assert.equal(code.textContent, "sudo bash -c 'install'");
});

test("copy reports success only after the clipboard promise resolves", async () => {
  const document = createDocument();
  const code = { textContent: "bash -c 'install'" };
  const { button, label } = addCopyButton(document, code);
  let copied = null;
  loadAgents({
    document,
    window: { isSecureContext: true },
    navigator: {
      clipboard: {
        writeText(text) {
          copied = text;
          return Promise.resolve();
        },
      },
    },
  });

  dispatch(document, "click", button);
  assert.equal(label.textContent, "复制");
  await flush();
  assert.equal(copied, "bash -c 'install'");
  assert.equal(label.textContent, "已复制");
  assert.equal(button.getAttribute("aria-label"), "已复制");
});

test("a rejected clipboard write reports failure instead of success", async () => {
  const document = createDocument();
  const code = { textContent: "command" };
  const { button, label } = addCopyButton(document, code);
  loadAgents({
    document,
    window: { isSecureContext: true },
    navigator: {
      clipboard: {
        writeText() {
          return Promise.reject(new Error("denied"));
        },
      },
    },
  });

  dispatch(document, "click", button);
  await flush();
  assert.equal(label.textContent, "复制失败");
  assert.equal(button.getAttribute("aria-label"), "复制失败");
});

test("the textarea fallback copies the displayed command and reports the result", () => {
  const document = createDocument();
  const code = { textContent: "plain command" };
  const { button, label } = addCopyButton(document, code);
  let copied = null;
  document.execCommand = (command) => {
    assert.equal(command, "copy");
    copied = document.bodyChildren[0].value;
    return true;
  };
  loadAgents({ document, window: { isSecureContext: false }, navigator: {} });

  dispatch(document, "click", button);
  assert.equal(copied, "plain command");
  assert.equal(label.textContent, "已复制");
  assert.equal(document.bodyChildren.length, 0);
});

test("a failed fallback copy reports failure", () => {
  const document = createDocument();
  const code = { textContent: "plain command" };
  const { button, label } = addCopyButton(document, code);
  document.execCommand = () => false;
  loadAgents({ document, window: { isSecureContext: false }, navigator: {} });

  dispatch(document, "click", button);
  assert.equal(label.textContent, "复制失败");
});

test("copy uses the command currently displayed after toggling sudo", async () => {
  const document = createDocument();
  const code = { textContent: "sudo bash -c 'install'" };
  const { button } = addCopyButton(document, code);
  const toggle = installCommandSection(document, code, "sudo bash -c 'install'", "bash -c 'install'");
  let copied = null;
  loadAgents({
    document,
    window: { isSecureContext: true },
    navigator: {
      clipboard: {
        writeText(text) {
          copied = text;
          return Promise.resolve();
        },
      },
    },
  });

  toggle.checked = false;
  dispatch(document, "change", toggle);
  dispatch(document, "click", button);
  await flush();
  assert.equal(copied, "bash -c 'install'");
});

test("the script is safe on a page without an install command", () => {
  const document = createDocument();
  assert.doesNotThrow(() => loadAgents({ document }));
  const unrelated = { closest: () => null };
  assert.doesNotThrow(() => dispatch(document, "click", unrelated));
  assert.doesNotThrow(() => dispatch(document, "change", unrelated));
});

test("a copy button whose target is absent does nothing", () => {
  const document = createDocument();
  const button = {
    getAttribute: () => "missing",
    closest: (selector) => (selector === "[data-copy-target]" ? button : null),
  };
  loadAgents({ document });
  assert.doesNotThrow(() => dispatch(document, "click", button));
});

test("loading the script twice does not copy twice", async () => {
  const document = createDocument();
  const code = { textContent: "command" };
  const { button } = addCopyButton(document, code);
  const window = { isSecureContext: true };
  let copies = 0;
  const navigator = {
    clipboard: {
      writeText() {
        copies++;
        return Promise.resolve();
      },
    },
  };
  loadAgents({ document, window, navigator });
  loadAgents({ document, window, navigator });

  dispatch(document, "click", button);
  await flush();
  assert.equal(copies, 1);
});

test("consecutive successful copies restore the stable original label and aria-label", async () => {
  const document = createDocument();
  const code = { textContent: "command" };
  const { button, label } = addCopyButton(document, code);
  const timers = createTimers();
  let copies = 0;
  loadAgents({
    document,
    window: { isSecureContext: true },
    navigator: {
      clipboard: {
        writeText() {
          copies++;
          return Promise.resolve();
        },
      },
    },
    timers,
  });

  dispatch(document, "click", button);
  await flush();
  assert.equal(label.textContent, "已复制");
  assert.equal(button.getAttribute("aria-label"), "已复制");

  // The second click happens while the first feedback timer is still pending.
  dispatch(document, "click", button);
  await flush();
  assert.equal(copies, 2);
  assert.equal(label.textContent, "已复制");
  assert.equal(button.getAttribute("aria-label"), "已复制");

  // The latest timer restores the values captured on the first click, not the
  // transient "已复制" feedback.
  timers.runAll();
  assert.equal(label.textContent, "复制");
  assert.equal(button.getAttribute("aria-label"), "复制安装命令");
});

test("a later failed copy replaces stale success feedback and still restores the original", async () => {
  const document = createDocument();
  const code = { textContent: "command" };
  const { button, label } = addCopyButton(document, code);
  const timers = createTimers();
  let call = 0;
  loadAgents({
    document,
    window: { isSecureContext: true },
    navigator: {
      clipboard: {
        writeText() {
          call++;
          return call === 1 ? Promise.resolve() : Promise.reject(new Error("denied"));
        },
      },
    },
    timers,
  });

  dispatch(document, "click", button);
  await flush();
  assert.equal(label.textContent, "已复制");

  dispatch(document, "click", button);
  await flush();
  assert.equal(label.textContent, "复制失败");
  assert.equal(button.getAttribute("aria-label"), "复制失败");

  timers.runAll();
  assert.equal(label.textContent, "复制");
  assert.equal(button.getAttribute("aria-label"), "复制安装命令");
});

test("a stale copy result cannot overwrite a newer click", async () => {
  const document = createDocument();
  const code = { textContent: "command" };
  const { button, label } = addCopyButton(document, code);
  const timers = createTimers();
  const pending = [];
  loadAgents({
    document,
    window: { isSecureContext: true },
    navigator: {
      clipboard: {
        writeText() {
          return new Promise((resolve, reject) => {
            pending.push({ resolve, reject });
          });
        },
      },
    },
    timers,
  });

  dispatch(document, "click", button);
  dispatch(document, "click", button);
  assert.equal(pending.length, 2);

  // The first (stale) write succeeds after the second click has started.
  pending[0].resolve();
  await flush();
  assert.equal(label.textContent, "复制");
  assert.equal(button.getAttribute("aria-label"), "复制安装命令");

  // Only the current write's failure is shown.
  pending[1].reject(new Error("denied"));
  await flush();
  assert.equal(label.textContent, "复制失败");
  assert.equal(button.getAttribute("aria-label"), "复制失败");

  timers.runAll();
  assert.equal(label.textContent, "复制");
  assert.equal(button.getAttribute("aria-label"), "复制安装命令");
});

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../static/login.js"), "utf8");

test("login collects browser environment without storing credentials", () => {
  const field = { value: "" };
  vm.runInNewContext(source, {
    document: { getElementById: () => field },
    navigator: { platform: "Linux", language: "zh-CN", hardwareConcurrency: 8, maxTouchPoints: 0 },
    screen: { width: 1920, height: 1080, colorDepth: 24 },
    Intl: { DateTimeFormat: () => ({ resolvedOptions: () => ({ timeZone: "Asia/Shanghai" }) }) },
  });
  assert.deepEqual(JSON.parse(field.value), { platform: "Linux", language: "zh-CN", timezone: "Asia/Shanghai", screen: "1920x1080x24", cores: 8, touch: 0 });
});

test("login remains usable when browser information is blocked", () => {
  const field = { value: "" };
  assert.doesNotThrow(() => vm.runInNewContext(source, { document: { getElementById: () => field } }));
  assert.equal(field.value, "");
});

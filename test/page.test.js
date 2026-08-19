"use strict";

/**
 * Page-level tests for index.html + rules.js using jsdom (no network).
 *
 * The page is loaded by inlining rules.js into index.html (replacing the
 * <script src> tag) and stripping the CDN stylesheet links, so the tests run
 * fully offline and deterministically. Real DOM events (change/input/click)
 * drive the UI; the generated XML is validated with jsdom's DOMParser.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const REPO_ROOT = path.resolve(__dirname, "..");
const CONCURRENCY_KEY = "ComplianceMetrics|APILimits|Client_API_Concurrency_Limit";
const CONCURRENCY_ID =
  "SymptomDefinition-VCF-SEC-ComplianceMetrics-APILimits-Client-API-Concurrency-Limit";

function loadRulesData() {
  const js = fs.readFileSync(path.join(REPO_ROOT, "rules.js"), "utf8");
  return new Function(js + "\n; return RULES_DATA;")();
}

function loadPage() {
  let html = fs.readFileSync(path.join(REPO_ROOT, "index.html"), "utf8");
  // No network in tests: drop the CDN stylesheets and inline rules.js in place.
  html = html.replace(/<link rel="stylesheet"[^>]*>\n?/g, "");
  const rulesJs = fs.readFileSync(path.join(REPO_ROOT, "rules.js"), "utf8");
  assert.ok(!rulesJs.includes("</script"), "rules.js must not contain a closing script tag");
  html = html.replace(
    '<script src="rules.js"></script>',
    "<script>\n" + rulesJs + "\n</script>"
  );
  const dom = new JSDOM(html, {
    url: "http://localhost/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
  });
  return dom;
}

function parseXml(dom, xml) {
  const doc = new dom.window.DOMParser().parseFromString(xml, "text/xml");
  const errors = doc.getElementsByTagName("parsererror");
  assert.equal(errors.length, 0, `generated XML is not well-formed:\n${errors[0]?.textContent ?? xml.slice(0, 500)}`);
  return doc;
}

function rowFor(dom, id) {
  return dom.window.document.querySelector(`tr[data-id="${id}"]`);
}

function operatorSelect(row) {
  // Each row has two selects: condition type (property/metric) and operator.
  return [...row.querySelectorAll("select")].find((sel) => sel.querySelector('option[value="contains"]'));
}

function fire(el, type) {
  el.dispatchEvent(new el.ownerDocument.defaultView.Event(type, { bubbles: true }));
}

test("renders one table row per rule (144)", () => {
  const dom = loadPage();
  const doc = dom.window.document;
  const rules = loadRulesData();
  assert.equal(rules.count, 144);

  assert.equal(doc.querySelectorAll("#rulesBody tr").length, 144);
  assert.equal(doc.getElementById("countTotal").textContent, "144");
  assert.equal(doc.getElementById("countIncluded").textContent, "144");
  assert.equal(doc.getElementById("countModified").textContent, "0");

  const first = doc.querySelector("#rulesBody tr");
  assert.equal(first.querySelectorAll("td").length, 9);
});

test("default export is well-formed and carries the inverted-operator symptoms", () => {
  const dom = loadPage();
  const doc = parseXml(dom, dom.window.buildAlertsXml());

  assert.equal(doc.querySelectorAll("SymptomDefinitions > SymptomDefinition").length, 144);
  assert.equal(
    doc.querySelectorAll('SymptomDefinition > State[severity="warning"] > Condition').length,
    144,
    "default severity is warning"
  );

  const condition = (key) => doc.querySelector(`Condition[key="${key}"]`);
  const assertCondition = (key, { operator, value, valueType, type }) => {
    const el = condition(key);
    assert.ok(el, `missing Condition for ${key}`);
    if (operator !== undefined) assert.equal(el.getAttribute("operator"), operator, key);
    if (value !== undefined) assert.equal(el.getAttribute("value"), value, key);
    if (valueType !== undefined) assert.equal(el.getAttribute("valueType"), valueType, key);
    if (type !== undefined) assert.equal(el.getAttribute("type"), type, key);
  };

  // The P0 evidence rows from issue #1: desired-state cells inverted into
  // violation symptoms (fixed by PR #16).
  assertCondition(CONCURRENCY_KEY, { operator: "!=", value: "40.0", valueType: "numeric", type: "property" });
  assertCondition("config|boot_options_efi_secure_boot_enabled", { operator: "=", value: "false", valueType: "string", type: "property" });
  assertCondition("config|extraConfig|mem_tps_share", { operator: "=", value: "true", valueType: "string", type: "property" });
  assertCondition("security|NtpServersCount", { operator: "<", value: "3.0", valueType: "numeric", type: "metric" });
  assertCondition("config|version", { operator: "regex", value: "vmx-[1-9]|vmx-1[0-8]", valueType: "string", type: "property" });
  assertCondition("config|security|service:NTP Daemon|isRunning", { operator: "!=", value: "true", valueType: "string", type: "property" });
  assertCondition("config|security|syslog_host", { operator: "regex", value: "^(false|none)$", valueType: "string", type: "property" });

  // One AlertDefinition per resource kind, symptom refs match definitions.
  assert.equal(doc.querySelectorAll("AlertDefinitions > AlertDefinition").length, 9);
  const defined = new Set([...doc.querySelectorAll("SymptomDefinition")].map((el) => el.getAttribute("id")));
  for (const ref of doc.querySelectorAll("SymptomSet > Symptom")) {
    assert.ok(defined.has(ref.getAttribute("ref")), `Symptom ref ${ref.getAttribute("ref")} has no definition`);
  }
});

test("unchecking a row's include checkbox removes it from the export", () => {
  const dom = loadPage();
  const doc = dom.window.document;

  const row = rowFor(dom, CONCURRENCY_ID);
  const checkbox = row.querySelector('input[type="checkbox"]');
  assert.equal(checkbox.checked, true);

  checkbox.checked = false;
  fire(checkbox, "change");

  assert.equal(doc.getElementById("countIncluded").textContent, "143");
  assert.ok(row.classList.contains("excluded"), "row must be visually excluded");
  // Excluding a row counts as a customization on this branch.
  assert.ok(row.classList.contains("modified"));
  assert.equal(doc.getElementById("countModified").textContent, "1");

  const xml = parseXml(dom, dom.window.buildAlertsXml());
  assert.equal(xml.querySelectorAll("SymptomDefinitions > SymptomDefinition").length, 143);
  assert.equal(xml.querySelector(`Condition[key="${CONCURRENCY_KEY}"]`), null);
});

test("changing operator and value through the DOM updates overrides and the XML", () => {
  const dom = loadPage();
  const doc = dom.window.document;

  const row = rowFor(dom, CONCURRENCY_ID);
  const opSelect = operatorSelect(row);
  const valueInput = row.querySelector("input.value-input");
  assert.equal(opSelect.value, "!=");
  assert.equal(valueInput.value, "40.0");

  opSelect.value = "<=";
  fire(opSelect, "change");
  valueInput.value = "42";
  fire(valueInput, "input");

  assert.ok(row.classList.contains("modified"), "row must be marked modified");
  assert.equal(doc.getElementById("countModified").textContent, "1");
  assert.equal(doc.getElementById("countIncluded").textContent, "144");

  // Overrides must persist to localStorage (customizations survive reloads).
  const saved = JSON.parse(dom.window.localStorage.getItem("vcf-ops-scorecard-builder.v1"));
  assert.deepEqual(saved.overrides[CONCURRENCY_ID], { operator: "<=", value: "42" });

  const xml = parseXml(dom, dom.window.buildAlertsXml());
  const cond = xml.querySelector(`Condition[key="${CONCURRENCY_KEY}"]`);
  assert.equal(cond.getAttribute("operator"), "<=");
  assert.equal(cond.getAttribute("value"), "42");
  assert.equal(cond.getAttribute("valueType"), "numeric", "numeric value flips valueType back to numeric");

  // A non-numeric value must switch the comparison to string semantics.
  valueInput.value = "unlimited";
  fire(valueInput, "input");
  const cond2 = parseXml(dom, dom.window.buildAlertsXml()).querySelector(`Condition[key="${CONCURRENCY_KEY}"]`);
  assert.equal(cond2.getAttribute("value"), "unlimited");
  assert.equal(cond2.getAttribute("valueType"), "string");
});

test("the row's reset button restores the strictest-requirement default", () => {
  const dom = loadPage();
  const doc = dom.window.document;

  const row = rowFor(dom, CONCURRENCY_ID);
  const opSelect = operatorSelect(row);
  opSelect.value = ">";
  fire(opSelect, "change");
  assert.ok(row.classList.contains("modified"));

  const reset = row.querySelector("button");
  assert.equal(reset.textContent, "reset");
  reset.click();

  assert.ok(!row.classList.contains("modified"));
  assert.equal(opSelect.value, "!=");
  assert.equal(doc.getElementById("countModified").textContent, "0");
  const cond = parseXml(dom, dom.window.buildAlertsXml()).querySelector(`Condition[key="${CONCURRENCY_KEY}"]`);
  assert.equal(cond.getAttribute("operator"), "!=");
  assert.equal(cond.getAttribute("value"), "40.0");
});

test("default scorecard export is well-formed and covers every resource kind", () => {
  const dom = loadPage();
  const rules = loadRulesData();
  const expectedResources = new Set(rules.rules.map((r) => r.resource));

  const doc = parseXml(dom, dom.window.buildScorecardXml());
  const scorecard = doc.querySelector("ComplianceScorecard");
  assert.equal(scorecard.getAttribute("name"), "VCF Security Benchmark");
  assert.equal(scorecard.getAttribute("type"), "CUSTOM");

  const ids = [...doc.querySelectorAll("AlertDefinitionId")].map((el) => el.getAttribute("id"));
  assert.equal(ids.length, expectedResources.size);
  for (const id of ids) {
    assert.match(id, /^AlertDefinition-VCF-SEC-[A-Z0-9-]+$/);
  }
});

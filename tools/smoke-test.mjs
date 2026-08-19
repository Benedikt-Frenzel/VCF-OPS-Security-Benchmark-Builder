#!/usr/bin/env node
// Minimal dependency-free smoke test: node tools/smoke-test.mjs
// Guards the resilience invariants of index.html and the integrity of rules.js.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;

function check(name, cond) {
  if (cond) {
    console.log(`ok   - ${name}`);
  } else {
    failures++;
    console.error(`FAIL - ${name}`);
  }
}

// --- rules.js: parses, non-empty, unique ids, required fields ---
const rulesSrc = readFileSync(join(root, "rules.js"), "utf8");
// `const RULES_DATA` is lexical and does not attach to the vm global,
// so append an expression whose completion value hands us the rules.
const rules = vm.runInNewContext(rulesSrc + "\n;RULES_DATA.rules", {});

check("rules.js exposes RULES_DATA.rules as a non-empty array", Array.isArray(rules) && rules.length > 0);

const ids = new Set(rules.map((r) => r.id));
check("rule ids are unique", ids.size === rules.length);

check(
  "every rule has id, conditionKey, resource, description, operator",
  rules.every((r) => r.id && r.conditionKey && r.resource && r.description && r.operator)
);

// --- index.html: resilience invariants ---
const html = readFileSync(join(root, "index.html"), "utf8");

check(
  "rules.js bootstrap guard: RULES stays null when data file is missing/corrupt",
  /const RULES = typeof RULES_DATA !== "undefined"/.test(html) && html.includes(": null;")
);

check("localStorage backup key is written alongside every save", html.includes('STORE_KEY + ".backup"'));

check("v1 -> v2 migration path exists", html.includes("STORE_KEY_V1") && html.includes("readStore(STORE_KEY_V1)"));

check("saves are debounced", /saveTimer\s*=\s*setTimeout/.test(html));

check(
  "pending saves flush on download/beforeunload/visibilitychange",
  html.includes("beforeunload") && html.includes("visibilitychange") && html.includes("flushSave")
);

check("ruleById map replaces per-edit RULES.find() scans", html.includes("const ruleById = new Map("));

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall checks passed");

#!/usr/bin/env node
/**
 * Guard for the dependency CVE gate (scripts/audit-gate.mjs).
 *
 * The gate decides whether a required status check goes green, so its own
 * failure modes need a test — a gate that silently passes is indistinguishable
 * from a healthy repo right up until it isn't. Every case below asserts a
 * FAIL-CLOSED property: the gate must refuse to pass on bad input, not shrug.
 *
 * Deliberately uses no test framework and no network — same shape as
 * scripts/lighthouse-profiles.test.mjs.
 *
 * Run: node scripts/audit-gate.test.mjs
 */

import { ALLOWLIST, collectAdvisories, evaluate, findExpired } from "./audit-gate.mjs";

let pass = 0;
let fail = 0;

function check(label, fn) {
  try {
    fn();
    pass++;
    console.log(`  [32m✓[0m ${label}`);
  } catch (err) {
    fail++;
    console.log(`  [31m✗[0m ${label}`);
    console.log(`      ${err.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function throws(fn, label) {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  assert(threw, `expected ${label} to throw, it did not — that is a fail-OPEN path`);
}

/** Minimal npm-audit-shaped payload. */
function payload(vulns) {
  return JSON.stringify({ vulnerabilities: vulns });
}

function advisory(id, title = "t") {
  return { url: `https://github.com/advisories/${id}`, title };
}

console.log("=== audit-gate guard ===\n");

// --- Fail-closed on malformed input -----------------------------------------

check("throws on non-JSON input", () => {
  throws(() => collectAdvisories("not json at all"), "garbage input");
});

check("throws on empty string", () => {
  throws(() => collectAdvisories(""), "empty payload");
});

check("throws when the `vulnerabilities` key is absent", () => {
  // The dangerous case: valid JSON that simply has no findings key. Treating
  // this as "zero vulnerabilities" is the classic fail-open bug.
  throws(() => collectAdvisories(JSON.stringify({ metadata: {} })), "payload without findings key");
});

check("throws when the payload is a bare array", () => {
  throws(() => collectAdvisories("[]"), "array payload");
});

// --- Advisory collection ----------------------------------------------------

check("collects a high advisory by its GHSA id", () => {
  const raw = payload({ foo: { severity: "high", name: "foo", via: [advisory("GHSA-aaaa")] } });
  const found = collectAdvisories(raw);
  assert(found.has("GHSA-aaaa"), "expected GHSA-aaaa to be collected");
});

check("ignores moderate and low severities", () => {
  const raw = payload({
    a: { severity: "moderate", name: "a", via: [advisory("GHSA-mod")] },
    b: { severity: "low", name: "b", via: [advisory("GHSA-low")] },
  });
  assert(collectAdvisories(raw).size === 0, "moderate/low must not be gated");
});

check("includes critical, not just high", () => {
  const raw = payload({ a: { severity: "critical", name: "a", via: [advisory("GHSA-crit")] } });
  assert(collectAdvisories(raw).has("GHSA-crit"), "critical must be gated");
});

check("string `via` entries contribute no advisory id", () => {
  // This is the transitive-parent case: npm marks `next` high purely because
  // sharp is, with via: ["sharp"] and no advisory object. Matching on package
  // name here would suppress far more than intended.
  const raw = payload({ next: { severity: "high", name: "next", via: ["sharp"] } });
  assert(collectAdvisories(raw).size === 0, "a parent pointer must not become an advisory");
});

check("the same advisory reached twice is counted once", () => {
  const raw = payload({
    a: { severity: "high", name: "a", via: [advisory("GHSA-dup")] },
    b: { severity: "high", name: "b", via: [advisory("GHSA-dup")] },
  });
  assert(collectAdvisories(raw).size === 1, "advisories must be deduplicated by id");
});

// --- Allowlist evaluation ---------------------------------------------------

const LIST = [
  { id: "GHSA-known", pkg: "p", devOnly: false, expires: "2099-01-01", reason: "r" },
];

check("an unlisted advisory is reported as unaccepted", () => {
  const raw = payload({ x: { severity: "high", name: "x", via: [advisory("GHSA-surprise")] } });
  const r = evaluate(raw, LIST, "2026-07-27");
  assert(r.unlisted.length === 1, "an unlisted advisory must not pass");
  assert(r.unlisted[0].id === "GHSA-surprise", "wrong advisory reported");
});

check("a listed, unexpired advisory is suppressed rather than failed", () => {
  const raw = payload({ x: { severity: "high", name: "p", via: [advisory("GHSA-known")] } });
  const r = evaluate(raw, LIST, "2026-07-27");
  assert(r.unlisted.length === 0, "a listed advisory must not fail the gate");
  assert(r.suppressed.length === 1, "a listed advisory must be reported as suppressed");
});

check("an expired entry fails EVEN IF its advisory is gone", () => {
  // The whole point of the expiry: it forces a revisit rather than letting a
  // temporary acceptance become permanent silence.
  const expiring = [{ id: "GHSA-old", pkg: "p", devOnly: false, expires: "2026-01-01", reason: "r" }];
  const r = evaluate(payload({}), expiring, "2026-07-27");
  assert(r.expired.length === 1, "an expired entry must fail even with a clean audit");
});

check("an entry expiring exactly today is still valid", () => {
  const sameDay = [{ id: "GHSA-t", pkg: "p", devOnly: false, expires: "2026-07-27", reason: "r" }];
  assert(findExpired(sameDay, "2026-07-27").length === 0, "expiry must be inclusive of its own day");
});

check("throws on an allowlist entry missing a reason", () => {
  throws(() => findExpired([{ id: "GHSA-x", expires: "2099-01-01" }], "2026-07-27"), "reasonless entry");
});

check("throws on a malformed expiry date", () => {
  throws(
    () => findExpired([{ id: "GHSA-x", expires: "31.10.2026", reason: "r" }], "2026-07-27"),
    "non-ISO date",
  );
});

// --- The real allowlist -----------------------------------------------------

check("the shipped allowlist is well-formed and unexpired today", () => {
  const today = new Date().toISOString().slice(0, 10);
  const expired = findExpired(ALLOWLIST, today);
  assert(expired.length === 0, `expired entries: ${expired.map((e) => e.id).join(", ")}`);
});

check("every shipped allowlist entry carries a substantive reason", () => {
  for (const e of ALLOWLIST) {
    assert(e.reason.length > 60, `${e.id} has a token reason — say why it cannot be fixed`);
  }
});

check("shipped allowlist ids are unique", () => {
  const ids = ALLOWLIST.map((e) => e.id);
  assert(new Set(ids).size === ids.length, "duplicate ids in the allowlist");
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

import test from "node:test";
import assert from "node:assert/strict";
import { evaluateHeaders } from "../src/audit.mjs";

test("awards a full score to a hardened HTTPS response", () => {
  const result = evaluateHeaders({
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin"
  }, "https:");
  assert.equal(result.score, 100);
  assert.equal(result.grade, "A");
});

test("detects missing protections and cookie flags", () => {
  const result = evaluateHeaders({ "set-cookie": ["session=abc; Path=/"] }, "http:");
  assert.equal(result.score, 0);
  assert.equal(result.grade, "F");
  assert.deepEqual(result.cookies[0], { name: "session", secure: false, httpOnly: false, sameSite: null });
});

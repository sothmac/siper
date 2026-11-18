#!/usr/bin/env node
import { auditUrl } from "./audit.mjs";

const target = process.argv[2];
if (!target) {
  console.error("Usage: npm run audit -- https://example.com");
  process.exit(1);
}

try {
  const report = await auditUrl(target);
  console.log(`\nSiper report for ${report.finalUrl}`);
  console.log(`Score: ${report.score}/100 (${report.grade}) | HTTP ${report.status}`);
  console.log(`TLS: ${report.certificate ? `${report.certificate.daysRemaining} days remaining` : "not in use"}\n`);
  for (const item of report.findings) {
    console.log(`${item.passed ? "PASS" : "FAIL"}  ${item.title}${item.passed ? "" : ` — ${item.guidance}`}`);
  }
  if (report.cookies.length) {
    console.log("\nCookies:");
    for (const cookie of report.cookies) {
      console.log(`- ${cookie.name}: Secure=${cookie.secure} HttpOnly=${cookie.httpOnly} SameSite=${cookie.sameSite ?? "missing"}`);
    }
  }
} catch (error) {
  console.error(`Audit failed: ${error.message}`);
  process.exit(1);
}

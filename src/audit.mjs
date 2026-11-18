import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 10_000;

function isPrivateIp(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224;
  }

  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase();
    return normalized === "::" || normalized === "::1" ||
      normalized.startsWith("fc") || normalized.startsWith("fd") ||
      normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
      normalized.startsWith("fea") || normalized.startsWith("feb") ||
      normalized.startsWith("ff");
  }

  return true;
}

async function resolvePublicAddress(hostname) {
  const answers = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!answers.length || answers.some(({ address }) => isPrivateIp(address))) {
    throw new Error("Private, local, or unresolved addresses are not allowed.");
  }
  return answers[0];
}

function requestHeaders(url, resolved) {
  const client = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = client.request(url, {
      method: "GET",
      headers: {
        "User-Agent": "Siper-Web-Audit/0.1 (+passive-security-audit)",
        Accept: "text/html,*/*;q=0.1"
      },
      lookup: (_hostname, options, callback) => {
        if (options?.all) {
          callback(null, [{ address: resolved.address, family: resolved.family }]);
          return;
        }
        callback(null, resolved.address, resolved.family);
      }
    }, (response) => {
      const result = {
        status: response.statusCode ?? 0,
        headers: response.headers,
        rawHeaders: response.rawHeaders
      };
      response.destroy();
      resolve(result);
    });
    req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy(new Error("Request timed out.")));
    req.on("error", reject);
    req.end();
  });
}

async function followRedirects(input) {
  let current = new URL(input);
  const chain = [];

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    if (!["http:", "https:"].includes(current.protocol)) {
      throw new Error("Only HTTP and HTTPS URLs are supported.");
    }
    if (current.username || current.password) {
      throw new Error("Credentials in URLs are not allowed.");
    }

    const resolved = await resolvePublicAddress(current.hostname);
    const response = await requestHeaders(current, resolved);
    chain.push({ url: current.href, status: response.status });

    if (response.status < 300 || response.status >= 400 || !response.headers.location) {
      return { finalUrl: current, response, chain, resolved };
    }
    current = new URL(response.headers.location, current);
  }
  throw new Error(`Too many redirects (maximum ${MAX_REDIRECTS}).`);
}

function finding(id, title, passed, weight, guidance, evidence = null) {
  return { id, title, passed, weight, guidance, evidence };
}

export function evaluateHeaders(headers, protocol = "https:") {
  const h = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])
  );
  const csp = String(h["content-security-policy"] ?? "");
  const cookies = Array.isArray(h["set-cookie"])
    ? h["set-cookie"]
    : h["set-cookie"] ? [h["set-cookie"]] : [];

  const findings = [
    finding("https", "HTTPS is in use", protocol === "https:", 20,
      "Serve the entire site over HTTPS and redirect HTTP to HTTPS."),
    finding("hsts", "Strict-Transport-Security", Boolean(h["strict-transport-security"]), 15,
      "Add HSTS after confirming every subdomain supports HTTPS.", h["strict-transport-security"]),
    finding("csp", "Content-Security-Policy", Boolean(csp), 20,
      "Define a restrictive CSP and avoid broad wildcards or unsafe-inline where possible.", csp || null),
    finding("nosniff", "X-Content-Type-Options", String(h["x-content-type-options"]).toLowerCase() === "nosniff", 10,
      "Set X-Content-Type-Options: nosniff.", h["x-content-type-options"]),
    finding("framing", "Clickjacking protection", Boolean(h["x-frame-options"]) || /frame-ancestors/i.test(csp), 10,
      "Use CSP frame-ancestors (preferred) or X-Frame-Options.", h["x-frame-options"]),
    finding("referrer", "Referrer-Policy", Boolean(h["referrer-policy"]), 8,
      "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.", h["referrer-policy"]),
    finding("permissions", "Permissions-Policy", Boolean(h["permissions-policy"]), 7,
      "Disable browser capabilities the site does not need.", h["permissions-policy"]),
    finding("coop", "Cross-Origin-Opener-Policy", Boolean(h["cross-origin-opener-policy"]), 5,
      "Consider same-origin isolation where compatible.", h["cross-origin-opener-policy"]),
    finding("corp", "Cross-Origin-Resource-Policy", Boolean(h["cross-origin-resource-policy"]), 5,
      "Restrict which origins may embed site resources.", h["cross-origin-resource-policy"])
  ];

  const cookieFindings = cookies.map((cookie) => ({
    name: cookie.split("=", 1)[0],
    secure: /;\s*secure(?:;|$)/i.test(cookie),
    httpOnly: /;\s*httponly(?:;|$)/i.test(cookie),
    sameSite: /;\s*samesite=(strict|lax|none)(?:;|$)/i.exec(cookie)?.[1] ?? null
  }));

  const score = findings.reduce((sum, item) => sum + (item.passed ? item.weight : 0), 0);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade, findings, cookies: cookieFindings };
}

async function inspectCertificate(url, resolved) {
  if (url.protocol !== "https:") return null;
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: resolved.address,
      port: Number(url.port || 443),
      servername: url.hostname,
      rejectUnauthorized: true,
      timeout: REQUEST_TIMEOUT_MS
    }, () => {
      const cert = socket.getPeerCertificate();
      resolve({
        authorized: socket.authorized,
        issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
        subject: cert.subject?.CN ?? null,
        validFrom: cert.valid_from ?? null,
        validTo: cert.valid_to ?? null,
        daysRemaining: cert.valid_to
          ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000)
          : null
      });
      socket.end();
    });
    socket.on("timeout", () => socket.destroy(new Error("TLS inspection timed out.")));
    socket.on("error", reject);
  });
}

export async function auditUrl(input) {
  const normalized = /^[a-z][a-z\d+.-]*:/i.test(input) ? input : `https://${input}`;
  const { finalUrl, response, chain, resolved } = await followRedirects(normalized);
  const assessment = evaluateHeaders(response.headers, finalUrl.protocol);
  const certificate = await inspectCertificate(finalUrl, resolved);

  return {
    auditedAt: new Date().toISOString(),
    requestedUrl: normalized,
    finalUrl: finalUrl.href,
    status: response.status,
    redirectChain: chain,
    resolvedAddress: resolved.address,
    certificate,
    ...assessment,
    disclaimer: "Passive configuration review only. Results are not a penetration test."
  };
}

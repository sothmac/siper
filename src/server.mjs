import { createReadStream } from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { auditUrl } from "./audit.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../public");
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 12);
const requestCounts = new Map();
const staticAssets = new Map([
  ["/assets/siper-wordmark.png", "assets/siper-wordmark.png"],
  ["/assets/siper-icon.png", "assets/siper-icon.png"]
]);

function sendJson(response, status, value) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type"
  });
  response.end(JSON.stringify(value));
}

const server = http.createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type"
    });
    response.end();
    return;
  }

  if (request.method === "GET" && request.url === "/") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    createReadStream(path.join(root, "index.html")).pipe(response);
    return;
  }

  if (request.method === "GET" && request.url === "/health") {
    sendJson(response, 200, { status: "ok" });
    return;
  }

  if (request.method === "GET" && staticAssets.has(request.url)) {
    response.writeHead(200, {
      "content-type": "image/png",
      "cache-control": "public, max-age=86400"
    });
    createReadStream(path.join(root, staticAssets.get(request.url))).pipe(response);
    return;
  }

  if (request.method === "POST" && request.url === "/api/audit") {
    const clientAddress = request.socket.remoteAddress || "unknown";
    const now = Date.now();
    const current = requestCounts.get(clientAddress);
    if (!current || now - current.startedAt >= RATE_LIMIT_WINDOW_MS) {
      requestCounts.set(clientAddress, { count: 1, startedAt: now });
    } else if (current.count >= RATE_LIMIT_MAX) {
      response.setHeader("retry-after", "60");
      sendJson(response, 429, { error: "Too many audit requests. Please try again in a minute." });
      return;
    } else {
      current.count += 1;
    }

    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 10_000) request.destroy();
    });
    request.on("end", async () => {
      try {
        const { url } = JSON.parse(body);
        if (typeof url !== "string" || !url.trim()) throw new Error("A URL is required.");
        sendJson(response, 200, await auditUrl(url.trim()));
      } catch (error) {
        sendJson(response, 400, { error: error.message });
      }
    });
    return;
  }

  sendJson(response, 404, { error: "Not found" });
});

server.listen(port, host, () => {
  console.log(`Siper is running at http://${host}:${port}`);
});

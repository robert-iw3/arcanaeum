#!/usr/bin/env node
/**
 * rustunnel demo server — zero dependencies, pure Node.js http module.
 * Usage: node server.js [port]   (default port: 3000)
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = parseInt(process.argv[2] || process.env.PORT || "3000", 10);

// ── in-memory request counter ─────────────────────────────────────────────────

let requestCount = 0;
const recentRequests = [];

function recordRequest(req) {
  requestCount++;
  recentRequests.unshift({
    id: requestCount,
    method: req.method,
    path: req.url,
    time: new Date().toISOString(),
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown",
    ua: req.headers["user-agent"] || "",
  });
  if (recentRequests.length > 10) recentRequests.pop();
}

// ── MIME types ────────────────────────────────────────────────────────────────

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css",
  ".js":   "application/javascript",
  ".json": "application/json",
  ".png":  "image/png",
  ".ico":  "image/x-icon",
  ".svg":  "image/svg+xml",
};

// ── API routes ────────────────────────────────────────────────────────────────

function handleApi(req, res, pathname) {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (pathname === "/api/status") {
    res.writeHead(200);
    res.end(JSON.stringify({
      ok: true,
      uptime_seconds: Math.floor(process.uptime()),
      request_count: requestCount,
      node_version: process.version,
      timestamp: new Date().toISOString(),
    }, null, 2));
    return true;
  }

  if (pathname === "/api/requests") {
    res.writeHead(200);
    res.end(JSON.stringify({ total: requestCount, recent: recentRequests }, null, 2));
    return true;
  }

  if (pathname === "/api/echo") {
    const q = Object.fromEntries(new URL(req.url, "http://localhost").searchParams);
    res.writeHead(200);
    res.end(JSON.stringify({
      message: q.msg || "hello from rustunnel demo!",
      headers: req.headers,
      method: req.method,
    }, null, 2));
    return true;
  }

  return false;
}

// ── static file server ────────────────────────────────────────────────────────

function serveStatic(res, filePath) {
  const ext = path.extname(filePath);
  const mime = MIME[ext] || "text/plain";

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end(page404());
      return;
    }
    res.writeHead(200, { "Content-Type": mime });
    res.end(data);
  });
}

// ── request handler ───────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  recordRequest(req);

  const parsed = new URL(req.url, "http://localhost");
  const pathname = parsed.pathname.replace(/\/+$/, "") || "/";

  // API
  if (pathname.startsWith("/api/")) {
    if (!handleApi(req, res, pathname)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    }
    return;
  }

  // Map routes to HTML files
  const routeMap = {
    "/":        "index.html",
    "/about":   "about.html",
    "/live":    "live.html",
    "/api-demo": "api-demo.html",
  };

  const file = routeMap[pathname];
  if (file) {
    serveStatic(res, path.join(__dirname, "public", file));
    return;
  }

  // Try as static file
  const filePath = path.join(__dirname, "public", pathname);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    serveStatic(res, filePath);
    return;
  }

  res.writeHead(404, { "Content-Type": "text/html" });
  res.end(page404());
});

// ── 404 page ──────────────────────────────────────────────────────────────────

function page404() {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>404 — Not Found</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/style.css"></head>
<body>
  <nav><a href="/">Home</a><a href="/about">About</a><a href="/live">Live</a><a href="/api-demo">API</a></nav>
  <main class="center">
    <div class="card">
      <h1 class="error">404</h1>
      <p>Page not found.</p>
      <a href="/" class="btn">Go home</a>
    </div>
  </main>
</body></html>`;
}

// ── start ─────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n  rustunnel demo server`);
  console.log(`  ─────────────────────────────────`);
  console.log(`  Local:  http://localhost:${PORT}`);
  console.log(`\n  Expose it with:\n`);
  console.log(`    rustunnel http ${PORT} --subdomain demo\n`);
});

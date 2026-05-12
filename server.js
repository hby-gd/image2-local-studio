const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const { URL } = require("node:url");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8787);
const ROOT = __dirname;
const UPSTREAM_HTTP_AGENT = new http.Agent({ keepAlive: true });
const UPSTREAM_HTTPS_AGENT = new https.Agent({ keepAlive: true });
const MAX_UPSTREAM_RETRIES = 2;

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
};

function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Upstream-Url");
  res.setHeader("Access-Control-Expose-Headers", "Content-Length, Content-Type");
}

function sendJson(res, statusCode, payload) {
  setCorsHeaders(res);
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function getUpstreamUrl(req) {
  const headerUrl = req.headers["x-upstream-url"];
  if (headerUrl) {
    return String(headerUrl);
  }

  const currentUrl = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
  return currentUrl.searchParams.get("url") || "";
}

function sanitizeProxyHeaders(headers, bodyBuffer) {
  const nextHeaders = {};

  for (const [key, value] of Object.entries(headers)) {
    if (value == null) {
      continue;
    }

    const lowerKey = key.toLowerCase();
    if (["host", "origin", "referer", "connection", "x-upstream-url", "content-length"].includes(lowerKey)) {
      continue;
    }

    if (lowerKey.startsWith("sec-fetch-") || lowerKey === "sec-ch-ua" || lowerKey === "sec-ch-ua-mobile" || lowerKey === "sec-ch-ua-platform") {
      continue;
    }

    nextHeaders[key] = value;
  }

  if (bodyBuffer.length > 0) {
    nextHeaders["Content-Length"] = String(bodyBuffer.length);
  }

  return nextHeaders;
}

function shouldRetryUpstreamError(error) {
  const code = String(error?.code || "");
  const message = String(error?.message || "");
  return (
    ["ECONNRESET", "ETIMEDOUT", "ECONNREFUSED", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT"].includes(code) ||
    /before secure TLS connection was established/i.test(message) ||
    /socket hang up/i.test(message)
  );
}

function proxyRequest(targetUrl, req, res, bodyBuffer, redirectCount = 0, retryCount = 0) {
  const target = new URL(targetUrl);
  const client = target.protocol === "https:" ? https : http;
  const headers = sanitizeProxyHeaders(req.headers, bodyBuffer);

  const upstreamReq = client.request(
    target,
    {
      method: req.method,
      headers,
      servername: target.hostname,
      agent: target.protocol === "https:" ? UPSTREAM_HTTPS_AGENT : UPSTREAM_HTTP_AGENT,
    },
    (upstreamRes) => {
      const statusCode = upstreamRes.statusCode || 502;
      const location = upstreamRes.headers.location;

      if (location && statusCode >= 300 && statusCode < 400 && redirectCount < 5) {
        const redirectUrl = new URL(location, target).toString();
        upstreamRes.resume();
        proxyRequest(redirectUrl, req, res, bodyBuffer, redirectCount + 1, retryCount);
        return;
      }

      setCorsHeaders(res);
      const responseHeaders = { ...upstreamRes.headers };
      delete responseHeaders["access-control-allow-origin"];
      delete responseHeaders["access-control-allow-credentials"];
      res.writeHead(statusCode, responseHeaders);
      upstreamRes.pipe(res);
    },
  );

  upstreamReq.on("error", (error) => {
    if (!res.headersSent && retryCount < MAX_UPSTREAM_RETRIES && shouldRetryUpstreamError(error)) {
      setTimeout(() => {
        proxyRequest(targetUrl, req, res, bodyBuffer, redirectCount, retryCount + 1);
      }, 300 * (retryCount + 1));
      return;
    }

    if (!res.headersSent) {
      sendJson(res, 502, {
        error: {
          message: `代理请求失败：${error.message}${retryCount > 0 ? `（已重试 ${retryCount} 次）` : ""}`,
        },
      });
    } else {
      res.destroy(error);
    }
  });

  if (bodyBuffer.length > 0) {
    upstreamReq.write(bodyBuffer);
  }
  upstreamReq.end();
}

function serveStatic(req, res) {
  const requestUrl = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
  const pathname = decodeURIComponent(requestUrl.pathname === "/" ? "/index.html" : requestUrl.pathname);
  const resolvedPath = path.normalize(path.join(ROOT, pathname));

  if (!resolvedPath.startsWith(ROOT)) {
    sendJson(res, 403, { error: { message: "禁止访问该路径。" } });
    return;
  }

  fs.readFile(resolvedPath, (error, content) => {
    if (error) {
      sendJson(res, error.code === "ENOENT" ? 404 : 500, {
        error: { message: error.code === "ENOENT" ? "文件不存在。" : "读取文件失败。" },
      });
      return;
    }

    const ext = path.extname(resolvedPath).toLowerCase();
    setCorsHeaders(res);
    res.writeHead(200, { "Content-Type": CONTENT_TYPES[ext] || "application/octet-stream" });
    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  if (!req.url) {
    sendJson(res, 400, { error: { message: "缺少请求地址。" } });
    return;
  }

  if (req.method === "OPTIONS") {
    setCorsHeaders(res);
    res.writeHead(204);
    res.end();
    return;
  }

  const requestUrl = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);

  if (requestUrl.pathname === "/health") {
    sendJson(res, 200, {
      ok: true,
      host: HOST,
      port: PORT,
      now: new Date().toISOString(),
    });
    return;
  }

  if (requestUrl.pathname === "/proxy") {
    const upstreamUrl = getUpstreamUrl(req);
    if (!upstreamUrl) {
      sendJson(res, 400, { error: { message: "缺少 X-Upstream-Url 或 ?url= 参数。" } });
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(upstreamUrl);
    } catch {
      sendJson(res, 400, { error: { message: "上游地址格式不合法。" } });
      return;
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      sendJson(res, 400, { error: { message: "只支持 http/https 上游地址。" } });
      return;
    }

    try {
      const bodyBuffer = await readRequestBody(req);
      proxyRequest(parsedUrl.toString(), req, res, bodyBuffer);
    } catch (error) {
      sendJson(res, 500, { error: { message: `读取请求体失败：${error.message}` } });
    }
    return;
  }

  if (!["GET", "HEAD"].includes(req.method || "GET")) {
    sendJson(res, 405, { error: { message: "仅支持 GET/HEAD 静态文件请求。" } });
    return;
  }

  serveStatic(req, res);
});

server.listen(PORT, HOST, () => {
  console.log(`Image 2 Local Studio proxy running at http://${HOST}:${PORT}`);
  console.log(`Open http://${HOST}:${PORT} in your browser`);
});

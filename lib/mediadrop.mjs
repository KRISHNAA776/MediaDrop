// MediaDrop server: zero dependencies, Node >= 18. See README.md (kept out of the repo root so Vercel does not treat it as an app entrypoint)
import http from "node:http";
import https from "node:https";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import dns from "node:dns/promises";
import net from "node:net";
import crypto from "node:crypto";

const MAX_BYTES = +process.env.MAX_BYTES || 500e6,
  TTL = 10 * 60e3;
const ALLOW_DIRECT = process.env.ALLOW_DIRECT_FILES !== "false",
  META = process.env.META_OEMBED_TOKEN;
const SECRET =
  process.env.LINK_SECRET || crypto.randomBytes(32).toString("hex");
const NOT_AVAIL =
  "Direct downloading is not available for this link. You can open it on the original platform or use an authorized media file.";
const q = encodeURIComponent;

// ---- Provider adapters. Each declares exactly what it supports. Recognition != authorization. ----
const caps = { metadata: true, preview: true, download: false, audio: false };
const P = {
  youtube: {
    name: "YouTube",
    hosts: ["youtube.com", "youtu.be"],
    caps,
    oembed: (u) => `https://www.youtube.com/oembed?format=json&url=${q(u)}`,
  },
  vimeo: {
    name: "Vimeo",
    hosts: ["vimeo.com"],
    caps,
    oembed: (u) => `https://vimeo.com/api/oembed.json?url=${q(u)}`,
  },
  x: {
    name: "X",
    hosts: ["x.com", "twitter.com"],
    caps,
    oembed: (u) => `https://publish.twitter.com/oembed?url=${q(u)}`,
  },
  tiktok: {
    name: "TikTok",
    hosts: ["tiktok.com"],
    caps,
    oembed: (u) => `https://www.tiktok.com/oembed?url=${q(u)}`,
  },
  reddit: {
    name: "Reddit",
    hosts: ["reddit.com", "redd.it"],
    caps,
    oembed: (u) => `https://www.reddit.com/oembed?url=${q(u)}`,
  },
  facebook: {
    name: "Facebook",
    hosts: ["facebook.com", "fb.watch"],
    caps,
    needsToken: true,
    oembed: (u) =>
      `https://graph.facebook.com/v19.0/oembed_video?access_token=${META}&url=${q(u)}`,
  },
  instagram: {
    name: "Instagram",
    hosts: ["instagram.com"],
    caps,
    needsToken: true,
    oembed: (u) =>
      `https://graph.facebook.com/v19.0/instagram_oembed?access_token=${META}&url=${q(u)}`,
  },
};
const SHORT = [
  "youtu.be",
  "fb.watch",
  "redd.it",
  "vm.tiktok.com",
  "vt.tiktok.com",
];
const matchHost = (h, list) => list.some((d) => h === d || h.endsWith("." + d));
const detect = (h) =>
  Object.keys(P).find((id) => matchHost(h, P[id].hosts)) || null;
const hostOk = (h) => !!detect(h);

// ---- SSRF defence: https only, port 443, DNS result validated at connect time (defeats rebinding), manual redirects re-checked ----
function isPublic(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0)) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }
  const l = ip.toLowerCase();
  if (l.startsWith("::ffff:"))
    return l.includes(".") ? isPublic(l.slice(7)) : false;
  return (
    net.isIPv6(l) &&
    !(
      l === "::" ||
      l === "::1" ||
      /^f[cd]/.test(l) ||
      /^fe[89ab]/.test(l) ||
      l.startsWith("ff")
    )
  );
}
function guarded(host, opts, cb) {
  dns.lookup(host, { all: true }).then((rs) => {
    if (!rs.length || !rs.every((r) => isPublic(r.address)))
      return cb(new Error("blocked_address"));
    opts && opts.all ? cb(null, rs) : cb(null, rs[0].address, rs[0].family);
  }, cb);
}
function get(
  urlStr,
  { method = "GET", headers = {}, any = false } = {},
  hop = 0,
) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(urlStr);
    } catch {
      return reject(new Error("bad_url"));
    }
    if (
      u.protocol !== "https:" ||
      (u.port && u.port !== "443") ||
      u.username ||
      u.password
    )
      return reject(new Error("bad_url"));
    const hn = u.hostname.replace(/^\[|\]$/g, ""); // IP literals skip the DNS lookup hook, so check them here
    if (net.isIP(hn) && !isPublic(hn))
      return reject(new Error("blocked_address"));
    if (!any && !hostOk(u.hostname)) return reject(new Error("blocked_host"));
    const req = https.request(
      u,
      {
        method,
        headers: { "user-agent": "MediaDropBot/1.0", ...headers },
        lookup: guarded,
        timeout: 10000,
      },
      (res) => {
        if (
          [301, 302, 303, 307, 308].includes(res.statusCode) &&
          res.headers.location
        ) {
          res.resume();
          if (hop >= 3) return reject(new Error("too_many_redirects"));
          return resolve(
            get(
              new URL(res.headers.location, u).href,
              { method, headers, any },
              hop + 1,
            ),
          );
        }
        res.finalUrl = u.href;
        resolve(res);
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}
const readBody = (res, max = 1e6) =>
  new Promise((ok, no) => {
    let n = 0;
    const b = [];
    res.on("data", (c) => {
      n += c.length;
      if (n > max) {
        res.destroy();
        no(new Error("too_large"));
      } else b.push(c);
    });
    res.on("end", () => ok(Buffer.concat(b).toString()));
    res.on("error", no);
  });

// ---- Expiring signed download tokens ----
const mac = (s) =>
  crypto.createHmac("sha256", SECRET).update(s).digest("base64url");
const sign = (url) => {
  const p = Buffer.from(
    JSON.stringify({ u: url, e: Date.now() + TTL }),
  ).toString("base64url");
  return `${p}.${mac(p)}`;
};
function verify(t = "") {
  const [p, m] = t.split(".");
  if (!p || !m) return null;
  const a = Buffer.from(m),
    b = Buffer.from(mac(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const d = JSON.parse(Buffer.from(p, "base64url"));
    return d.e > Date.now() ? d.u : null;
  } catch {
    return null;
  }
}

const fail = (status, error, message, extra = {}) => ({
  ok: false,
  status,
  error,
  message,
  ...extra,
});
const MEDIA_EXT = /\.(mp4|webm|mov|m4v|mp3|m4a|aac|wav|ogg|opus|flac)$/i;

async function analyze(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    return fail(400, "invalid_url", "That does not look like a valid link.");
  }
  if (u.protocol === "http:") u.protocol = "https:";
  if (u.protocol !== "https:" || u.username || u.password)
    return fail(400, "invalid_url", "Only HTTPS links are accepted.");
  const id = detect(u.hostname.toLowerCase());
  try {
    if (id) {
      const p = P[id];
      let target = u.href;
      if (SHORT.includes(u.hostname.toLowerCase())) {
        const r = await get(u.href, { method: "HEAD" });
        r.resume();
        target = r.finalUrl;
      }
      if (p.needsToken && !META)
        return fail(
          503,
          "not_configured",
          `${p.name} metadata needs a Meta app token (META_OEMBED_TOKEN), which is not configured on this server.`,
          { platformName: p.name, officialUrl: target },
        );
      const r = await get(p.oembed(target));
      const body = await readBody(r);
      if (r.statusCode !== 200)
        return fail(
          404,
          "unavailable",
          `${p.name} did not return information for this link. It may be private, removed, or restricted.`,
          { platformName: p.name, officialUrl: target },
        );
      const d = JSON.parse(body);
      return {
        ok: true,
        platform: id,
        platformName: p.name,
        officialUrl: target,
        capabilities: p.caps,
        meta: {
          title: d.title || null,
          author: d.author_name || null,
          thumbnail: /^https:\/\//.test(d.thumbnail_url || "")
            ? d.thumbnail_url
            : null,
        },
        formats: [],
        notice: `${NOT_AVAIL} ${p.name} does not offer a permitted direct-download integration in MediaDrop.`,
      };
    }
    if (ALLOW_DIRECT && MEDIA_EXT.test(u.pathname)) {
      const r = await get(u.href, { method: "HEAD", any: true });
      r.resume();
      const type = String(r.headers["content-type"] || "").split(";")[0],
        size = +r.headers["content-length"] || null;
      if (r.statusCode !== 200 || !/^(video|audio)\//.test(type))
        return fail(
          404,
          "unavailable",
          "The file is not reachable or is not a video/audio file.",
        );
      if (size && size > MAX_BYTES)
        return fail(
          413,
          "too_large",
          `File exceeds the ${Math.round(MAX_BYTES / 1e6)} MB limit.`,
        );
      return {
        ok: true,
        platform: "direct",
        platformName: "Direct media file",
        officialUrl: u.href,
        capabilities: {
          metadata: true,
          preview: false,
          download: true,
          audio: false,
        },
        meta: {
          title: decodeURIComponent(path.basename(u.pathname)),
          author: u.hostname,
          thumbnail: null,
        },
        formats: [
          {
            kind: type.startsWith("audio") ? "audio" : "video",
            label: "Original file",
            container: type,
            size,
            original: true,
            href: `/api/download?t=${sign(u.href)}`,
          },
        ],
        notice:
          "Original file, no conversion. Download only files you own or have permission to use.",
      };
    }
    return fail(
      422,
      "unsupported",
      "This link is not from a supported platform and does not point to a direct media file.",
    );
  } catch (e) {
    const m = {
      blocked_address:
        "This link points to a private or internal address and was blocked.",
      blocked_host: "That redirect leads somewhere that is not allowed.",
      timeout: "The source took too long to respond.",
    };
    return fail(
      502,
      "unreachable",
      m[e.message] || "Could not reach the source. Please try again later.",
    );
  }
}

async function download(t, out) {
  const url = verify(t);
  if (!url)
    return fail(
      410,
      "expired",
      "This download link is invalid or has expired. Analyze the link again.",
    );
  const up = await get(url, { any: true }),
    type = String(up.headers["content-type"] || "").split(";")[0],
    size = +up.headers["content-length"] || 0;
  if (up.statusCode !== 200 || !/^(video|audio)\//.test(type)) {
    up.resume();
    return fail(404, "unavailable", "The file is no longer available.");
  }
  if (size > MAX_BYTES) {
    up.resume();
    return fail(413, "too_large", "File is too large.");
  }
  const name =
    path.basename(new URL(url).pathname).replace(/[^\w.\- ]/g, "_") || "media";
  out.writeHead(200, {
    "content-type": type,
    "content-disposition": `attachment; filename="${name}"`,
    ...(size && { "content-length": size }),
    "cache-control": "no-store",
  });
  let n = 0;
  up.on("data", (c) => {
    n += c.length;
    if (n > MAX_BYTES) {
      up.destroy();
      out.destroy();
    }
  });
  up.on("error", () => out.destroy());
  up.pipe(out);
  return null;
}

const hits = new Map();
setInterval(() => hits.clear(), 6e5).unref();
const limited = (ip) => {
  const now = Date.now(),
    a = (hits.get(ip) || []).filter((t) => now - t < 6e4);
  a.push(now);
  hits.set(ip, a);
  return a.length > 20;
};
const send = (res, code, obj) => {
  res.writeHead(code, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(obj));
};
// Vercel Node.js serverless request handler for MediaDrop API routes.
export async function handler(req, res) {
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("x-frame-options", "DENY");
    res.setHeader(
      "content-security-policy",
      "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
    const url = new URL(req.url, `https://${req.headers.host || "localhost"}`),
      ip =
        (process.env.TRUST_PROXY
          ? String(req.headers["x-forwarded-for"] || "")
              .split(",")[0]
              .trim()
          : "") || req.socket.remoteAddress;
    try {
      if (url.pathname.startsWith("/api/")) {
        if (limited(ip))
          return send(
            res,
            429,
            fail(
              429,
              "rate_limited",
              "Too many requests. Please wait a minute.",
            ),
          );
        if (url.pathname === "/api/analyze" && req.method === "POST") {
          let body;
          try {
            body = JSON.parse(await readBody(req, 4096));
          } catch {
            return send(res, 400, fail(400, "bad_request", "Invalid request."));
          }
          const r = await analyze(body.url);
          return send(res, r.status || 200, r);
        }
        if (url.pathname === "/api/download" && req.method === "GET") {
          let r;
          try {
            r = await download(url.searchParams.get("t"), res);
          } catch {
            r = fail(502, "unreachable", "Could not fetch the file.");
          }
          if (r && !res.headersSent) return send(res, r.status, r);
          return;
        }
        return send(res, 404, fail(404, "not_found", "Not found."));
      }
      return send(res, 404, fail(404, "not_found", "Not found."));
    } catch {
      if (!res.headersSent)
        send(res, 500, fail(500, "server", "Something went wrong."));
      else res.destroy();
    }
}

// ---- Local server (node server.mjs). Not used on Vercel, which imports `handler` directly. ----
const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css" };
async function app(req, res) {
  const { pathname } = new URL(req.url, "http://localhost");
  if (pathname.startsWith("/api/")) return handler(req, res);
  const rel = pathname === "/" ? "index.html" : pathname.slice(1);
  const file = path.join(PUBLIC, path.normalize(rel));
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 404, fail(404, "not_found", "Not found."));
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, fail(404, "not_found", "Not found."));
    res.writeHead(200, {
      "content-type": TYPES[path.extname(file)] || "application/octet-stream",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    });
    res.end(data);
  });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const PORT = +process.env.PORT || 3000;
  http.createServer(app).listen(PORT, () => console.log(`MediaDrop running at http://localhost:${PORT}`));
}

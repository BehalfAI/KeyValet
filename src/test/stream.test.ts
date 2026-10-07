import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { dispatch, type SessionAuth } from "../helper/dispatch.js";
import { Gateway, StreamRedactor } from "../helper/gateway.js";
import { aggregateSse, redact, redactionList } from "../helper/http-proxy.js";
import { execFile } from "node:child_process";
import { cleanupGatewayEnv, recordSecrets, writeGatewayEnv, writeSecretFile } from "../server/gateway-env.js";
import { allowInsecureLoopbackForTests } from "../helper/protocols/http.js";
import { Vault } from "../helper/vault.js";

const SECRET = "sk-STREAM-SECRET-0123456789";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let port = 0;
let upstream: http.Server;
const seen: Array<{ url: string; headers: http.IncomingHttpHeaders; body: string }> = [];

before(async () => {
  allowInsecureLoopbackForTests(true);
  upstream = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      seen.push({ url: req.url!, headers: req.headers, body });
      const auth = String(req.headers.authorization ?? "");
      if (req.url === "/sse/openai") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        for (const piece of ["Hel", "lo ", "world"]) {
          res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: piece } }] })}\n\n`);
          await sleep(20);
        }
        res.write(`data: ${JSON.stringify({ echo: auth })}\n\n`);
        res.end("data: [DONE]\n\n");
      } else if (req.url === "/sse/split") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        const k = auth.replace("Bearer ", "");
        for (const piece of [k.slice(0, 7), k.slice(7)]) res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: piece } }] })}\n\n`);
        res.end("data: [DONE]\n\n");
      } else if (req.url === "/slow") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.write("data: first\n\n");
        await sleep(400);
        res.end("data: second\n\n");
      } else if (req.url === "/split") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        const k = auth.replace("Bearer ", "");
        res.write(`before ${k.slice(0, 9)}`);
        await sleep(50);
        res.end(`${k.slice(9)} after`);
      } else {
        res.writeHead(200, { "Content-Type": "application/json", "X-Echo": auth });
        res.end(JSON.stringify({ method: req.method, url: req.url, auth, body }));
      }
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  port = (upstream.address() as { port: number }).port;
});
after(() => {
  upstream.close();
  allowInsecureLoopbackForTests(false);
});

function freshVault(): Vault {
  const v = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kv-stream-")), "vault"));
  v.init();
  return v;
}

async function setCred(vault: Vault) {
  const r = await dispatch(
    vault,
    {
      id: 1,
      op: "set",
      params: {
        type: "llm",
        name: "main",
        secrets: { apiKey: SECRET },
        http: { inject: { headers: { Authorization: "Bearer {{apiKey}}" } }, allowed_hosts: ["127.0.0.1"] },
        purpose: "测试",
      },
    },
    {},
  );
  assert.ok(r.ok, JSON.stringify(r));
}

describe("SSE 流式响应（MCP 代理调用）", () => {
  it("拼出大模型增量文本，事件流中回显的秘密被抹掉", async () => {
    const vault = freshVault();
    await setCred(vault);
    const r = await dispatch(vault, { id: 2, op: "httpRequest", params: { type: "llm", name: "main", method: "POST", url: `http://127.0.0.1:${port}/sse/openai`, body: { stream: true }, purpose: "测试" } }, {});
    assert.ok(r.ok, JSON.stringify(r));
    const res = r.result as { stream: { events: number; text: string }; body: string };
    assert.deepEqual(res.stream, { events: 5, text: "Hello world" });
    assert.equal(JSON.stringify(res).includes(SECRET), false);
  });

  it("[审查] 拆在多个增量里的秘密，拼接后的 stream.text 中也被抹掉", async () => {
    const vault = freshVault();
    await setCred(vault);
    const r = await dispatch(vault, { id: 2, op: "httpRequest", params: { type: "llm", name: "main", method: "POST", url: `http://127.0.0.1:${port}/sse/split`, body: {}, purpose: "测试" } }, {});
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal((r.result as { stream: { text: string } }).stream.text, "[REDACTED]");
  });

  it("[审查] 小写化会改变长度的字符（İ）不能让脱敏错位", () => {
    const list = redactionList([SECRET]);
    for (const n of [1, 6, 40]) {
      const out = redact("İ".repeat(n) + SECRET + "zz", list);
      assert.equal(out, "İ".repeat(n) + "[REDACTED]zz");
    }
    assert.equal(redact("x(a+b)[c]", ["(a+b)[c]"]), "x[REDACTED]", "正则特殊字符被转义");
  });

  it("识别 Anthropic、Gemini、OpenAI Responses 格式；无法识别时 text 为 null", () => {
    const sse = (objs: unknown[]) => objs.map((o) => `event: x\ndata: ${JSON.stringify(o)}\n\n`).join("");
    assert.equal(aggregateSse(sse([{ type: "content_block_delta", delta: { type: "text_delta", text: "Hi " } }, { type: "content_block_delta", delta: { text: "there" } }])).text, "Hi there");
    assert.equal(aggregateSse(sse([{ candidates: [{ content: { parts: [{ text: "Gem" }, { text: "ini" }] } }] }])).text, "Gemini");
    assert.equal(aggregateSse(sse([{ type: "response.output_text.delta", delta: "Res" }, { type: "response.output_text.delta", delta: "ponses" }])).text, "Responses");
    assert.deepEqual(aggregateSse("data: {\"foo\":1}\n\ndata: plain\n\n"), { events: 2, text: null });
  });
});

describe("流式脱敏", () => {
  it("秘密被拆在任意两个数据块之间也能抹掉", () => {
    const secret = "SECRET-abcdef-123";
    const text = `xx ${secret} yy ${secret.toLowerCase()} zz`;
    for (let cut = 0; cut <= text.length; cut++) {
      const r = new StreamRedactor([secret]);
      const out = Buffer.concat([r.push(Buffer.from(text.slice(0, cut))), r.push(Buffer.from(text.slice(cut))), r.flush()]).toString();
      assert.equal(out, "xx [REDACTED] yy [REDACTED] zz", `cut=${cut}`);
    }
  });
});

describe("本地网关", () => {
  let vault: Vault;
  let gw: Gateway;
  let base = "";
  let token = "";
  const audits: Array<Record<string, unknown>> = [];

  before(async () => {
    vault = freshVault();
    await setCred(vault);
    gw = new Gateway(vault, (e) => audits.push(e));
    const auth: SessionAuth = { grantAll: false, grants: new Set(["llm/main"]), authorize: async () => ({ ok: true }), gateway: gw };
    const r = await dispatch(vault, { id: 3, op: "gatewayOpen", params: { type: "llm", name: "main", purpose: "测试" } }, {}, auth);
    assert.ok(r.ok, JSON.stringify(r));
    base = (r.result as { base: string }).base;
    token = (r.result as { token: string }).token;
    assert.match(base, /^http:\/\/127\.0\.0\.1:\d+$/, "URL 中不含令牌");
    assert.match(token, /^kv_[A-Za-z0-9_-]{43}$/);
  });
  after(() => gw.close());

  it("替换程序发来的假 key、注入真实凭证，转发请求体；响应（含响应头）脱敏", async () => {
    const res = await fetch(`${base}/127.0.0.1:${port}/v1/chat?x=1`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "x-api-key": "fake", Referer: `${base}/x`, "Content-Type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    });
    const text = await res.text();
    const last = seen.at(-1)!;
    assert.equal(last.headers.authorization, `Bearer ${SECRET}`);
    assert.equal(last.headers["x-api-key"], undefined, "程序自带的认证头被去掉");
    assert.equal(last.headers.referer, undefined, "Referer 不转发（可能含令牌）");
    assert.equal(last.url, "/v1/chat?x=1");
    assert.equal(last.body, '{"hello":"world"}');
    assert.equal(text.includes(SECRET), false);
    assert.match(text, /\[REDACTED\]/);
    assert.equal(res.headers.get("x-echo"), "[REDACTED]");
  });

  it("边收边转发：第一块数据在上游结束前就到达", async () => {
    const t0 = Date.now();
    const res = await fetch(`${base}/127.0.0.1:${port}/slow`, { headers: { "x-api-key": token } });
    const reader = res.body!.getReader();
    let first = "";
    while (!first.includes("first")) {
      const { value } = await reader.read();
      first += Buffer.from(value!).toString();
    }
    assert.ok(Date.now() - t0 < 350, `首块到达用时 ${Date.now() - t0}ms，应早于上游结束（400ms）`);
    let rest = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      rest += Buffer.from(value).toString();
    }
    assert.match(first + rest, /second/);
  });

  it("跨数据块的秘密在网关输出中被抹掉", async () => {
    const text = await (await fetch(`${base}/127.0.0.1:${port}/split`, { headers: { Authorization: `Bearer ${token}` } })).text();
    assert.equal(text, "before [REDACTED] after");
  });

  it("缺少/错误令牌 401；Host 头不对 421；浏览器请求 403；不在白名单的域名 403", async () => {
    const u = new URL(base);
    assert.equal((await fetch(`${base}/127.0.0.1:${port}/x`)).status, 401);
    assert.equal((await fetch(`${base}/127.0.0.1:${port}/x`, { headers: { Authorization: "Bearer kv_wrong" } })).status, 401);
    const status = await new Promise<number>((resolve) => {
      http.get({ host: "127.0.0.1", port: u.port, path: `/127.0.0.1:${port}/x`, headers: { Host: "evil.example.com", Authorization: `Bearer ${token}` } }, (r) => {
        r.resume();
        resolve(r.statusCode!);
      });
    });
    assert.equal(status, 421);
    assert.equal((await fetch(`${base}/127.0.0.1:${port}/x`, { headers: { Authorization: `Bearer ${token}`, Origin: "https://evil.example.com" } })).status, 403);
    assert.equal((await fetch(`${base}/127.0.0.1:${port}/x`, { headers: { Authorization: `Bearer ${token}`, "Sec-Fetch-Site": "cross-site" } })).status, 403);
    assert.equal((await fetch(`${base}/evil.example.com/steal`, { headers: { Authorization: `Bearer ${token}` } })).status, 403);
  });

  it("每次请求（含被拒绝的）写入审计，不含查询参数和令牌", () => {
    const g = audits.filter((a) => a.op === "gateway");
    assert.ok(g.some((a) => a.target === `POST 127.0.0.1:${port}/v1/chat` && a.ok === true));
    assert.ok(g.some((a) => a.reason === "token" && a.status === 401));
    assert.ok(g.some((a) => a.reason === "browser"));
    assert.equal(JSON.stringify(audits).includes(token), false, "审计中不出现令牌");
    assert.equal(JSON.stringify(audits).includes("x=1"), false);
  });

  it("未授权的凭证不能开通网关", async () => {
    const auth: SessionAuth = { grantAll: false, grants: new Set(), authorize: async () => ({ ok: true }), gateway: gw };
    const r = await dispatch(vault, { id: 4, op: "gatewayOpen", params: { type: "llm", name: "main", purpose: "测试" } }, {}, auth);
    assert.equal(r.ok, false);
    assert.match(!r.ok ? r.error : "", /GRANT_REQUIRED/);
  });
});

describe("网关：只接受会话用户的进程（真实 lsof 检查）", () => {
  const curl = (url: string, token: string) =>
    new Promise<{ code: number | null; out: string }>((resolve) => {
      execFile("/usr/bin/curl", ["-s", "-o", "-", "-w", "\n%{http_code}", "-H", `Authorization: Bearer ${token}`, url], (err, stdout) =>
        resolve({ code: err ? 1 : 0, out: String(stdout) }),
      );
    });

  for (const [label, uidOf] of [["本人的进程可以连接", () => process.getuid!()], ["其他用户的进程被断开", () => 4242]] as const) {
    it(label, async () => {
      const vault = freshVault();
      await setCred(vault);
      const gw = new Gateway(vault, () => {}, { allowedUid: uidOf() });
      try {
        const { base, token } = await gw.open("llm", "main");
        const r = await curl(`${base}/127.0.0.1:${port}/echo`, token);
        if (uidOf() === process.getuid!()) assert.match(r.out, /\n200$/);
        else assert.ok(!/\n200$/.test(r.out), `应被拒绝：${r.out}`);
      } finally {
        gw.close();
      }
    });
  }
});

describe("网关环境变量文件", () => {
  it("只有用户可读（0600，目录 0700），会话结束删除", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "kv-home-"));
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      const f = writeGatewayEnv("sess1", "llm", "main", { OPENAI_API_KEY: "kv_x'y", OPENAI_BASE_URL: "http://127.0.0.1:1/api.openai.com/v1" });
      assert.equal(fs.statSync(f).mode & 0o777, 0o600);
      assert.equal(fs.statSync(path.dirname(f)).mode & 0o777, 0o700);
      assert.match(fs.readFileSync(f, "utf8"), /export OPENAI_API_KEY='kv_x'\\''y'/);
      cleanupGatewayEnv();
      assert.equal(fs.existsSync(f), false);
    } finally {
      process.env.HOME = prev;
    }
  });
});

describe("秘密文件（credential_export_file 用）", () => {
  it("只有用户可读（0600），内容原样写入，不做 shell 转义；会话结束删除", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "kv-home-"));
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc'\"$(whoami)\ndef\n-----END OPENSSH PRIVATE KEY-----\n";
      const f = writeSecretFile("sess1", "ssh_key", "simvito", undefined, key);
      assert.match(f, /sess1-ssh_key-simvito\.key$/);
      assert.equal(fs.statSync(f).mode & 0o777, 0o600);
      assert.equal(fs.readFileSync(f, "utf8"), key);
      const f2 = writeSecretFile("sess1", "password", "db", "secret_access_key", "s3cr3t");
      assert.match(f2, /sess1-password-db-secret_access_key\.key$/);
      cleanupGatewayEnv();
      assert.equal(fs.existsSync(f), false);
      assert.equal(fs.existsSync(f2), false);
    } finally {
      process.env.HOME = prev;
    }
  });
});

describe("已返回值记录（recordSecrets，供 PreToolUse hook 精确匹配）", () => {
  it("只记录达到最短长度的值，去重后逐行追加，会话结束删除", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "kv-home-"));
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      recordSecrets("sess1", ["rqspdbmnzfvjbeac", "123456", undefined, "rqspdbmnzfvjbeac"]);
      recordSecrets("sess1", ["AKIAABCDEFGHIJKLMNOP"]);
      const file = path.join(home, ".keyvalet", "run", "sess1.redact");
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      const lines = fs.readFileSync(file, "utf8").trim().split("\n");
      assert.deepEqual(lines, ["rqspdbmnzfvjbeac", "AKIAABCDEFGHIJKLMNOP"]);
      cleanupGatewayEnv();
      assert.equal(fs.existsSync(file), false);
    } finally {
      process.env.HOME = prev;
    }
  });
});

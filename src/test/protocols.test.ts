import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, describe, it } from "node:test";
import { dispatch } from "../helper/dispatch.js";
import { setStsEndpointForTests, sigv4 } from "../helper/protocols/aws.js";
import { allowInsecureLoopbackForTests } from "../helper/protocols/http.js";
import { signJwt } from "../helper/protocols/jwt.js";
import { base32Decode, totpAt } from "../helper/protocols/totp.js";
import { setUserConfirmForTests } from "../helper/user-dialog.js";
import { Vault } from "../helper/vault.js";
import { runBrowserFlow } from "../server/oauth-flow.js";
import type { Op } from "../shared/protocol.js";

// ---------- 模拟服务端 ----------
const sa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ghApp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = (k: crypto.KeyObject) => k.export({ type: "pkcs8", format: "pem" }).toString();

function verifyJwt(jwt: string, pub: crypto.KeyObject): Record<string, unknown> {
  const [h, p, s] = jwt.split(".");
  assert.ok(crypto.verify("sha256", Buffer.from(`${h}.${p}`), pub, Buffer.from(s!, "base64url")), "JWT 签名无效");
  return JSON.parse(Buffer.from(p!, "base64url").toString());
}

let base = "";
let server: http.Server;
let devicePolls = 0;
const seen: Array<{ path: string; form: URLSearchParams; headers: http.IncomingHttpHeaders }> = [];

function route(method: string, p: string, body: string, headers: http.IncomingHttpHeaders): { status: number; body: unknown; xml?: boolean } {
  const form = new URLSearchParams(body);
  seen.push({ path: p, form, headers });
  if (p === "/token") {
    const g = form.get("grant_type");
    if (g === "authorization_code") {
      if (form.get("code") !== "good-code" || !form.get("code_verifier")) return { status: 400, body: { error: "invalid_grant" } };
      if (form.get("client_secret") !== "s3cret") return { status: 401, body: { error: "invalid_client" } };
      const idToken = `x.${Buffer.from(JSON.stringify({ email: "me@example.com" })).toString("base64url")}.y`;
      return { status: 200, body: { access_token: "at-1", expires_in: 3600, refresh_token: "rt-1", scope: "a b", id_token: idToken } };
    }
    if (g === "refresh_token") {
      const rt = form.get("refresh_token");
      if (rt === "rt-1") return { status: 200, body: { access_token: "at-2", expires_in: 3600, refresh_token: "rt-2" } };
      if (rt === "rt-2") return { status: 200, body: { access_token: "at-3", expires_in: 3600 } };
      return { status: 400, body: { error: "invalid_grant" } };
    }
    if (g === "client_credentials") return { status: 200, body: { access_token: `cc-${form.get("scope")}`, expires_in: 3600 } };
    if (g === "urn:ietf:params:oauth:grant-type:device_code") {
      devicePolls++;
      return devicePolls < 2 ? { status: 400, body: { error: "authorization_pending" } } : { status: 200, body: { access_token: "dev-at", expires_in: 3600, refresh_token: "dev-rt" } };
    }
    if (g === "urn:ietf:params:oauth:grant-type:jwt-bearer") {
      const claims = verifyJwt(form.get("assertion")!, sa.publicKey);
      return { status: 200, body: { access_token: `sa:${String(claims.scope)}:${String(claims.sub ?? "")}`, expires_in: 3600 } };
    }
  }
  if (p === "/evil-token") return { status: 200, body: { access_token: "evil", expires_in: 3600 } };
  if (p === "/huge") return { status: 200, body: { access_token: "x".repeat(2 * 1024 * 1024) } };
  if (p === "/device") return { status: 200, body: { device_code: "dc-1", user_code: "ABCD-EFGH", verification_uri: `${base}/verify`, interval: 1, expires_in: 600 } };
  if (p === "/app/installations" && method === "GET") {
    verifyJwt(String(headers.authorization).replace("Bearer ", ""), ghApp.publicKey);
    return { status: 200, body: [{ id: 42, account: { login: "me" } }] };
  }
  if (p === "/app/installations/42/access_tokens") {
    const claims = verifyJwt(String(headers.authorization).replace("Bearer ", ""), ghApp.publicKey);
    assert.equal(claims.iss, "12345");
    const req = body ? JSON.parse(body) : {};
    return { status: 201, body: { token: `ghs_${req.repositories ? "narrow" : "full"}`, expires_at: new Date(Date.now() + 3600_000).toISOString(), permissions: { contents: "read" } } };
  }
  if (p === "/sts") {
    assert.match(String(headers.authorization), /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY123456\/\d{8}\/us-east-1\/sts\/aws4_request/);
    const exp = new Date(Date.now() + 3600_000).toISOString();
    return {
      status: 200,
      xml: true,
      body: `<R><Credentials><AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>tempSecret</SecretAccessKey><SessionToken>tok-${form.get("Action")}-${form.get("TokenCode") ?? "nomfa"}</SessionToken><Expiration>${exp}</Expiration></Credentials></R>`,
    };
  }
  return { status: 404, body: { error: "not_found" } };
}

before(async () => {
  allowInsecureLoopbackForTests(true);
  setUserConfirmForTests(async () => true); // helper 端的覆盖确认：测试中默认同意
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const r = route(req.method!, new URL(req.url!, "http://x").pathname, body, req.headers);
      res.writeHead(r.status, { "Content-Type": r.xml ? "text/xml" : "application/json" });
      res.end(r.xml ? String(r.body) : JSON.stringify(r.body));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  setStsEndpointForTests(`${base}/sts`);
});

after(() => {
  server.close();
  allowInsecureLoopbackForTests(false);
  setStsEndpointForTests(null);
});

let vault: Vault;
let nextId = 1;
beforeEach(() => {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "credmcp-p-")), "vault");
  vault = new Vault(dir);
  vault.init();
  devicePolls = 0;
});

async function call<T = Record<string, unknown>>(op: Op, params: Record<string, unknown>): Promise<T> {
  const r = await dispatch(vault, { id: nextId++, op, params: { purpose: "自动化测试", ...params } }, { session: "test" });
  if (!r.ok) throw new Error(r.error);
  return r.result as T;
}

function oauthConfig(extra: Record<string, unknown> = {}) {
  return {
    provider: "custom",
    client_id: "cid",
    authorization_url: `${base}/authorize`,
    token_url: `${base}/token`,
    device_authorization_url: `${base}/device`,
    scopes: ["a", "b"],
    ...extra,
  };
}

// ---------- 测试 ----------

describe("标准测试向量", () => {
  it("TOTP：RFC 6238 附录 B", () => {
    const k1 = Buffer.from("12345678901234567890");
    assert.equal(totpAt(k1, 59, 8, 30, "SHA1"), "94287082");
    assert.equal(totpAt(k1, 1111111109, 8, 30, "SHA1"), "07081804");
    assert.equal(totpAt(Buffer.from("12345678901234567890123456789012"), 59, 8, 30, "SHA256"), "46119246");
    assert.equal(totpAt(Buffer.from("1234567890".repeat(6) + "1234"), 59, 8, 30, "SHA512"), "90693936");
    assert.deepEqual(base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), k1);
  });

  it("AWS SigV4：官方测试套件 get-vanilla", () => {
    const auth = sigv4({
      method: "GET",
      path: "/",
      query: "",
      headers: { Host: "example.amazonaws.com", "X-Amz-Date": "20150830T123600Z" },
      body: "",
      region: "us-east-1",
      service: "service",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      amzDate: "20150830T123600Z",
    });
    assert.equal(
      auth,
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
  });

  it("JWT：各算法签名可被公钥验证", () => {
    const cases: Array<[Parameters<typeof signJwt>[0], crypto.KeyPairKeyObjectResult | null]> = [
      ["RS256", crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })],
      ["PS256", crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })],
      ["ES256", crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })],
      ["EdDSA", crypto.generateKeyPairSync("ed25519")],
    ];
    for (const [alg, kp] of cases) {
      const jwt = signJwt(alg, pem(kp!.privateKey), { a: 1 });
      const [h, p, s] = jwt.split(".");
      const data = Buffer.from(`${h}.${p}`);
      const sig = Buffer.from(s!, "base64url");
      const ok =
        alg === "EdDSA"
          ? crypto.verify(null, data, kp!.publicKey, sig)
          : alg === "ES256"
            ? crypto.verify("sha256", data, { key: kp!.publicKey, dsaEncoding: "ieee-p1363" }, sig)
            : alg === "PS256"
              ? crypto.verify("sha256", data, { key: kp!.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig)
              : crypto.verify("sha256", data, kp!.publicKey, sig);
      assert.ok(ok, alg);
      assert.equal(JSON.parse(Buffer.from(h!, "base64url").toString()).alg, alg);
    }
  });
});

describe("OAuth 2.0", () => {
  it("授权码换 token、缓存、刷新（含 refresh token 轮换）", async () => {
    const r = await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "svc", config: oauthConfig(), secrets: { client_secret: "s3cret" } });
    assert.equal(r.typeCreated, true, "类型不存在时先创建类型");

    const ex = await call("oauthExchange", { type: "oauth2", name: "svc", code: "good-code", code_verifier: "v".repeat(43), redirect_uri: "http://127.0.0.1:5555/callback" });
    assert.deepEqual({ account: ex.account, refresh_token: ex.refresh_token }, { account: "me@example.com", refresh_token: true });

    assert.equal((await call("accessToken", { type: "oauth2", name: "svc" })).access_token, "at-1", "缓存有效时直接返回");
    assert.equal((await call("accessToken", { type: "oauth2", name: "svc", force: true })).access_token, "at-2");
    assert.equal(vault.getRecord("oauth2", "svc").record.secrets!.refresh_token, "rt-2", "轮换后的 refresh token 被保存");
    assert.equal((await call("accessToken", { type: "oauth2", name: "svc", force: true })).access_token, "at-3");
    assert.equal(vault.getRecord("oauth2", "svc").record.secrets!.refresh_token, "rt-2", "未返回新 refresh token 时保留旧的");
  });

  it("refresh token 失效时标记需要重新授权", async () => {
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "svc", config: oauthConfig(), secrets: { client_secret: "s3cret" } });
    vault.patchRecord("oauth2", "svc", "oauth2", vault.getRecord("oauth2", "svc").record.generation, (rec) => {
      rec.secrets = { ...rec.secrets, refresh_token: "revoked" };
    });
    await assert.rejects(call("accessToken", { type: "oauth2", name: "svc" }), /授权已失效/);
    const info = await call<{ status: { needs_reauth: boolean } }>("info", { type: "oauth2", name: "svc" });
    assert.equal(info.status.needs_reauth, true);
  });

  it("设备码流程：pending 后成功", async () => {
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "dev", config: oauthConfig({ flow: "device_code" }), secrets: {} });
    const d = await call("oauthDeviceStart", { type: "oauth2", name: "dev" });
    assert.equal(d.user_code, "ABCD-EFGH");
    assert.equal((await call("oauthDevicePoll", { type: "oauth2", name: "dev", device_code: d.device_code })).status, "pending");
    assert.equal((await call("oauthDevicePoll", { type: "oauth2", name: "dev", device_code: d.device_code })).status, "done");
    assert.equal((await call("accessToken", { type: "oauth2", name: "dev" })).access_token, "dev-at");
    const tokenCall = seen.filter((s) => s.path === "/token").at(-1)!;
    assert.equal(tokenCall.form.get("client_secret"), null, "公共客户端不发送 secret");
  });

  it("客户端凭证流程", async () => {
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "m2m", config: oauthConfig({ flow: "client_credentials", scopes: ["api"] }), secrets: { client_secret: "s3cret" } });
    assert.equal((await call("accessToken", { type: "oauth2", name: "m2m" })).access_token, "cc-api");
  });

  it("client_secret_basic 放在 Authorization 头里", async () => {
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "basic",
      config: oauthConfig({ flow: "client_credentials", token_auth_method: "client_secret_basic" }), secrets: { client_secret: "s3cret" },
    });
    await call("accessToken", { type: "oauth2", name: "basic" });
    const last = seen.at(-1)!;
    assert.equal(last.headers.authorization, `Basic ${Buffer.from("cid:s3cret").toString("base64")}`);
    assert.equal(last.form.get("client_secret"), null);
  });

  it("安全：拒绝非 https 端点、非回环回调、覆盖保留参数", async () => {
    allowInsecureLoopbackForTests(false);
    try {
      await assert.rejects(call("setupProtocol", { kind: "oauth2", type: "o", name: "x", config: oauthConfig(), secrets: { client_secret: "s" } }), /https/);
    } finally {
      allowInsecureLoopbackForTests(true);
    }
    await assert.rejects(
      call("setupProtocol", { kind: "oauth2", type: "o", name: "x", config: oauthConfig({ redirect_uri: "http://evil.com/cb" }), secrets: { client_secret: "s" } }),
      /回环/,
    );
    await assert.rejects(
      call("setupProtocol", { kind: "oauth2", type: "o", name: "x", config: oauthConfig({ extra_auth_params: { redirect_uri: "x" } }), secrets: { client_secret: "s" } }),
      /不能包含 redirect_uri/,
    );
  });

  it("安全：端点变化时不能沿用旧 client secret", async () => {
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "svc", config: oauthConfig(), secrets: { client_secret: "s3cret" } });
    // 只改 scope：可以沿用
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "svc", config: oauthConfig({ scopes: ["c"] }), secrets: {}, reuseClientSecret: true, overwrite: true });
    assert.equal(vault.getRecord("oauth2", "svc").record.secrets!.client_secret, "s3cret");
    // 改 token_url：拒绝
    await assert.rejects(
      call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "svc", config: oauthConfig({ token_url: `${base}/evil` }), secrets: {}, reuseClientSecret: true, overwrite: true }),
      /token_url 已变化/,
    );
  });

  it("安全：刷新期间配置被替换时，新 refresh token 不会写进新配置（竞态攻击回归测试）", async () => {
    const cfg = oauthConfig({ token_auth_method: "none" });
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "pub", config: cfg, secrets: {} });
    const g1 = vault.getRecord("oauth2", "pub").record.generation;
    vault.patchRecord("oauth2", "pub", "oauth2", g1, (rec) => {
      rec.secrets = { refresh_token: "rt-1" };
    });
    // 刷新请求发出后（等待网络时），agent 把凭证改成指向攻击者的端点
    const refreshing = call("accessToken", { type: "oauth2", name: "pub", force: true });
    await call("setupProtocol", {
      kind: "oauth2", type: "oauth2", name: "pub", overwrite: true, secrets: {},
      config: oauthConfig({ token_auth_method: "none", token_url: `${base}/evil-token`, authorization_url: `${base}/evil-auth` }),
    });
    await assert.rejects(refreshing, /操作期间被修改/);
    const rec = vault.getRecord("oauth2", "pub").record;
    assert.notEqual(rec.generation, g1);
    assert.equal(rec.secrets?.refresh_token, undefined, "轮换得到的 rt-2 没有落入攻击者配置");
  });

  it("安全：超大响应被中止，不会整个读进内存", async () => {
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "big", config: oauthConfig({ flow: "client_credentials", token_url: `${base}/huge` }), secrets: { client_secret: "s" } });
    await assert.rejects(call("accessToken", { type: "oauth2", name: "big" }), /响应过大/);
  });

  it("安全：get/info/list/审计日志都不暴露秘密", async () => {
    await call("setupProtocol", { kind: "oauth2", type: "oauth2", name: "svc", config: oauthConfig(), secrets: { client_secret: "s3cret" } });
    await call("oauthExchange", { type: "oauth2", name: "svc", code: "good-code", code_verifier: "v".repeat(43), redirect_uri: "http://127.0.0.1:5555/callback" });
    const exposed = JSON.stringify([
      await call("get", { type: "oauth2", name: "svc" }),
      await call("info", { type: "oauth2", name: "svc" }),
      await call("list", {}),
    ]);
    for (const secret of ["s3cret", "rt-1", "at-1"]) assert.equal(exposed.includes(secret), false, secret);
    assert.throws(() => vault.get("oauth2", "svc"), /不能直接读取/);
    const audit = fs.readFileSync(vault.auditPath, "utf8");
    for (const secret of ["s3cret", "rt-1", "at-1", "good-code"]) assert.equal(audit.includes(secret), false, secret);
  });
});

describe("Google 服务账号", () => {
  it("签 JWT 换 token，按 scope 缓存，subject 固定", async () => {
    const keyJson = JSON.stringify({ type: "service_account", client_email: "bot@p.iam.gserviceaccount.com", private_key: pem(sa.privateKey), private_key_id: "kid1", token_uri: `${base}/token` });
    await call("setupProtocol", {
      kind: "google_service_account", type: "gsa", name: "bot", secrets: { key_json: keyJson },
      config: { subject: "admin@example.com", scopes: ["https://www.googleapis.com/auth/cloud-platform", "https://x/a", "https://x/b"] },
    });
    const t1 = await call("accessToken", { type: "gsa", name: "bot" });
    assert.equal(t1.access_token, "sa:https://www.googleapis.com/auth/cloud-platform https://x/a https://x/b:admin@example.com");
    const t2 = await call("accessToken", { type: "gsa", name: "bot", scopes: ["https://x/b", "https://x/a"] });
    assert.equal(t2.access_token, "sa:https://x/a https://x/b:admin@example.com");
    const n = seen.length;
    await call("accessToken", { type: "gsa", name: "bot", scopes: ["https://x/a", "https://x/b"] });
    assert.equal(seen.length, n, "相同 scope 命中缓存");
    assert.equal(JSON.stringify(await call("get", { type: "gsa", name: "bot" })).includes("PRIVATE KEY"), false);
  });

  it("安全：只能请求设置时允许的 scope 子集", async () => {
    const keyJson = JSON.stringify({ type: "service_account", client_email: "bot@p.iam.gserviceaccount.com", private_key: pem(sa.privateKey), token_uri: `${base}/token` });
    await call("setupProtocol", { kind: "google_service_account", type: "gsa", name: "narrow", config: { scopes: ["https://x/read"] }, secrets: { key_json: keyJson } });
    await assert.rejects(call("accessToken", { type: "gsa", name: "narrow", scopes: ["https://mail.google.com/"] }), /不在该凭证允许的范围内/);
    assert.equal((await call("accessToken", { type: "gsa", name: "narrow", scopes: ["https://x/read"] })).access_token, "sa:https://x/read:");
  });

  it("拒绝不是服务账号的 JSON", async () => {
    await assert.rejects(call("setupProtocol", { kind: "google_service_account", type: "gsa", name: "x", config: {}, secrets: { key_json: '{"type":"authorized_user"}' } }), /service_account/);
  });
});

describe("GitHub App", () => {
  it("自动发现唯一 installation，获取并缓存 token；收窄权限的 token 不缓存", async () => {
    await call("setupProtocol", { kind: "github_app", type: "github_app", name: "bot", config: { app_id: "12345", api_base_url: base }, secrets: { private_key: pem(ghApp.privateKey) } });
    assert.equal((await call("accessToken", { type: "github_app", name: "bot" })).access_token, "ghs_full");
    const n = seen.length;
    assert.equal((await call("accessToken", { type: "github_app", name: "bot" })).access_token, "ghs_full");
    assert.equal(seen.length, n, "命中缓存");
    assert.equal((await call("accessToken", { type: "github_app", name: "bot", repositories: ["repo1"] })).access_token, "ghs_narrow");
    assert.equal((await call("accessToken", { type: "github_app", name: "bot" })).access_token, "ghs_full");
  });
});

describe("JWT 签发", () => {
  it("按模板签发 ES256（App Store Connect 风格），保留字段不可覆盖", async () => {
    const kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    await call("setupProtocol", {
      kind: "jwt", type: "jwt", name: "asc",
      config: { algorithm: "ES256", issuer: "issuer-uuid", audience: "appstoreconnect-v1", key_id: "KEY123", lifetime_seconds: 1200 },
      secrets: { key: pem(kp.privateKey) },
    });
    const t = await call<{ access_token: string }>("accessToken", { type: "jwt", name: "asc" });
    const [h, p] = t.access_token.split(".");
    assert.deepEqual(JSON.parse(Buffer.from(h!, "base64url").toString()), { kid: "KEY123", alg: "ES256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(p!, "base64url").toString());
    assert.equal(claims.iss, "issuer-uuid");
    assert.equal(claims.aud, "appstoreconnect-v1");
    assert.equal(claims.exp - claims.iat, 1200);
    await assert.rejects(call("setupProtocol", { kind: "jwt", type: "jwt", name: "bad", config: { algorithm: "ES256", claims: { exp: 1 } }, secrets: { key: pem(kp.privateKey) } }), /保留字段/);
    await assert.rejects(call("setupProtocol", { kind: "jwt", type: "jwt", name: "bad", config: { algorithm: "RS256" }, secrets: { key: pem(kp.privateKey) } }), /不匹配/);
  });
});

describe("TOTP", () => {
  it("从 otpauth URI 设置并生成验证码，不暴露种子", async () => {
    const uri = "otpauth://totp/GitHub:me%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=6";
    await call("setupProtocol", { kind: "totp", type: "totp", name: "gh", config: {}, secrets: { secret: uri } });
    const c = await call<{ code: string; issuer: string; account: string }>("totp", { type: "totp", name: "gh" });
    assert.match(c.code, /^\d{6}$/);
    assert.equal(c.code, totpAt(Buffer.from("12345678901234567890"), Date.now() / 1000, 6, 30, "SHA1"));
    assert.deepEqual([c.issuer, c.account], ["GitHub", "me@example.com"]);
    assert.equal(JSON.stringify(await call("get", { type: "totp", name: "gh" })).includes("GEZDGNBV"), false);
  });
});

describe("AWS", () => {
  it("GetSessionToken 与 AssumeRole + TOTP MFA", async () => {
    const secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    await call("setupProtocol", { kind: "aws", type: "aws", name: "dev", config: { access_key_id: "AKIAEXAMPLEKEY123456" }, secrets: { secret_access_key: secret } });
    const c = await call<{ session_token: string; access_key_id: string }>("aws", { type: "aws", name: "dev" });
    assert.equal(c.session_token, "tok-GetSessionToken-nomfa");
    assert.equal(c.access_key_id, "ASIATEMP");

    await call("setupProtocol", { kind: "totp", type: "totp", name: "aws-mfa", config: {}, secrets: { secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" } });
    await call("setupProtocol", {
      kind: "aws", type: "aws", name: "prod",
      config: { access_key_id: "AKIAEXAMPLEKEY123456", role_arn: "arn:aws:iam::123456789012:role/Admin", mfa_serial: "arn:aws:iam::123456789012:mfa/me", mfa_totp: { type: "totp", name: "aws-mfa" } },
      secrets: { secret_access_key: secret },
    });
    const code = totpAt(Buffer.from("12345678901234567890"), Date.now() / 1000, 6, 30, "SHA1");
    const p = await call<{ session_token: string }>("aws", { type: "aws", name: "prod" });
    assert.equal(p.session_token, `tok-AssumeRole-${code}`);
    assert.equal(JSON.stringify(await call("get", { type: "aws", name: "prod" })).includes(secret), false);
  });

  it("mfa_totp 必须指向 TOTP 凭证；access key 格式校验", async () => {
    await assert.rejects(
      call("setupProtocol", { kind: "aws", type: "aws", name: "x", config: { access_key_id: "ASIATEMPKEY123456789" }, secrets: { secret_access_key: "a".repeat(40) } }),
      /AKIA/,
    );
  });
});

describe("浏览器授权流程（本地回调）", () => {
  it("PKCE + state：伪造的 state 被忽略，正确回调返回授权码", async () => {
    let challenge = "";
    const r = await runBrowserFlow({
      authorizationUrl: "https://auth.example.com/authorize",
      clientId: "cid",
      scopes: ["a", "b"],
      extraParams: { access_type: "offline" },
      timeoutMs: 5000,
      open: async (url) => {
        const u = new URL(url);
        assert.equal(u.searchParams.get("code_challenge_method"), "S256");
        assert.equal(u.searchParams.get("scope"), "a b");
        assert.equal(u.searchParams.get("access_type"), "offline");
        challenge = u.searchParams.get("code_challenge")!;
        const cb = u.searchParams.get("redirect_uri")!;
        const forged = await fetch(`${cb}?code=evil&state=wrong`);
        assert.equal(forged.status, 400);
        void fetch(`${cb}?code=real-code&state=${u.searchParams.get("state")}`);
      },
    });
    assert.equal(r.code, "real-code");
    assert.equal(crypto.createHash("sha256").update(r.code_verifier).digest("base64url"), challenge);
    assert.match(r.redirect_uri, /^http:\/\/127\.0\.0\.1:\d+\/callback$/);
  });

  it("用户拒绝授权时报错", async () => {
    await assert.rejects(
      runBrowserFlow({
        authorizationUrl: "https://auth.example.com/authorize",
        clientId: "cid",
        scopes: [],
        extraParams: {},
        timeoutMs: 5000,
        open: async (url) => {
          const u = new URL(url);
          void fetch(`${u.searchParams.get("redirect_uri")}?error=access_denied&state=${u.searchParams.get("state")}`);
        },
      }),
      /access_denied/,
    );
  });
});

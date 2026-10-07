import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, beforeEach, describe, it } from "node:test";
import { applyMode, dispatch, resolveHint, type SessionAuth } from "../helper/dispatch.js";
import { isLoosening, readSettings, rememberActive, stricter, writeSettings } from "../helper/settings.js";
import { setUserConfirmForTests } from "../helper/user-dialog.js";
import { Vault } from "../helper/vault.js";
import { GRANT_REQUIRED_PREFIX, type Op } from "../shared/protocol.js";

let vault: Vault;
let auth: SessionAuth;
let touchIdAnswers: boolean[];
let reasons: string[];

beforeEach(() => {
  vault = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "credmcp-g-")), "vault"));
  vault.init();
  vault.set({ type: "api_key", name: "openai", value: "sk-openai-123" });
  vault.set({ type: "api_key", name: "github", value: "ghp-456789" });
  touchIdAnswers = [];
  reasons = [];
  auth = {
    grantAll: false,
    grants: new Set(),
    mode: "per_credential",
    authorize: async (reason) => {
      reasons.push(reason);
      return touchIdAnswers.shift() ?? false ? { ok: true } : { ok: false, error: "Touch ID 认证未通过" };
    },
  };
  setUserConfirmForTests(async () => {
    throw new Error("放宽设置应使用 Touch ID，而不是确认框");
  });
});
after(() => setUserConfirmForTests(null));

async function call(op: Op, params: Record<string, unknown>) {
  return dispatch(vault, { id: 1, op, params: { purpose: "测试", ...params } }, { session: "s", cwd: "/proj" }, auth);
}
const ok = (r: Awaited<ReturnType<typeof call>>) => r.ok;

describe("per_credential（默认）", () => {
  it("未授权的凭证被拒绝；Touch ID 授权后本会话可用，其他凭证仍需授权", async () => {
    const denied = await call("get", { type: "api_key", name: "openai" });
    assert.equal(!denied.ok && denied.error, `${GRANT_REQUIRED_PREFIX}api_key/openai`);
    touchIdAnswers.push(true);
    const g = await call("grant", { type: "api_key", name: "openai", purpose: "调用 OpenAI" });
    assert.deepEqual(g.ok && g.result, { granted: "api_key/openai", already: false, single_use: false });
    assert.match(reasons[0]!, /授权本次 AI 会话使用凭证：api_key\/openai/);
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })));
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })), "本会话内可重复使用");
    assert.equal(ok(await call("get", { type: "api_key", name: "github" })), false, "授权一个不等于授权全部");
  });

  it("Touch ID 未通过则不授权；本会话新建的凭证自动授权；元数据操作不需要授权", async () => {
    touchIdAnswers.push(false);
    assert.equal(ok(await call("grant", { type: "api_key", name: "openai" })), false);
    assert.ok(ok(await call("set", { type: "api_key", name: "new", value: "v-111111" })));
    assert.ok(ok(await call("get", { type: "api_key", name: "new" })));
    for (const op of ["list", "listTypes", "info", "exists", "auditQuery", "sessionInfo"] as const) {
      assert.ok(ok(await call(op, { type: "api_key", name: "openai" })), op);
    }
  });
});

describe("per_use：每次使用都要 Touch ID", () => {
  it("一次 Touch ID 只换来一次使用；新建凭证也不自动授权", async () => {
    auth.mode = "per_use";
    touchIdAnswers.push(true, true);
    assert.ok(ok(await call("grant", { type: "api_key", name: "openai" })));
    assert.match(reasons[0]!, /仅此一次/);
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })));
    assert.equal(ok(await call("get", { type: "api_key", name: "openai" })), false, "第二次使用需要再次认证");
    assert.ok(ok(await call("grant", { type: "api_key", name: "openai" })), "再次授权不会被当成已授权");
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })));
    assert.ok(ok(await call("set", { type: "api_key", name: "new", value: "v-111111" })));
    assert.equal(ok(await call("get", { type: "api_key", name: "new" })), false);
  });
});

describe("授权模式设置（可在会话中用 / 命令修改）", () => {
  it("默认 per_credential；放宽需要 Touch ID，并对当前会话立即生效", async () => {
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");
    touchIdAnswers.push(false);
    assert.equal(ok(await call("settings", { grant_mode: "per_session" })), false);
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");

    touchIdAnswers.push(true);
    assert.ok(ok(await call("settings", { grant_mode: "per_session" })));
    assert.match(reasons.at(-1)!, /每个会话按一次 Touch ID/);
    assert.equal(readSettings(vault.dir).grant_mode, "per_session");
    assert.ok(ok(await call("get", { type: "api_key", name: "github" })), "当前会话立即可用全部凭证");
    assert.equal(fs.statSync(path.join(vault.dir, "settings.json")).mode & 0o777, 0o600);
  });

  it("收紧立即生效、无需认证，并收回当前会话的授权", async () => {
    auth.mode = "per_session";
    auth.grantAll = true;
    writeSettings(vault.dir, { grant_mode: "per_session", remember_hours: 8 });
    assert.ok(ok(await call("settings", { grant_mode: "per_use" })));
    assert.equal(reasons.length, 0);
    assert.equal(auth.mode, "per_use");
    assert.equal(ok(await call("get", { type: "api_key", name: "openai" })), false);
  });

  it("remember：按一次 Touch ID 开始记住；延长时长算放宽；forget 清除", async () => {
    touchIdAnswers.push(true);
    const r = await call("settings", { grant_mode: "remember", remember_hours: 8 });
    assert.ok(r.ok, JSON.stringify(r));
    const s = readSettings(vault.dir);
    assert.ok(rememberActive(s));
    assert.ok(Math.abs(s.remember_until! - (Date.now() + 8 * 3_600_000)) < 5000);

    touchIdAnswers.push(false);
    assert.equal(ok(await call("settings", { remember_hours: 0 })), false, "改为永久需要 Touch ID");
    assert.ok(ok(await call("settings", { remember_hours: 1 })), "缩短不需要");
    assert.ok(readSettings(vault.dir).remember_until! <= Date.now() + 3_600_000 + 5000, "缩短时长同时缩短当前窗口");

    assert.ok(ok(await call("settings", { forget: true })));
    assert.equal(rememberActive(readSettings(vault.dir)), false);
    const info = await call("sessionInfo", {});
    assert.equal(info.ok && (info.result as { remembered_until: unknown }).remembered_until, null);
  });

  it("客户端只能收严：KEYVALET_GRANT_MODE 与全局设置取更严格的那个", () => {
    assert.equal(stricter("remember", "per_use"), "per_use");
    assert.equal(stricter("per_use", "remember"), "per_use");
    assert.equal(stricter("per_credential", null), "per_credential");
    auth.requested = "per_use";
    applyMode(auth, { grant_mode: "per_session", remember_hours: 8 });
    assert.equal(auth.mode, "per_use");
    assert.equal(auth.grantAll, false);
  });

  it("isLoosening 判定", () => {
    const s = (grant_mode: "per_use" | "per_credential" | "per_session" | "remember", remember_hours = 8) => ({ grant_mode, remember_hours });
    assert.equal(isLoosening(s("per_credential"), s("per_session")), true);
    assert.equal(isLoosening(s("per_credential"), s("per_use")), false);
    assert.equal(isLoosening(s("remember", 8), s("remember", 24)), true);
    assert.equal(isLoosening(s("remember", 8), s("remember", 0)), true);
    assert.equal(isLoosening(s("remember", 0), s("remember", 8)), false);
    assert.equal(isLoosening(s("remember", 8), s("per_session")), false);
  });

  it("兼容旧设置 all → per_session；握手提示按名字唯一匹配", () => {
    fs.writeFileSync(path.join(vault.dir, "settings.json"), JSON.stringify({ grant_mode: "all" }), { mode: 0o600 });
    assert.equal(readSettings(vault.dir).grant_mode, "per_session");
    assert.equal(resolveHint(vault, { type: "api_key", name: "openai" }), "api_key/openai");
    assert.equal(resolveHint(vault, { name: "github" }), "api_key/github");
    assert.equal(resolveHint(vault, { name: "nope" }), null);
  });
});

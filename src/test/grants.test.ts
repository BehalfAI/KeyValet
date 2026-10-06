import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, beforeEach, describe, it } from "node:test";
import { dispatch, resolveHint, type SessionAuth } from "../helper/dispatch.js";
import { readSettings } from "../helper/settings.js";
import { setUserConfirmForTests } from "../helper/user-dialog.js";
import { Vault } from "../helper/vault.js";
import { GRANT_REQUIRED_PREFIX, type Op } from "../shared/protocol.js";

let vault: Vault;
let auth: SessionAuth;
let touchIdAnswers: boolean[];
let reasons: string[];
let confirmAnswer: boolean;

beforeEach(() => {
  vault = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "credmcp-g-")), "vault"));
  vault.init();
  vault.set({ type: "api_key", name: "openai", value: "sk-openai-123" });
  vault.set({ type: "api_key", name: "github", value: "ghp-456789" });
  touchIdAnswers = [];
  reasons = [];
  confirmAnswer = true;
  auth = {
    grantAll: false,
    grants: new Set(),
    authorize: async (reason) => {
      reasons.push(reason);
      return touchIdAnswers.shift() ?? false ? { ok: true } : { ok: false, error: "Touch ID 认证未通过" };
    },
  };
  setUserConfirmForTests(async () => confirmAnswer);
});
after(() => setUserConfirmForTests(null));

async function call(op: Op, params: Record<string, unknown>) {
  return dispatch(vault, { id: 1, op, params: { purpose: "测试", ...params } }, { session: "s", cwd: "/proj" }, auth);
}

describe("按凭证授权（per_credential）", () => {
  it("未授权的凭证被拒绝；Touch ID 授权后可用，其他凭证仍需授权", async () => {
    const denied = await call("get", { type: "api_key", name: "openai" });
    assert.equal(denied.ok, false);
    assert.equal(!denied.ok && denied.error, `${GRANT_REQUIRED_PREFIX}api_key/openai`);

    touchIdAnswers.push(true);
    const g = await call("grant", { type: "api_key", name: "openai", purpose: "调用 OpenAI" });
    assert.deepEqual(g, { id: 1, ok: true, result: { granted: "api_key/openai", already: false } });
    assert.match(reasons[0]!, /授权本次 AI 会话使用凭证：api_key\/openai/);
    assert.match(reasons[0]!, /目的：调用 OpenAI/);

    assert.equal((await call("get", { type: "api_key", name: "openai" })).ok, true);
    assert.equal((await call("get", { type: "api_key", name: "github" })).ok, false, "授权一个不等于授权全部");
    // 已授权的再次 grant 不弹窗
    assert.deepEqual((await call("grant", { type: "api_key", name: "openai" })).ok && reasons.length, 1);
  });

  it("Touch ID 未通过则不授权", async () => {
    touchIdAnswers.push(false);
    const g = await call("grant", { type: "api_key", name: "openai" });
    assert.equal(g.ok, false);
    assert.equal(auth.grants.size, 0);
  });

  it("本会话新建/覆盖的凭证自动授权；列表等元数据操作不需要授权", async () => {
    assert.equal((await call("set", { type: "api_key", name: "new", value: "v-111111" })).ok, true);
    assert.equal((await call("get", { type: "api_key", name: "new" })).ok, true);
    for (const op of ["list", "listTypes", "info", "exists", "auditQuery", "sessionInfo"] as const) {
      assert.equal((await call(op, { type: "api_key", name: "openai" })).ok, true, op);
    }
    const info = await call("sessionInfo", {});
    assert.deepEqual(info.ok && info.result, { grant_mode: "per_credential", session_grants_all: false, granted: ["api_key/new"] });
  });

  it("all 模式的会话可使用全部凭证", async () => {
    auth.grantAll = true;
    assert.equal((await call("get", { type: "api_key", name: "openai" })).ok, true);
    assert.equal((await call("get", { type: "api_key", name: "github" })).ok, true);
  });
});

describe("授权范围设置", () => {
  it("默认 per_credential；改为 all 需用户确认，改回不需要", async () => {
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");
    confirmAnswer = false;
    const denied = await call("settings", { grant_mode: "all" });
    assert.equal(denied.ok, false);
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");

    confirmAnswer = true;
    assert.equal((await call("settings", { grant_mode: "all" })).ok, true);
    assert.equal(readSettings(vault.dir).grant_mode, "all");
    assert.equal(fs.statSync(path.join(vault.dir, "settings.json")).mode & 0o777, 0o600);

    confirmAnswer = false; // 收紧不弹窗
    assert.equal((await call("settings", { grant_mode: "per_credential" })).ok, true);
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");
  });

  it("握手时的凭证提示：按类型+名称，或按名称唯一匹配；不存在则不授权", () => {
    assert.equal(resolveHint(vault, { type: "api_key", name: "openai" }), "api_key/openai");
    assert.equal(resolveHint(vault, { name: "github" }), "api_key/github");
    assert.equal(resolveHint(vault, { name: "nope" }), null);
    vault.set({ type: "token", name: "github", value: "x-123456" });
    assert.equal(resolveHint(vault, { name: "github" }), null, "同名多个时不猜");
  });
});

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
      return touchIdAnswers.shift() ?? false ? { ok: true } : { ok: false, error: "Touch ID authentication failed" };
    },
  };
  setUserConfirmForTests(async () => {
    throw new Error("Loosening settings should use Touch ID, not a confirmation dialog");
  });
});
after(() => setUserConfirmForTests(null));

async function call(op: Op, params: Record<string, unknown>) {
  return dispatch(vault, { id: 1, op, params: { purpose: "test", ...params } }, { session: "s", cwd: "/proj" }, auth);
}
const ok = (r: Awaited<ReturnType<typeof call>>) => r.ok;

describe("per_credential (default)", () => {
  it("an unauthorized credential is denied; after Touch ID authorization it's usable for this session, other credentials still need authorization", async () => {
    const denied = await call("get", { type: "api_key", name: "openai" });
    assert.equal(!denied.ok && denied.error, `${GRANT_REQUIRED_PREFIX}api_key/openai`);
    touchIdAnswers.push(true);
    const g = await call("grant", { type: "api_key", name: "openai", purpose: "Call OpenAI" });
    assert.deepEqual(g.ok && g.result, { granted: "api_key/openai", already: false, single_use: false });
    assert.match(reasons[0]!, /授权本次 AI 会话使用凭证：api_key\/openai/);
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })));
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })), "reusable within this session");
    assert.equal(ok(await call("get", { type: "api_key", name: "github" })), false, "authorizing one credential doesn't authorize all of them");
  });

  it("failed Touch ID does not grant authorization; credentials created in this session are auto-authorized; metadata operations don't need authorization", async () => {
    touchIdAnswers.push(false);
    assert.equal(ok(await call("grant", { type: "api_key", name: "openai" })), false);
    assert.ok(ok(await call("set", { type: "api_key", name: "new", value: "v-111111" })));
    assert.ok(ok(await call("get", { type: "api_key", name: "new" })));
    for (const op of ["list", "listTypes", "info", "exists", "auditQuery", "sessionInfo"] as const) {
      assert.ok(ok(await call(op, { type: "api_key", name: "openai" })), op);
    }
  });
});

describe("per_use: Touch ID required every time", () => {
  it("one Touch ID buys exactly one use; newly created credentials are not auto-authorized either", async () => {
    auth.mode = "per_use";
    touchIdAnswers.push(true, true);
    assert.ok(ok(await call("grant", { type: "api_key", name: "openai" })));
    assert.match(reasons[0]!, /仅此一次/);
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })));
    assert.equal(ok(await call("get", { type: "api_key", name: "openai" })), false, "a second use requires authenticating again");
    assert.ok(ok(await call("grant", { type: "api_key", name: "openai" })), "re-authorizing is not treated as already authorized");
    assert.ok(ok(await call("get", { type: "api_key", name: "openai" })));
    assert.ok(ok(await call("set", { type: "api_key", name: "new", value: "v-111111" })));
    assert.equal(ok(await call("get", { type: "api_key", name: "new" })), false);
  });
});

describe("grant mode settings (can be changed mid-session with the / command)", () => {
  it("defaults to per_credential; loosening requires Touch ID and takes effect immediately for the current session", async () => {
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");
    touchIdAnswers.push(false);
    assert.equal(ok(await call("settings", { grant_mode: "per_session" })), false);
    assert.equal(readSettings(vault.dir).grant_mode, "per_credential");

    touchIdAnswers.push(true);
    assert.ok(ok(await call("settings", { grant_mode: "per_session" })));
    assert.match(reasons.at(-1)!, /每个会话按一次 Touch ID/);
    assert.equal(readSettings(vault.dir).grant_mode, "per_session");
    assert.ok(ok(await call("get", { type: "api_key", name: "github" })), "all credentials are immediately usable in the current session");
    assert.equal(fs.statSync(path.join(vault.dir, "settings.json")).mode & 0o777, 0o600);
  });

  it("tightening takes effect immediately without authentication, and revokes the current session's authorization", async () => {
    auth.mode = "per_session";
    auth.grantAll = true;
    writeSettings(vault.dir, { grant_mode: "per_session", remember_hours: 8 });
    assert.ok(ok(await call("settings", { grant_mode: "per_use" })));
    assert.equal(reasons.length, 0);
    assert.equal(auth.mode, "per_use");
    assert.equal(ok(await call("get", { type: "api_key", name: "openai" })), false);
  });

  it("remember: one Touch ID starts the remember window; extending the duration counts as loosening; forget clears it", async () => {
    touchIdAnswers.push(true);
    const r = await call("settings", { grant_mode: "remember", remember_hours: 8 });
    assert.ok(r.ok, JSON.stringify(r));
    const s = readSettings(vault.dir);
    assert.ok(rememberActive(s));
    assert.ok(Math.abs(s.remember_until! - (Date.now() + 8 * 3_600_000)) < 5000);

    touchIdAnswers.push(false);
    assert.equal(ok(await call("settings", { remember_hours: 0 })), false, "changing it to forever requires Touch ID");
    assert.ok(ok(await call("settings", { remember_hours: 1 })), "shortening it doesn't");
    assert.ok(readSettings(vault.dir).remember_until! <= Date.now() + 3_600_000 + 5000, "shortening the duration also shortens the current window");

    assert.ok(ok(await call("settings", { forget: true })));
    assert.equal(rememberActive(readSettings(vault.dir)), false);
    const info = await call("sessionInfo", {});
    assert.equal(info.ok && (info.result as { remembered_until: unknown }).remembered_until, null);
  });

  it("a client can only tighten: KEYVALET_GRANT_MODE and the global setting combine to the stricter one", () => {
    assert.equal(stricter("remember", "per_use"), "per_use");
    assert.equal(stricter("per_use", "remember"), "per_use");
    assert.equal(stricter("per_credential", null), "per_credential");
    auth.requested = "per_use";
    applyMode(auth, { grant_mode: "per_session", remember_hours: 8 });
    assert.equal(auth.mode, "per_use");
    assert.equal(auth.grantAll, false);
  });

  it("isLoosening determination", () => {
    const s = (grant_mode: "per_use" | "per_credential" | "per_session" | "remember", remember_hours = 8) => ({ grant_mode, remember_hours });
    assert.equal(isLoosening(s("per_credential"), s("per_session")), true);
    assert.equal(isLoosening(s("per_credential"), s("per_use")), false);
    assert.equal(isLoosening(s("remember", 8), s("remember", 24)), true);
    assert.equal(isLoosening(s("remember", 8), s("remember", 0)), true);
    assert.equal(isLoosening(s("remember", 0), s("remember", 8)), false);
    assert.equal(isLoosening(s("remember", 8), s("per_session")), false);
  });

  it("backward compatible with the old 'all' setting -> per_session; handshake hints match uniquely by name", () => {
    fs.writeFileSync(path.join(vault.dir, "settings.json"), JSON.stringify({ grant_mode: "all" }), { mode: 0o600 });
    assert.equal(readSettings(vault.dir).grant_mode, "per_session");
    assert.equal(resolveHint(vault, { type: "api_key", name: "openai" }), "api_key/openai");
    assert.equal(resolveHint(vault, { name: "github" }), "api_key/github");
    assert.equal(resolveHint(vault, { name: "nope" }), null);
  });
});

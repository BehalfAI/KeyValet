import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { dispatch } from "../helper/dispatch.js";
import { Vault } from "../helper/vault.js";
import { setLang, t } from "../shared/i18n.js";

// Each test file runs in its own process, so switching to English here doesn't affect other tests
describe("i18n", () => {
  it("t() picks the text for the current language", () => {
    setLang("zh");
    assert.equal(t("中", "en"), "中");
    setLang("en");
    assert.equal(t("中", "en"), "en");
  });

  it("in English mode, helper error messages are in English", async () => {
    setLang("en");
    const vault = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kv-i18n-")), "vault"));
    vault.init();
    const r = await dispatch(vault, { id: 1, op: "get", params: { type: "nope", name: "x", purpose: "test" } }, {});
    assert.equal(r.ok, false);
    assert.doesNotMatch(!r.ok ? r.error : "", /[一-龥]/);
    const r2 = await dispatch(vault, { id: 2, op: "get", params: { type: "nope", name: "x" } }, {});
    assert.doesNotMatch(!r2.ok ? r2.error : "", /[一-龥]/, "the error for a missing purpose is in English too");
  });

  it("in English mode, MCP tool descriptions and server instructions contain no Chinese", () => {
    const input = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
    ]
      .map((m) => JSON.stringify(m))
      .join("\n");
    const out = execFileSync(process.execPath, [path.join(process.cwd(), "dist/server/index.js")], {
      input: input + "\n",
      env: { ...process.env, KEYVALET_LANG: "en" },
      encoding: "utf8",
      timeout: 15_000,
    });
    const msgs = out.trim().split("\n").map((l) => JSON.parse(l) as { id?: number; result?: { tools?: unknown[]; instructions?: string } });
    const tools = msgs.find((m) => m.id === 2)!.result!.tools!;
    assert.ok(tools.length >= 25);
    const text = JSON.stringify(tools) + (msgs.find((m) => m.id === 1)!.result!.instructions ?? "");
    assert.doesNotMatch(text, /[一-龥]/);
  });
});

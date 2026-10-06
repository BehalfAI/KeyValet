import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { dispatch } from "../helper/dispatch.js";
import { Vault } from "../helper/vault.js";
import { setLang, t } from "../shared/i18n.js";

// 每个测试文件在独立进程中运行，这里切到英文不影响其他测试
describe("i18n", () => {
  it("t() 按当前语言取文案", () => {
    setLang("zh");
    assert.equal(t("中", "en"), "中");
    setLang("en");
    assert.equal(t("中", "en"), "en");
  });

  it("英文模式下 helper 的错误信息是英文", async () => {
    setLang("en");
    const vault = new Vault(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kv-i18n-")), "vault"));
    vault.init();
    const r = await dispatch(vault, { id: 1, op: "get", params: { type: "nope", name: "x", purpose: "test" } }, {});
    assert.equal(r.ok, false);
    assert.doesNotMatch(!r.ok ? r.error : "", /[一-龥]/);
    const r2 = await dispatch(vault, { id: 2, op: "get", params: { type: "nope", name: "x" } }, {});
    assert.doesNotMatch(!r2.ok ? r2.error : "", /[一-龥]/, "缺少 purpose 的提示也是英文");
  });

  it("英文模式下 MCP 工具说明和服务说明不含中文", () => {
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

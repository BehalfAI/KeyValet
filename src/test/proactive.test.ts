import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { recordSecrets } from "../server/gateway-env.js";
import { setFromTemplate } from "../server/tools/http.js";
import type { Op } from "../shared/protocol.js";

// 插件里的 hook 脚本是无依赖的 .mjs，不经过 tsc，按路径动态加载
const hookPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../claude-plugin/hooks/secrets.mjs");
type Hit = { id: string | null; label: string; preview: string; tool?: string; ambiguous?: boolean };
const hooks = (await import(pathToFileURL(hookPath).href)) as {
  detect(text: string, opts?: { generic?: boolean }): Hit[];
  detectReturnedSecrets(text: string): Array<{ preview: string }>;
  handle(mode: string, input: unknown): { hookSpecificOutput: Record<string, string> } | null;
};

const OPENAI = "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv";
const ANTHROPIC = "sk-ant-api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa-9z8y7x6w5v4u3t2";
const GITHUB = "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";

describe("hook：识别对话和工具调用中的密钥", () => {
  it("按前缀识别服务并给出模板；更具体的前缀优先", () => {
    const hits = hooks.detect(`openai ${OPENAI}, claude ${ANTHROPIC}, gh ${GITHUB}, aws AKIAIOSFODNN7EXAMPL3`);
    assert.deepEqual(
      hits.map((h) => h.id),
      ["anthropic", "openai", "github", "aws"],
    );
    assert.equal(hits.find((h) => h.id === "aws")!.tool, "credential_setup_aws");
  });

  it("不回显完整密钥，只给掩码", () => {
    const [h] = hooks.detect(`key: ${OPENAI}`);
    assert.equal(h!.preview, "sk-pro…StUv");
    const out = JSON.stringify(hooks.handle("prompt", { prompt: `use ${OPENAI}` }));
    assert.ok(!out.includes(OPENAI));
    assert.match(out, /credential_set/);
  });

  it("占位符、示例值、环境变量引用不算密钥", () => {
    for (const text of [
      "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "const key = process.env.OPENAI_API_KEY ?? 'your-api-key-here'",
      "token: ${GITHUB_TOKEN}",
      "password = getPasswordFromVaultService()",
    ]) {
      assert.deepEqual(hooks.detect(text, { generic: true }), [], text);
    }
  });

  it("通用写法（密码是 …）只在用户消息里识别", () => {
    const text = "数据库密码是 Xk29pLmQa7zR4w";
    assert.equal(hooks.detect(text, { generic: true }).length, 1);
    assert.equal(hooks.detect(text).length, 0);
  });

  it("PreToolUse：写文件或命令里带密钥时请用户确认", () => {
    const write = hooks.handle("tool", { tool_name: "Write", tool_input: { file_path: ".env", content: `OPENAI_API_KEY=${OPENAI}\n` } });
    assert.equal(write?.hookSpecificOutput.permissionDecision, "ask");
    const multi = hooks.handle("tool", { tool_name: "MultiEdit", tool_input: { edits: [{ new_string: "x" }, { new_string: GITHUB }] } });
    assert.equal(multi?.hookSpecificOutput.permissionDecision, "ask");
    const bash = hooks.handle("tool", { tool_name: "Bash", tool_input: { command: `curl -H "x-api-key: ${ANTHROPIC}" https://api.anthropic.com` } });
    assert.match(bash!.hookSpecificOutput.permissionDecisionReason!, /shell command/);
    assert.equal(hooks.handle("tool", { tool_name: "Bash", tool_input: { command: "npm test" } }), null);
    assert.equal(hooks.handle("tool", { tool_name: "Read", tool_input: { file_path: OPENAI } }), null);
  });

  it("PreToolUse：精确匹配 KeyValet 本会话已经返回过的值（不管像不像密钥）", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "kv-home-"));
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      const AUTH_CODE = "rqspdbmnzfvjbeac"; // 不匹配任何已知厂商前缀
      recordSecrets("sessX", [AUTH_CODE]);
      const hit = hooks.detectReturnedSecrets(`QQ_IMAP_PWD='${AUTH_CODE}' python3 -c '...'`);
      assert.equal(hit.length, 1);
      assert.ok(!hit[0]!.preview.includes(AUTH_CODE));

      const bash = hooks.handle("tool", { tool_name: "Bash", tool_input: { command: `QQ_IMAP_PWD='${AUTH_CODE}' python3 -c '...'` } });
      assert.equal(bash?.hookSpecificOutput.permissionDecision, "ask");
      assert.match(bash!.hookSpecificOutput.permissionDecisionReason!, /credential_export_file/);
      const out = JSON.stringify(bash);
      assert.ok(!out.includes(AUTH_CODE));

      assert.equal(hooks.handle("tool", { tool_name: "Bash", tool_input: { command: "echo unrelated" } }), null);
    } finally {
      process.env.HOME = prev;
    }
  });
});

describe("credential_set + template + value：用户已在对话中给出密钥", () => {
  function fakeSession() {
    const calls: Array<{ op: Op; params: Record<string, unknown> }> = [];
    return {
      calls,
      async request<T>(op: Op, params: Record<string, unknown>): Promise<T> {
        calls.push({ op, params });
        if (op === "exists") return false as T;
        if (op === "set") return { type: params.type, name: params.name, typeCreated: true, replaced: false } as T;
        return { ok: true } as T;
      },
    };
  }

  it("单个秘密字段的模板直接使用 value，不弹窗", async () => {
    const s = fakeSession();
    const r = await setFromTemplate(s, { template: "openai", name: "default", value: OPENAI, verify: false });
    const set = s.calls.find((c) => c.op === "set")!;
    assert.deepEqual(set.params.secrets, { apiKey: OPENAI });
    assert.deepEqual(r.secret_fields, ["apiKey"]);
  });

  it("多个秘密字段的模板拒绝 value，并且在解锁前就拒绝", async () => {
    const s = fakeSession();
    await assert.rejects(setFromTemplate(s, { template: "datadog", name: "default", value: "abc123def456" }), /2 个秘密字段/);
    await assert.rejects(setFromTemplate(s, { template: "openai", name: "default", value: "" }), /value 为空/);
    assert.equal(s.calls.length, 0);
  });
});

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { recordSecrets } from "../server/gateway-env.js";
import { setFromTemplate } from "../server/tools/http.js";
import type { Op } from "../shared/protocol.js";

// The hook script in the plugin is a dependency-free .mjs that bypasses tsc and is loaded dynamically by path
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

describe("hook: recognizing secrets in conversations and tool calls", () => {
  it("recognizes the service by prefix and suggests a template; more specific prefixes take priority", () => {
    const hits = hooks.detect(`openai ${OPENAI}, claude ${ANTHROPIC}, gh ${GITHUB}, aws AKIAIOSFODNN7EXAMPL3`);
    assert.deepEqual(
      hits.map((h) => h.id),
      ["anthropic", "openai", "github", "aws"],
    );
    assert.equal(hits.find((h) => h.id === "aws")!.tool, "credential_setup_aws");
  });

  it("doesn't echo the full secret, only a masked preview", () => {
    const [h] = hooks.detect(`key: ${OPENAI}`);
    assert.equal(h!.preview, "sk-pro…StUv");
    const out = JSON.stringify(hooks.handle("prompt", { prompt: `use ${OPENAI}` }));
    assert.ok(!out.includes(OPENAI));
    assert.match(out, /credential_set/);
  });

  it("placeholders, example values, and environment variable references don't count as secrets", () => {
    for (const text of [
      "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "const key = process.env.OPENAI_API_KEY ?? 'your-api-key-here'",
      "token: ${GITHUB_TOKEN}",
      "password = getPasswordFromVaultService()",
    ]) {
      assert.deepEqual(hooks.detect(text, { generic: true }), [], text);
    }
  });

  it("generic phrasing (e.g. 'password is ...') is only recognized in user messages", () => {
    const text = "database password is Xk29pLmQa7zR4w";
    assert.equal(hooks.detect(text, { generic: true }).length, 1);
    assert.equal(hooks.detect(text).length, 0);
  });

  it("PreToolUse: asks the user to confirm when a file write or command contains a secret", () => {
    const write = hooks.handle("tool", { tool_name: "Write", tool_input: { file_path: ".env", content: `OPENAI_API_KEY=${OPENAI}\n` } });
    assert.equal(write?.hookSpecificOutput.permissionDecision, "ask");
    const multi = hooks.handle("tool", { tool_name: "MultiEdit", tool_input: { edits: [{ new_string: "x" }, { new_string: GITHUB }] } });
    assert.equal(multi?.hookSpecificOutput.permissionDecision, "ask");
    const bash = hooks.handle("tool", { tool_name: "Bash", tool_input: { command: `curl -H "x-api-key: ${ANTHROPIC}" https://api.anthropic.com` } });
    assert.match(bash!.hookSpecificOutput.permissionDecisionReason!, /shell command/);
    assert.equal(hooks.handle("tool", { tool_name: "Bash", tool_input: { command: "npm test" } }), null);
    assert.equal(hooks.handle("tool", { tool_name: "Read", tool_input: { file_path: OPENAI } }), null);
  });

  it("PreToolUse: exact match against values KeyValet already returned this session (regardless of whether they look like secrets)", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "kv-home-"));
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      const AUTH_CODE = "rqspdbmnzfvjbeac"; // doesn't match any known vendor prefix
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

describe("credential_set + template + value: the user already gave the secret in the conversation", () => {
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

  it("a template with a single secret field uses value directly, no dialog", async () => {
    const s = fakeSession();
    const r = await setFromTemplate(s, { template: "openai", name: "default", value: OPENAI, verify: false });
    const set = s.calls.find((c) => c.op === "set")!;
    assert.deepEqual(set.params.secrets, { apiKey: OPENAI });
    assert.deepEqual(r.secret_fields, ["apiKey"]);
  });

  it("a template with multiple secret fields rejects value, and rejects it before unlocking", async () => {
    const s = fakeSession();
    await assert.rejects(setFromTemplate(s, { template: "datadog", name: "default", value: "abc123def456" }), /2 个秘密字段/);
    await assert.rejects(setFromTemplate(s, { template: "openai", name: "default", value: "" }), /value 为空/);
    assert.equal(s.calls.length, 0);
  });
});

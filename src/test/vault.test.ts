import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, it } from "node:test";
import { dispatch } from "../helper/dispatch.js";
import { Vault, VaultError } from "../helper/vault.js";

let dir: string;
let vault: Vault;

beforeEach(() => {
  dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "credmcp-")), "vault");
  vault = new Vault(dir);
  vault.init();
});

describe("Vault", () => {
  it("creates the directory and master key, permissions restricted to the owner only", () => {
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    assert.equal(fs.statSync(vault.keyPath).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(vault.keyPath).length, 32);
  });

  it("creates the type first when writing if it doesn't exist yet, then writes the value", () => {
    assert.equal(vault.typeExists("api_key"), false);
    const r1 = vault.set({ type: "api_key", name: "openai", value: "sk-1", typeDescription: "API Key" });
    assert.deepEqual(r1, { type: "api_key", name: "openai", typeCreated: true, replaced: false });
    assert.equal(vault.typeExists("api_key"), true);
    assert.equal(vault.listTypes()[0]!.description, "API Key");

    const r2 = vault.set({ type: "api_key", name: "anthropic", value: "sk-2" });
    assert.equal(r2.typeCreated, false);
    assert.equal(vault.listTypes()[0]!.count, 2);
  });

  it("an existing credential can only be overwritten with explicit overwrite", () => {
    vault.set({ type: "password", name: "db", value: "a" });
    assert.throws(() => vault.set({ type: "password", name: "db", value: "b" }), VaultError);
    assert.equal(vault.get("password", "db").value, "a");
    const r = vault.set({ type: "password", name: "db", value: "b", overwrite: true });
    assert.equal(r.replaced, true);
    assert.equal(vault.get("password", "db").value, "b");
  });

  it("type and name are case-insensitive", () => {
    vault.set({ type: "API_Key", name: "OpenAI", value: "sk" });
    assert.equal(vault.get("api_key", "openai").value, "sk");
    assert.equal(vault.listTypes().length, 1);
  });

  it("list does not return credential values, attributes are preserved", () => {
    vault.set({ type: "password", name: "github", value: "secret!", attributes: { username: "me" } });
    const items = vault.list();
    assert.equal(items.length, 1);
    assert.equal("value" in items[0]!, false);
    assert.deepEqual(items[0]!.attributes, { username: "me" });
  });

  it("stored on disk as ciphertext", () => {
    vault.set({ type: "api_key", name: "x", value: "PLAINTEXT-MARKER-12345" });
    const raw = fs.readFileSync(vault.dataPath, "utf8");
    assert.equal(raw.includes("PLAINTEXT-MARKER"), false);
    assert.equal(raw.includes("api_key"), false);
  });

  it("refuses to read when the ciphertext has been tampered with", () => {
    vault.set({ type: "api_key", name: "x", value: "v" });
    const file = JSON.parse(fs.readFileSync(vault.dataPath, "utf8"));
    const ct = Buffer.from(file.ct, "base64");
    ct[0]! ^= 1;
    file.ct = ct.toString("base64");
    fs.writeFileSync(vault.dataPath, JSON.stringify(file));
    assert.throws(() => vault.get("api_key", "x"), /解密失败/);
  });

  it("refuses to operate when permissions are too broad", () => {
    fs.chmodSync(vault.keyPath, 0o644);
    assert.throws(() => new Vault(dir).init(), /权限过宽/);
    fs.chmodSync(vault.keyPath, 0o600);
    fs.chmodSync(dir, 0o755);
    assert.throws(() => new Vault(dir).init(), /权限过宽/);
  });

  it("a symlinked key file is rejected", () => {
    const real = path.join(path.dirname(dir), "evil.key");
    fs.writeFileSync(real, Buffer.alloc(32), { mode: 0o600 });
    fs.rmSync(vault.keyPath);
    fs.symlinkSync(real, vault.keyPath);
    assert.throws(() => new Vault(dir).init(), /符号链接/);
  });

  it("names on the prototype chain are not treated as already existing", () => {
    assert.equal(vault.typeExists("constructor"), false);
    vault.set({ type: "constructor", name: "tostring", value: "v" });
    assert.equal(vault.get("constructor", "tostring").value, "v");
    assert.throws(() => vault.get("api_key", "constructor"), /不存在/);
  });

  it("rejects invalid names", () => {
    for (const bad of ["", "../x", "__proto__", "a b", "x/y", "a".repeat(65)]) {
      assert.throws(() => vault.set({ type: bad, name: "n", value: "v" }), VaultError, bad);
    }
    assert.throws(() => vault.set({ type: "t", name: "n", value: "" }), VaultError);
  });

  it("a non-empty type cannot be deleted", () => {
    vault.set({ type: "token", name: "a", value: "v" });
    assert.throws(() => vault.deleteType("token"), /还有 1 个凭证/);
    vault.delete("token", "a");
    vault.deleteType("token");
    assert.equal(vault.listTypes().length, 0);
  });

  it("is compatible with data encrypted before the rename (credential-mcp); the next write upgrades it to the new identifier", () => {
    const key = fs.readFileSync(vault.keyPath);
    const data = { version: 1, types: { api_key: { description: "", createdAt: "t", updatedAt: "t" } }, credentials: { api_key: { old: { value: "legacy-secret", description: "", attributes: {}, createdAt: "t", updatedAt: "t" } } } };
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(Buffer.from("credential-mcp/vault/v1"));
    const ct = Buffer.concat([c.update(JSON.stringify(data)), c.final()]);
    fs.writeFileSync(vault.dataPath, JSON.stringify({ v: 1, alg: "aes-256-gcm", iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ct: ct.toString("base64") }), { mode: 0o600 });
    fs.chmodSync(vault.dataPath, 0o600);

    const reopened = new Vault(dir);
    reopened.init();
    assert.equal(reopened.get("api_key", "old").value, "legacy-secret");
    vault.set({ type: "api_key", name: "new", value: "v" });
    const file = JSON.parse(fs.readFileSync(vault.dataPath, "utf8"));
    const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
    d.setAAD(Buffer.from("keyvalet/vault/v1"));
    d.setAuthTag(Buffer.from(file.tag, "base64"));
    const plain = JSON.parse(Buffer.concat([d.update(Buffer.from(file.ct, "base64")), d.final()]).toString());
    assert.equal(plain.credentials.api_key.old.value, "legacy-secret", "old data is preserved and re-encrypted under the new identifier");
  });

  it("multiple instances (multiple sessions) read and write the same vault", () => {
    const other = new Vault(dir);
    other.init();
    vault.set({ type: "api_key", name: "a", value: "1" });
    other.set({ type: "api_key", name: "b", value: "2" });
    assert.equal(vault.list().length, 2);
  });
});

describe("dispatch", () => {
  const ctx = { session: "sess-1", cwd: "/tmp/p", client: "test" };

  it("returns a result; the audit log includes purpose and session, but not the credential value", async () => {
    const set = await dispatch(vault, { id: 2, op: "set", params: { type: "api_key", name: "openai", value: "SECRET-VALUE-999", purpose: "Save a test secret" } }, ctx);
    assert.deepEqual(set, { id: 2, ok: true, result: { type: "api_key", name: "openai", typeCreated: true, replaced: false } });
    const get = await dispatch(vault, { id: 3, op: "get", params: { type: "api_key", name: "openai", purpose: "Call the OpenAI API" } }, ctx);
    assert.equal(get.ok && (get.result as { value: string }).value, "SECRET-VALUE-999");

    const log = fs.readFileSync(vault.auditPath, "utf8");
    assert.equal(log.includes("SECRET-VALUE-999"), false);
    assert.match(log, /"op":"get","type":"api_key","name":"openai"/);
    assert.match(log, /"purpose":"Call the OpenAI API"/);
    assert.match(log, /"session":"sess-1"/);
  });

  it("reading/modifying a credential must state a purpose", async () => {
    vault.set({ type: "api_key", name: "x", value: "v" });
    for (const [op, params] of [
      ["get", { type: "api_key", name: "x" }],
      ["set", { type: "api_key", name: "y", value: "v" }],
      ["delete", { type: "api_key", name: "x" }],
      ["accessToken", { type: "api_key", name: "x" }],
    ] as const) {
      const r = await dispatch(vault, { id: 1, op, params: { ...params, purpose: " " } }, ctx);
      assert.equal(r.ok, false, op);
      assert.match(!r.ok ? r.error : "", /目的/);
    }
    // metadata operations like list don't need one
    assert.equal((await dispatch(vault, { id: 1, op: "list", params: {} }, ctx)).ok, true);
  });

  it("audit log query: filters by session/credential/op, newest first", async () => {
    await dispatch(vault, { id: 1, op: "set", params: { type: "api_key", name: "a", value: "v", purpose: "store a" } }, ctx);
    await dispatch(vault, { id: 2, op: "get", params: { type: "api_key", name: "a", purpose: "read a" } }, ctx);
    await dispatch(vault, { id: 3, op: "get", params: { type: "api_key", name: "a", purpose: "read a (other session)" } }, { session: "sess-2" });
    await dispatch(vault, { id: 4, op: "get", params: { type: "api_key", name: "missing", purpose: "read a nonexistent one" } }, ctx);

    const q = async (params: Record<string, unknown>) => {
      const r = await dispatch(vault, { id: 9, op: "auditQuery", params }, ctx);
      assert.ok(r.ok);
      return r.result as { current_session: string; entries: Array<Record<string, unknown>> };
    };
    const all = await q({});
    assert.equal(all.current_session, "sess-1");
    assert.deepEqual(all.entries.map((e) => e.purpose), ["read a nonexistent one", "read a (other session)", "read a", "store a"]);
    assert.equal(all.entries[0]!.ok, false);
    assert.match(String(all.entries[0]!.error), /不存在/);

    assert.deepEqual((await q({ this_session: true })).entries.map((e) => e.purpose), ["read a nonexistent one", "read a", "store a"]);
    assert.deepEqual((await q({ name: "a", op: "get" })).entries.map((e) => e.session), ["sess-2", "sess-1"]);
    assert.equal((await q({ limit: 1 })).entries.length, 1);
    assert.equal(JSON.stringify(all).includes('"value"'), false);
  });

  it("errors return as ok:false; unknown operations are rejected", async () => {
    const r = await dispatch(vault, { id: 1, op: "get", params: { type: "nope", name: "x", purpose: "test" } }, ctx);
    assert.deepEqual(r, { id: 1, ok: false, error: '凭证类型 "nope" 不存在' });
    const u = await dispatch(vault, { id: 2, op: "rm -rf" } as never, ctx);
    assert.equal(u.ok, false);
  });
});

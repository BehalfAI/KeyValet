// Encrypted credential vault. Depends only on node's built-in modules -- this code runs as root.
//
// Directory layout (all 0600/0700, owned by the process running it, which is root in production):
//   master.key   32 random bytes, the master key
//   vault.enc    JSON encrypted with AES-256-GCM
//   audit.log    audit log (never contains credential values)
//   .lock/       write lock (mkdir is atomic), serializing concurrent writes from multiple sessions

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { InjectRule, TestRequest } from "../shared/templates.js";
import { t } from "../shared/i18n.js";

export class VaultError extends Error {}

export interface TypeRecord {
  description: string;
  createdAt: string;
  updatedAt: string;
}

/** The kinds of protocol-based credentials; static is just a plain “store whatever, retrieve whatever” */
export const KINDS = ["static", "oauth2", "google_service_account", "github_app", "jwt", "totp", "aws"] as const;
export type Kind = (typeof KINDS)[number];

export interface HttpConfig {
  /** Injection rule (required for static credentials; omitted for token-based credentials, which auto-inject Authorization: Bearer <token>) */
  inject?: InjectRule;
  /** Hosts a proxied request is allowed to reach (exact match; *.example.com matches its subdomains) */
  allowed_hosts: string[];
  /** Proxy-only: forbids get from reading out the secret */
  proxy_only: boolean;
  test?: TestRequest;
}

export interface CredentialRecord {
  /** Defaults to static if absent (for compatibility with old data) */
  kind?: Kind;
  /** The value of a static credential; an empty string for protocol-based credentials */
  value: string;
  /** Non-sensitive configuration for a protocol-based credential (endpoint, client_id, scope, etc.) */
  config?: Record<string, unknown>;
  /** Long-lived secrets of a protocol-based credential (refresh token, private key, seed, ...); never leaves the root process */
  secrets?: Record<string, string>;
  /** Protocol runtime state (cached short-lived token, expiry, etc.) */
  state?: Record<string, unknown>;
  /** Random version number generated on each setProtocol; validated before writing back an async operation's result, to prevent writing over a configuration that was replaced in the meantime */
  generation?: string;
  /** Proxy call configuration (injection rule, allowed hosts, proxy-only flag, test request) */
  http?: HttpConfig;
  /** The template ID used at creation time */
  template?: string;
  description: string;
  attributes: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

interface VaultData {
  version: 1;
  types: Record<string, TypeRecord>;
  credentials: Record<string, Record<string, CredentialRecord>>;
}

interface EncryptedFile {
  v: 1;
  alg: "aes-256-gcm";
  iv: string;
  tag: string;
  ct: string;
}

const AAD = Buffer.from("keyvalet/vault/v1");
/** Data written under the old name (credential-mcp) before the rename: read for compatibility, and upgraded to the new identifier on the next write */
const LEGACY_AAD = Buffer.from("credential-mcp/vault/v1");
const KEY_BYTES = 32;
const LOCK_TIMEOUT_MS = 10_000;
const LOCK_STALE_MS = 30_000;

const TYPE_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const NAME_RE = /^[a-z0-9][a-z0-9_.@:-]{0,127}$/;
const ATTR_KEY_RE = /^[a-zA-Z0-9_.-]{1,64}$/;
export const MAX_VALUE_LENGTH = 64 * 1024;
const MAX_DESCRIPTION_LENGTH = 500;
const MAX_ATTRIBUTES = 20;
const MAX_ATTRIBUTE_LENGTH = 1000;
const MAX_PROTOCOL_BYTES = 128 * 1024;

export function normalizeType(input: unknown): string {
  if (typeof input !== "string") throw new VaultError(t("凭证类型必须是字符串", "Credential type must be a string"));
  const ty = input.trim().toLowerCase();
  if (!TYPE_RE.test(ty)) {
    throw new VaultError(
      t(
        `非法的凭证类型 "${input}"：只允许小写字母、数字、_ . -，以字母或数字开头，最长 64`,
        `Invalid credential type "${input}": only lowercase letters, digits, _ . - are allowed, must start with a letter or digit, max 64 characters`,
      ),
    );
  }
  return ty;
}

export function normalizeName(input: unknown): string {
  if (typeof input !== "string") throw new VaultError(t("凭证名必须是字符串", "Credential name must be a string"));
  const n = input.trim().toLowerCase();
  if (!NAME_RE.test(n)) {
    throw new VaultError(
      t(
        `非法的凭证名 "${input}"：只允许小写字母、数字、_ . @ : -，以字母或数字开头，最长 128`,
        `Invalid credential name "${input}": only lowercase letters, digits, _ . @ : - are allowed, must start with a letter or digit, max 128 characters`,
      ),
    );
  }
  return n;
}

function checkDescription(d: unknown): string {
  if (d === undefined || d === null) return "";
  if (typeof d !== "string" || d.length > MAX_DESCRIPTION_LENGTH) {
    throw new VaultError(t(`description 必须是不超过 ${MAX_DESCRIPTION_LENGTH} 字符的字符串`, `description must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters`));
  }
  return d;
}

function checkValue(v: unknown): string {
  if (typeof v !== "string" || v.length === 0 || v.length > MAX_VALUE_LENGTH) {
    throw new VaultError(t(`凭证值必须是 1~${MAX_VALUE_LENGTH} 字符的字符串`, `Credential value must be a string of 1-${MAX_VALUE_LENGTH} characters`));
  }
  return v;
}

function checkAttributes(a: unknown): Record<string, string> {
  if (a === undefined || a === null) return {};
  if (typeof a !== "object" || Array.isArray(a)) throw new VaultError(t("attributes 必须是对象", "attributes must be an object"));
  const entries = Object.entries(a as Record<string, unknown>);
  if (entries.length > MAX_ATTRIBUTES) throw new VaultError(t(`attributes 最多 ${MAX_ATTRIBUTES} 项`, `attributes may have at most ${MAX_ATTRIBUTES} entries`));
  const out: Record<string, string> = {};
  for (const [k, v] of entries) {
    if (!ATTR_KEY_RE.test(k)) throw new VaultError(t(`非法的 attribute 名 "${k}"`, `Invalid attribute name "${k}"`));
    if (typeof v !== "string" || v.length > MAX_ATTRIBUTE_LENGTH) {
      throw new VaultError(t(`attribute "${k}" 必须是不超过 ${MAX_ATTRIBUTE_LENGTH} 字符的字符串`, `attribute "${k}" must be a string of at most ${MAX_ATTRIBUTE_LENGTH} characters`));
    }
    out[k] = v;
  }
  return out;
}

/** Reads only the object's own property, to avoid names like "constructor" hitting the prototype chain */
function own<T>(obj: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function emptyData(): VaultData {
  return { version: 1, types: {}, credentials: {} };
}

export class Vault {
  readonly keyPath: string;
  readonly dataPath: string;
  readonly auditPath: string;
  private readonly lockPath: string;
  private key: Buffer | null = null;

  constructor(readonly dir: string) {
    this.keyPath = path.join(dir, "master.key");
    this.dataPath = path.join(dir, "vault.enc");
    this.auditPath = path.join(dir, "audit.log");
    this.lockPath = path.join(dir, ".lock");
  }

  /** Creates/validates the directory and master key. Refuses to operate if directory or file permissions are wrong, rather than “fixing” them. */
  init(): void {
    if (!fs.existsSync(this.dir)) {
      fs.mkdirSync(this.dir, { recursive: false, mode: 0o700 });
    }
    this.assertPrivate(this.dir, true);

    if (!fs.existsSync(this.keyPath)) {
      const key = crypto.randomBytes(KEY_BYTES);
      try {
        fs.writeFileSync(this.keyPath, key, { mode: 0o600, flag: "wx" });
      } catch (e) {
        // Another session initialized concurrently: use the key it wrote
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
    }
    this.assertPrivate(this.keyPath, false);
    const key = fs.readFileSync(this.keyPath);
    if (key.length !== KEY_BYTES) throw new VaultError(t("主密钥文件已损坏（长度不对）", "Master key file is corrupted (wrong length)"));
    this.key = key;

    if (fs.existsSync(this.dataPath)) {
      this.assertPrivate(this.dataPath, false);
      this.read(); // catch a key/data mismatch as early as possible
    }
  }

  private assertPrivate(p: string, isDir: boolean): void {
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) throw new VaultError(t(`${p} 不能是符号链接`, `${p} must not be a symbolic link`));
    if (isDir ? !st.isDirectory() : !st.isFile()) throw new VaultError(t(`${p} 类型不对`, `${p} has the wrong file type`));
    if (st.uid !== process.getuid!()) throw new VaultError(t(`${p} 的属主不是当前用户（应为 root）`, `${p} is not owned by the current user (should be root)`));
    if ((st.mode & 0o077) !== 0) {
      throw new VaultError(
        t(
          `${p} 权限过宽（${(st.mode & 0o777).toString(8)}），必须只有属主可访问`,
          `${p} has overly broad permissions (${(st.mode & 0o777).toString(8)}); it must be accessible only by its owner`,
        ),
      );
    }
  }

  private requireKey(): Buffer {
    if (!this.key) throw new VaultError(t("凭证库未初始化", "Vault is not initialized"));
    return this.key;
  }

  private read(): VaultData {
    if (!fs.existsSync(this.dataPath)) return emptyData();
    const file = JSON.parse(fs.readFileSync(this.dataPath, "utf8")) as EncryptedFile;
    if (file.v !== 1 || file.alg !== "aes-256-gcm") throw new VaultError(t("不支持的凭证库格式", "Unsupported vault format"));
    const key = this.requireKey(); // kept outside the loop: errors like “not initialized” must be reported accurately, not masked as a “decryption failure”
    let plain: Buffer | null = null;
    for (const aad of [AAD, LEGACY_AAD]) {
      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
        decipher.setAAD(aad);
        decipher.setAuthTag(Buffer.from(file.tag, "base64"));
        plain = Buffer.concat([decipher.update(Buffer.from(file.ct, "base64")), decipher.final()]);
        break;
      } catch {
        /* try the next identifier */
      }
    }
    if (!plain) throw new VaultError(t("凭证库解密失败：数据被篡改或主密钥不匹配", "Failed to decrypt vault: data has been tampered with or the master key does not match"));
    const data = JSON.parse(plain.toString("utf8")) as VaultData;
    plain.fill(0);
    if (data.version !== 1) throw new VaultError(t("不支持的凭证库版本", "Unsupported vault version"));
    return data;
  }

  private write(data: VaultData): void {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.requireKey(), iv);
    cipher.setAAD(AAD);
    const plain = Buffer.from(JSON.stringify(data), "utf8");
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    plain.fill(0);
    const file: EncryptedFile = {
      v: 1,
      alg: "aes-256-gcm",
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ct: ct.toString("base64"),
    };
    // Atomic write: temp file + fsync + rename, so a crash never leaves a half-written file
    const tmp = `${this.dataPath}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
    const fd = fs.openSync(tmp, "wx", 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(file));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.dataPath);
    const dirFd = fs.openSync(this.dir, "r");
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }

  /** Read-modify-write, holding a cross-process write lock */
  private mutate<T>(fn: (data: VaultData) => T): T {
    this.lock();
    try {
      const data = this.read();
      const result = fn(data);
      this.write(data);
      return result;
    } finally {
      this.unlock();
    }
  }

  private lock(): void {
    const deadline = Date.now() + LOCK_TIMEOUT_MS;
    for (;;) {
      try {
        fs.mkdirSync(this.lockPath, { mode: 0o700 });
        return;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
      try {
        if (Date.now() - fs.statSync(this.lockPath).mtimeMs > LOCK_STALE_MS) {
          fs.rmdirSync(this.lockPath); // the lock-holding process has crashed
          continue;
        }
      } catch {
        continue; // the lock was just released
      }
      if (Date.now() > deadline) throw new VaultError(t("凭证库正忙（获取写锁超时）", "Vault is busy (timed out acquiring write lock)"));
      sleepSync(50);
    }
  }

  private unlock(): void {
    try {
      fs.rmdirSync(this.lockPath);
    } catch {
      /* ignore */
    }
  }

  /** Reads the complete lines at the tail of the audit log (at most maxBytes bytes) */
  readAuditTail(maxBytes = 4 * 1024 * 1024): string[] {
    let fd: number;
    try {
      fd = fs.openSync(this.auditPath, "r");
    } catch {
      return [];
    }
    try {
      const size = fs.fstatSync(fd).size;
      const len = Math.min(size, maxBytes);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, size - len);
      const lines = buf.toString("utf8").split("\n");
      if (len < size) lines.shift(); // the first line may be incomplete
      return lines.filter((l) => l.trim());
    } finally {
      fs.closeSync(fd);
    }
  }

  audit(entry: Record<string, unknown>): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), pid: process.pid, ...entry }) + "\n";
    fs.appendFileSync(this.auditPath, line, { mode: 0o600 });
    // Rotate once it exceeds 10MB (keeping one previous copy), to prevent unbounded growth
    try {
      if (fs.statSync(this.auditPath).size > 10 * 1024 * 1024) fs.renameSync(this.auditPath, `${this.auditPath}.1`);
    } catch {
      /* ignore */
    }
  }

  // ---------- business operations ----------

  listTypes(): Array<{ name: string; description: string; count: number; createdAt: string }> {
    const data = this.read();
    return Object.keys(data.types)
      .sort()
      .map((name) => ({
        name,
        description: data.types[name]!.description,
        count: Object.keys(own(data.credentials, name) ?? {}).length,
        createdAt: data.types[name]!.createdAt,
      }));
  }

  typeExists(type: unknown): boolean {
    return own(this.read().types, normalizeType(type)) !== undefined;
  }

  createType(nameIn: unknown, descriptionIn?: unknown): { name: string; created: boolean } {
    const name = normalizeType(nameIn);
    const description = checkDescription(descriptionIn);
    return this.mutate((data) => {
      if (own(data.types, name)) return { name, created: false };
      const now = new Date().toISOString();
      data.types[name] = { description, createdAt: now, updatedAt: now };
      data.credentials[name] = {};
      return { name, created: true };
    });
  }

  deleteType(nameIn: unknown): { name: string } {
    const name = normalizeType(nameIn);
    return this.mutate((data) => {
      if (!own(data.types, name)) throw new VaultError(t(`凭证类型 "${name}" 不存在`, `Credential type "${name}" not found`));
      const count = Object.keys(own(data.credentials, name) ?? {}).length;
      if (count > 0) throw new VaultError(t(`凭证类型 "${name}" 下还有 ${count} 个凭证，请先删除它们`, `Credential type "${name}" still has ${count} credential(s); delete them first`));
      delete data.types[name];
      delete data.credentials[name];
      return { name };
    });
  }

  list(typeIn?: unknown): Array<{
    type: string;
    name: string;
    kind: Kind;
    description: string;
    attributes: Record<string, string>;
    template?: string;
    http?: { allowed_hosts: string[]; proxy_only: boolean; can_test: boolean };
    updatedAt: string;
  }> {
    const data = this.read();
    let types = Object.keys(data.types).sort();
    if (typeIn !== undefined && typeIn !== null && typeIn !== "") {
      const ty = normalizeType(typeIn);
      if (!own(data.types, ty)) throw new VaultError(t(`凭证类型 "${ty}" 不存在`, `Credential type "${ty}" not found`));
      types = [ty];
    }
    const out = [];
    for (const type of types) {
      const creds = own(data.credentials, type) ?? {};
      for (const name of Object.keys(creds).sort()) {
        const c = creds[name]!;
        out.push({
          type,
          name,
          kind: c.kind ?? "static",
          description: c.description,
          attributes: c.attributes,
          ...(c.template ? { template: c.template } : {}),
          ...(c.http ? { http: { allowed_hosts: c.http.allowed_hosts, proxy_only: c.http.proxy_only, can_test: !!c.http.test } } : {}),
          updatedAt: c.updatedAt,
        });
      }
    }
    return out;
  }

  exists(typeIn: unknown, nameIn: unknown): boolean {
    const type = normalizeType(typeIn);
    const name = normalizeName(nameIn);
    const creds = own(this.read().credentials, type);
    return !!creds && own(creds, name) !== undefined;
  }

  /** A deep copy of the full record (including secrets). For use only by protocol implementations inside the root helper and the root CLI. */
  getRecord(typeIn: unknown, nameIn: unknown): { type: string; name: string; record: CredentialRecord } {
    const type = normalizeType(typeIn);
    const name = normalizeName(nameIn);
    const data = this.read();
    if (!own(data.types, type)) throw new VaultError(t(`凭证类型 "${type}" 不存在`, `Credential type "${type}" not found`));
    const c = own(own(data.credentials, type) ?? {}, name);
    if (!c) throw new VaultError(t(`凭证 "${type}/${name}" 不存在`, `Credential "${type}/${name}" not found`));
    return { type, name, record: structuredClone(c) };
  }

  /** Reads the value of a static credential. A protocol-based credential's secrets cannot be retrieved this way. */
  get(typeIn: unknown, nameIn: unknown): {
    type: string;
    name: string;
    value: string;
    fields?: Record<string, string>;
    description: string;
    attributes: Record<string, string>;
    updatedAt: string;
  } {
    const { type, name, record: c } = this.getRecord(typeIn, nameIn);
    if (c.kind && c.kind !== "static") {
      throw new VaultError(t(`"${type}/${name}" 是 ${c.kind} 协议凭证，其长期秘密不能直接读取`, `"${type}/${name}" is a ${c.kind} protocol credential; its long-term secrets cannot be read directly`));
    }
    if (c.http?.proxy_only) {
      throw new VaultError(
        t(
          `"${type}/${name}" 设置为只能代理调用，不能读出秘密；请用 credential_http_request`,
          `"${type}/${name}" is proxy-only; its secret cannot be read. Use credential_http_request instead`,
        ),
      );
    }
    return {
      type,
      name,
      value: c.value,
      ...(c.secrets ? { fields: { ...c.secrets } } : {}),
      description: c.description,
      attributes: c.attributes,
      updatedAt: c.updatedAt,
    };
  }

  /**
   * Writes a credential: first checks the credential type, creating it first if it doesn't exist, then
   * writes the value. Both steps complete within the same write lock and the same disk write, so there's
   * no intermediate state where “the type was created but the value wasn't written.”
   */
  set(params: {
    type: unknown;
    name: unknown;
    value?: unknown;
    /** Multiple secret fields (template credential); value may be omitted when this is provided */
    secrets?: Record<string, string>;
    http?: HttpConfig;
    template?: string;
    description?: unknown;
    attributes?: unknown;
    typeDescription?: unknown;
    overwrite?: unknown;
  }): { type: string; name: string; typeCreated: boolean; replaced: boolean } {
    const type = normalizeType(params.type);
    const name = normalizeName(params.name);
    const secrets = params.secrets && Object.keys(params.secrets).length ? params.secrets : undefined;
    const value = secrets && (params.value === undefined || params.value === "") ? "" : checkValue(params.value);
    if (secrets && Buffer.byteLength(JSON.stringify(secrets)) > MAX_PROTOCOL_BYTES) throw new VaultError(t("秘密字段过大", "Secret fields are too large"));
    const description = checkDescription(params.description);
    const attributes = checkAttributes(params.attributes);
    const typeDescription = checkDescription(params.typeDescription);
    const overwrite = params.overwrite === true;

    return this.mutate((data) => {
      const now = new Date().toISOString();
      let typeCreated = false;
      if (!own(data.types, type)) {
        data.types[type] = { description: typeDescription, createdAt: now, updatedAt: now };
        typeCreated = true;
      }
      const creds = own(data.credentials, type) ?? (data.credentials[type] = {});
      const existing = own(creds, name);
      if (existing && !overwrite) {
        throw new VaultError(t(`凭证 "${type}/${name}" 已存在；如需替换请设置 overwrite=true`, `Credential "${type}/${name}" already exists; set overwrite=true to replace it`));
      }
      creds[name] = {
        value,
        ...(secrets ? { secrets } : {}),
        ...(params.http ? { http: params.http } : {}),
        ...(params.template ? { template: params.template } : {}),
        description: description || existing?.description || "",
        attributes: Object.keys(attributes).length ? attributes : (existing?.attributes ?? {}),
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      data.types[type]!.updatedAt = now;
      return { type, name, typeCreated, replaced: !!existing };
    });
  }

  /**
   * Writes a protocol-based credential. Same as set: the type is created first if it doesn't exist, then
   * the credential is written. The contents of config/secrets are validated by the caller (protocols/*).
   */
  setProtocol(params: {
    type: unknown;
    name: unknown;
    kind: Kind;
    config: Record<string, unknown>;
    secrets: Record<string, string>;
    description?: unknown;
    typeDescription?: unknown;
    overwrite?: boolean;
  }): { type: string; name: string; typeCreated: boolean; replaced: boolean } {
    const type = normalizeType(params.type);
    const name = normalizeName(params.name);
    const description = checkDescription(params.description);
    const typeDescription = checkDescription(params.typeDescription);
    if (!KINDS.includes(params.kind) || params.kind === "static") throw new VaultError(t(`非法的协议种类 ${params.kind}`, `Invalid protocol kind ${params.kind}`));
    if (Buffer.byteLength(JSON.stringify([params.config, params.secrets])) > MAX_PROTOCOL_BYTES) {
      throw new VaultError(t("协议凭证数据过大", "Protocol credential data is too large"));
    }
    return this.mutate((data) => {
      const now = new Date().toISOString();
      let typeCreated = false;
      if (!own(data.types, type)) {
        data.types[type] = { description: typeDescription, createdAt: now, updatedAt: now };
        typeCreated = true;
      }
      const creds = own(data.credentials, type) ?? (data.credentials[type] = {});
      const existing = own(creds, name);
      if (existing && !params.overwrite) {
        throw new VaultError(t(`凭证 "${type}/${name}" 已存在；如需替换请设置 overwrite=true`, `Credential "${type}/${name}" already exists; set overwrite=true to replace it`));
      }
      creds[name] = {
        kind: params.kind,
        value: "",
        config: params.config,
        secrets: params.secrets,
        state: {},
        generation: crypto.randomBytes(12).toString("hex"),
        description: description || existing?.description || "",
        attributes: {},
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      data.types[type]!.updatedAt = now;
      return { type, name, typeCreated, replaced: !!existing };
    });
  }

  /**
   * Modifies a protocol credential's state/secrets within the write lock (e.g. a refreshed token).
   * generation must match what was read: if the credential was replaced in the meantime (even with the
   * same kind), the write is refused -- otherwise a refreshed-back refresh token could get written into
   * a malicious configuration the agent just swapped in.
   */
  patchRecord(typeIn: unknown, nameIn: unknown, kind: Kind, generation: string | undefined, fn: (record: CredentialRecord) => void): void {
    const type = normalizeType(typeIn);
    const name = normalizeName(nameIn);
    this.mutate((data) => {
      const c = own(own(data.credentials, type) ?? {}, name);
      if (!c) throw new VaultError(t(`凭证 "${type}/${name}" 不存在`, `Credential "${type}/${name}" not found`));
      if ((c.kind ?? "static") !== kind || c.generation !== generation) {
        throw new VaultError(t(`凭证 "${type}/${name}" 在操作期间被修改，已放弃写入，请重试`, `Credential "${type}/${name}" was modified during the operation; write aborted, please retry`));
      }
      fn(c);
      c.updatedAt = new Date().toISOString();
    });
  }

  /** Modifies the proxy call configuration (for a credential of any kind). fn returns the new configuration; validation is done by the caller. */
  updateHttp(typeIn: unknown, nameIn: unknown, fn: (record: CredentialRecord) => HttpConfig | undefined): void {
    const type = normalizeType(typeIn);
    const name = normalizeName(nameIn);
    this.mutate((data) => {
      const c = own(own(data.credentials, type) ?? {}, name);
      if (!c) throw new VaultError(t(`凭证 "${type}/${name}" 不存在`, `Credential "${type}/${name}" not found`));
      const next = fn(structuredClone(c));
      if (next) c.http = next;
      else delete c.http;
      c.updatedAt = new Date().toISOString();
    });
  }

  delete(typeIn: unknown, nameIn: unknown): { type: string; name: string } {
    const type = normalizeType(typeIn);
    const name = normalizeName(nameIn);
    return this.mutate((data) => {
      const creds = own(data.credentials, type);
      if (!creds || !own(creds, name)) throw new VaultError(t(`凭证 "${type}/${name}" 不存在`, `Credential "${type}/${name}" not found`));
      delete creds[name];
      return { type, name };
    });
  }
}

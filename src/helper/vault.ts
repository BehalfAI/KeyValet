// 加密凭证库。只依赖 node 内置模块 —— 这段代码以 root 运行。
//
// 目录布局（全部 0600/0700，属主为运行者，生产环境即 root）：
//   master.key   32 字节随机主密钥
//   vault.enc    AES-256-GCM 加密后的 JSON
//   audit.log    审计日志（不含凭证值）
//   .lock/       写锁（mkdir 原子性），多个 session 并发写入时串行化

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

/** 协议型凭证的种类；static 即普通的“存什么取什么” */
export const KINDS = ["static", "oauth2", "google_service_account", "github_app", "jwt", "totp", "aws"] as const;
export type Kind = (typeof KINDS)[number];

export interface HttpConfig {
  /** 注入规则（static 凭证必填；token 类凭证省略，自动注入 Authorization: Bearer <token>） */
  inject?: InjectRule;
  /** 允许代理请求发往的域名（精确匹配；*.example.com 匹配其子域名） */
  allowed_hosts: string[];
  /** 只能代理调用：禁止 get 读出秘密 */
  proxy_only: boolean;
  test?: TestRequest;
}

export interface CredentialRecord {
  /** 缺省视为 static（兼容旧数据） */
  kind?: Kind;
  /** static 凭证的值；协议型凭证为空串 */
  value: string;
  /** 协议型凭证的非敏感配置（端点、client_id、scope 等） */
  config?: Record<string, unknown>;
  /** 协议型凭证的长期秘密（refresh token、私钥、种子……），永不离开 root 进程 */
  secrets?: Record<string, string>;
  /** 协议运行状态（缓存的短期 token、过期时间等） */
  state?: Record<string, unknown>;
  /** 每次 setProtocol 生成的随机版本号；异步操作写回结果前校验，防止写进期间被替换的配置 */
  generation?: string;
  /** 代理调用配置（注入规则、允许的域名、是否只能代理、验证请求） */
  http?: HttpConfig;
  /** 创建时所用的模板 ID */
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
/** 改名前（credential-mcp）写入的数据：读取时兼容，下次写入即升级为新标识 */
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

/** 只取对象自身属性，避免 "constructor" 之类的名字命中原型链 */
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

  /** 创建/校验目录与主密钥。目录或文件权限不对时拒绝工作，而不是“修好”它。 */
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
        // 另一个 session 同时初始化：用它写入的那把
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
    }
    this.assertPrivate(this.keyPath, false);
    const key = fs.readFileSync(this.keyPath);
    if (key.length !== KEY_BYTES) throw new VaultError(t("主密钥文件已损坏（长度不对）", "Master key file is corrupted (wrong length)"));
    this.key = key;

    if (fs.existsSync(this.dataPath)) {
      this.assertPrivate(this.dataPath, false);
      this.read(); // 尽早发现密钥/数据不匹配
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
    const key = this.requireKey(); // 放在循环外：未初始化等错误要如实报告，不能被当成“解密失败”
    let plain: Buffer | null = null;
    for (const aad of [AAD, LEGACY_AAD]) {
      try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
        decipher.setAAD(aad);
        decipher.setAuthTag(Buffer.from(file.tag, "base64"));
        plain = Buffer.concat([decipher.update(Buffer.from(file.ct, "base64")), decipher.final()]);
        break;
      } catch {
        /* 试下一个标识 */
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
    // 原子写：临时文件 + fsync + rename，崩溃时不会留下半截文件
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

  /** 读-改-写，持有跨进程写锁 */
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
          fs.rmdirSync(this.lockPath); // 持锁进程已崩溃
          continue;
        }
      } catch {
        continue; // 锁刚好被释放
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

  /** 读取审计日志末尾（最多 maxBytes 字节）的完整行 */
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
      if (len < size) lines.shift(); // 第一行可能不完整
      return lines.filter((l) => l.trim());
    } finally {
      fs.closeSync(fd);
    }
  }

  audit(entry: Record<string, unknown>): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), pid: process.pid, ...entry }) + "\n";
    fs.appendFileSync(this.auditPath, line, { mode: 0o600 });
    // 超过 10MB 轮转一次（保留上一份），防止无限增长
    try {
      if (fs.statSync(this.auditPath).size > 10 * 1024 * 1024) fs.renameSync(this.auditPath, `${this.auditPath}.1`);
    } catch {
      /* ignore */
    }
  }

  // ---------- 业务操作 ----------

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

  /** 完整记录（含秘密）的深拷贝。只供 root helper 内部的协议实现和 root CLI 使用。 */
  getRecord(typeIn: unknown, nameIn: unknown): { type: string; name: string; record: CredentialRecord } {
    const type = normalizeType(typeIn);
    const name = normalizeName(nameIn);
    const data = this.read();
    if (!own(data.types, type)) throw new VaultError(t(`凭证类型 "${type}" 不存在`, `Credential type "${type}" not found`));
    const c = own(own(data.credentials, type) ?? {}, name);
    if (!c) throw new VaultError(t(`凭证 "${type}/${name}" 不存在`, `Credential "${type}/${name}" not found`));
    return { type, name, record: structuredClone(c) };
  }

  /** 读取 static 凭证的值。协议型凭证的秘密不能通过这里取出。 */
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
   * 写入凭证：先检查凭证类型，不存在则先创建类型，再写入值。
   * 两步在同一把写锁、同一次落盘内完成，不会出现“类型建了但值没写”的中间态。
   */
  set(params: {
    type: unknown;
    name: unknown;
    value?: unknown;
    /** 多个秘密字段（模板凭证）；提供时 value 可省略 */
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
   * 写入协议型凭证。与 set 相同：类型不存在则先创建类型，再写入。
   * config/secrets 的内容由调用方（protocols/*）校验。
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
   * 在写锁内修改协议凭证的 state/secrets（如刷新后的 token）。
   * generation 必须与读取时一致：期间凭证被替换（哪怕种类相同）就拒绝写入，
   * 否则刷新回来的 refresh token 可能被写进 agent 刚换上的恶意配置里。
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

  /** 修改代理调用配置（任何种类的凭证）。fn 返回新的配置；校验由调用方完成。 */
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

import { GRANT_REQUIRED_OPS, GRANT_REQUIRED_PREFIX, OPS, PURPOSE_REQUIRED_OPS, cleanPurpose, type Request, type Response } from "../shared/protocol.js";
import type { GateResult } from "./auth-gate.js";
import { readSettings, writeSettings, type GrantMode } from "./settings.js";
import { deviceStart, devicePoll, exchangeCode } from "./protocols/oauth2.js";
import { accessToken, aws, publicView, setupProtocol, totp } from "./protocols/index.js";
import { validateHttpConfig } from "./http-config.js";
import { configureHttp } from "./http-manage.js";
import { confirmAsUser } from "./user-dialog.js";
import { describeTarget, proxyRequest, testCredential } from "./http-proxy.js";
import { Vault, VaultError, normalizeName, normalizeType, type HttpConfig } from "./vault.js";

/** 会话的授权状态（不写入审计日志） */
export interface SessionAuth {
  grantAll: boolean;
  grants: Set<string>;
  /** 弹出 Touch ID（由 main 注入；测试中可替换） */
  authorize: (reason: string) => Promise<GateResult>;
}

export function credKey(type: unknown, name: unknown): string {
  return `${normalizeType(type)}/${normalizeName(name)}`;
}

/** 握手时的凭证提示 → 凭证键（只认已存在的凭证；只给 name 时按名字唯一匹配） */
export function resolveHint(vault: Vault, hint: unknown): string | null {
  if (!hint || typeof hint !== "object") return null;
  const h = hint as { type?: unknown; name?: unknown };
  try {
    if (h.type) return vault.exists(h.type, h.name) ? credKey(h.type, h.name) : null;
    const name = normalizeName(h.name);
    const hits = vault.list().filter((c) => c.name === name);
    return hits.length === 1 ? `${hits[0]!.type}/${hits[0]!.name}` : null;
  } catch {
    return null;
  }
}

async function grantCredential(vault: Vault, p: Record<string, unknown>, ctx: ClientContext, auth: SessionAuth) {
  const { type, name } = vault.getRecord(p.type, p.name);
  const key = `${type}/${name}`;
  if (auth.grantAll || auth.grants.has(key)) return { granted: key, already: true };
  const purpose = cleanPurpose(p.purpose) ?? "";
  const r = await auth.authorize(`授权本次 AI 会话使用凭证：${key}\n目的：${purpose}\n来源目录（agent 提供）：${ctx.cwd || "未知"}`);
  if (!r.ok) throw new VaultError(r.error);
  auth.grants.add(key);
  return { granted: key, already: false };
}

async function settingsOp(vault: Vault, p: Record<string, unknown>) {
  const current = readSettings(vault.dir);
  if (p.grant_mode === undefined || p.grant_mode === null) return current;
  const mode = p.grant_mode as GrantMode;
  if (mode !== "all" && mode !== "per_credential") throw new VaultError("grant_mode 只能是 per_credential 或 all");
  if (mode === current.grant_mode) return current;
  // 放宽（改为一次授权全部）需要用户确认；收紧不需要
  if (mode === "all") {
    const purpose = cleanPurpose(p.purpose) ?? "";
    const ok = await confirmAsUser(
      `AI 会话请求修改凭证库设置：\n\n授权范围改为「一次授权全部凭证」\n（之后每个会话按一次 Touch ID 即可使用所有凭证）\n\n目的：${purpose.slice(0, 200)}`,
      "允许修改",
    );
    if (!ok) throw new VaultError("用户拒绝了该修改");
  }
  writeSettings(vault.dir, { ...current, grant_mode: mode });
  return { ...readSettings(vault.dir), note: "对新的会话生效" };
}

const FIELD_KEY_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/** 模板凭证的多个秘密字段 */
function checkSecrets(v: unknown): Record<string, string> | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError("secrets 必须是对象");
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 30) throw new VaultError("secrets 最多 30 项");
  const out: Record<string, string> = {};
  for (const [k, x] of entries) {
    if (!FIELD_KEY_RE.test(k)) throw new VaultError(`非法的字段名 "${k}"`);
    if (typeof x !== "string" || x.length === 0 || x.length > 64 * 1024) throw new VaultError(`秘密字段 ${k} 必须是 1~65536 字符的字符串`);
    out[k] = x;
  }
  return Object.keys(out).length ? out : undefined;
}

/** 写入 static 凭证：带模板时同时写入多个秘密字段和代理配置（新凭证的秘密刚由用户输入，无需再确认域名） */
function setStatic(vault: Vault, p: Record<string, unknown>) {
  const secrets = checkSecrets(p.secrets);
  let http: HttpConfig | undefined;
  if (p.http !== undefined && p.http !== null) {
    // 与 vault.set 一致：未提供 attributes 时沿用已有凭证的
    const given = (p.attributes ?? {}) as Record<string, string>;
    const attributes = Object.keys(given).length || !vault.exists(p.type, p.name) ? given : vault.getRecord(p.type, p.name).record.attributes;
    // 新写入的秘密：模板验证请求允许引用秘密字段（如 Trello 把 token 放在路径里）
    http = validateHttpConfig(p.http, { kind: "static", secrets, attributes, value: typeof p.value === "string" ? p.value : "" }, { allowSecretsInTest: true });
  }
  const template = typeof p.template === "string" && /^[A-Za-z0-9_.-]{1,100}$/.test(p.template) ? p.template : undefined;
  return vault.set({ ...(p as Parameters<Vault["set"]>[0]), secrets, http, template });
}

export interface ClientContext {
  cwd?: string;
  ppid?: number;
  client?: string;
  /** MCP server 进程（即一次 agent 会话）的随机 ID */
  session?: string;
}

function clip(v: unknown): string | undefined {
  return typeof v === "string" ? v.slice(0, 200) : undefined;
}

export function httpSummary(h: HttpConfig) {
  return {
    allowed_hosts: h.allowed_hosts,
    proxy_only: h.proxy_only,
    inject: h.inject
      ? [...Object.keys(h.inject.headers ?? {}).map((k) => `header:${k}`), ...Object.keys(h.inject.query ?? {}).map((k) => `query:${k}`), ...(h.inject.basic ? ["basic"] : [])]
      : ["Authorization: Bearer <access token>"],
    can_test: !!h.test,
  };
}

function info(vault: Vault, p: Record<string, unknown>) {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  if ((record.kind ?? "static") !== "static") {
    const v = publicView(type, name, record);
    return record.http ? { ...v, http: httpSummary(record.http) } : v;
  }
  return {
    type,
    name,
    kind: "static",
    description: record.description,
    attributes: record.attributes,
    secret_fields: record.secrets ? Object.keys(record.secrets) : ["value"],
    ...(record.template ? { template: record.template } : {}),
    ...(record.http ? { http: httpSummary(record.http) } : {}),
    updatedAt: record.updatedAt,
  };
}

/**
 * 覆盖/删除已有凭证前由 helper 自己弹窗确认（不依赖 MCP server），
 * 防止绕过 server 直接驱动 helper 时悄悄替换或删除用户的凭证。
 */
async function confirmDestructive(vault: Vault, p: Record<string, unknown>, action: "覆盖" | "删除"): Promise<void> {
  if (!vault.exists(p.type, p.name)) return;
  const label = `${String(p.type).trim().toLowerCase()}/${String(p.name).trim().toLowerCase()}`;
  const purpose = cleanPurpose(p.purpose) ?? "";
  const tail = action === "覆盖" ? "旧的值和配置将被永久替换。" : "此操作不可恢复。";
  if (!(await confirmAsUser(`AI 会话请求${action}凭证：\n\n${label}\n\n${tail}\n目的：${purpose.slice(0, 200)}`, `确认${action}`))) {
    throw new VaultError(`用户拒绝了${action}操作`);
  }
}

async function run(vault: Vault, req: Request, ctx: ClientContext, auth: SessionAuth | undefined): Promise<unknown> {
  const p = req.params;
  switch (req.op) {
    case "listTypes":
      return vault.listTypes();
    case "createType":
      return vault.createType(p.name, p.description);
    case "deleteType":
      return vault.deleteType(p.name);
    case "list":
      return vault.list(p.type);
    case "exists":
      return vault.exists(p.type, p.name);
    case "info":
      return info(vault, p);
    case "get": {
      const { record } = vault.getRecord(p.type, p.name);
      return (record.kind ?? "static") === "static" ? vault.get(p.type, p.name) : info(vault, p);
    }
    case "set":
      if (p.overwrite === true) await confirmDestructive(vault, p, "覆盖");
      return setStatic(vault, p);
    case "delete":
      await confirmDestructive(vault, p, "删除");
      return vault.delete(p.type, p.name);
    case "setupProtocol":
      if (p.overwrite === true) await confirmDestructive(vault, p, "覆盖");
      return setupProtocol(vault, p);
    case "oauthExchange":
      return exchangeCode(vault, p as Parameters<typeof exchangeCode>[1]);
    case "oauthDeviceStart":
      return deviceStart(vault, p as Parameters<typeof deviceStart>[1]);
    case "oauthDevicePoll":
      return devicePoll(vault, p as Parameters<typeof devicePoll>[1]);
    case "accessToken":
      return accessToken(vault, p);
    case "totp":
      return totp(vault, p);
    case "aws":
      return aws(vault, p);
    case "auditQuery":
      return auditQuery(vault, p, ctx);
    case "httpConfigure":
      return configureHttp(vault, p);
    case "httpRequest":
      return proxyRequest(vault, p as unknown as Parameters<typeof proxyRequest>[1]);
    case "httpTest":
      return testCredential(vault, p as Parameters<typeof testCredential>[1]);
    case "grant":
      if (!auth) return { granted: credKey(p.type, p.name), already: true };
      return grantCredential(vault, p, ctx, auth);
    case "settings":
      return settingsOp(vault, p);
    case "sessionInfo":
      return {
        grant_mode: readSettings(vault.dir).grant_mode,
        session_grants_all: auth ? auth.grantAll : true,
        granted: auth ? [...auth.grants].sort() : [],
      };
  }
}

/** 审计日志查询：最新的在前；不含任何凭证值（日志里本来就没有） */
function auditQuery(vault: Vault, p: Record<string, unknown>, ctx: ClientContext) {
  const limit = Math.min(Math.max(Number(p.limit ?? 50) || 50, 1), 500);
  const want = (k: string) => (typeof p[k] === "string" && p[k] ? String(p[k]).trim().toLowerCase() : undefined);
  const type = want("type");
  const name = want("name");
  const op = typeof p.op === "string" && p.op ? p.op : undefined;
  const session = p.this_session === true ? ctx.session : typeof p.session === "string" && p.session ? p.session : undefined;
  const since = typeof p.since === "string" && p.since ? Date.parse(p.since) : NaN;

  const out: Array<Record<string, unknown>> = [];
  const lines = vault.readAuditTail();
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    let e: Record<string, unknown>;
    try {
      e = JSON.parse(lines[i]!) as Record<string, unknown>;
    } catch {
      continue;
    }
    const client = (e.client ?? {}) as Record<string, unknown>;
    const entrySession = (e.session ?? client.session) as string | undefined;
    if (type && e.type !== type) continue;
    if (name && e.name !== name) continue;
    if (op && e.op !== op) continue;
    if (session && entrySession !== session) continue;
    if (!Number.isNaN(since) && Date.parse(String(e.ts)) < since) continue;
    out.push({
      ts: e.ts,
      session: entrySession ?? null,
      op: e.op,
      type: e.type ?? null,
      name: e.name ?? null,
      kind: e.kind ?? null,
      purpose: e.purpose ?? null,
      ok: e.ok ?? null,
      error: e.error ?? null,
      cwd: client.cwd ?? null,
      via: client.client ?? null,
    });
  }
  return { current_session: ctx.session ?? null, count: out.length, entries: out };
}

/** 处理一条请求。审计日志只记录操作和对象，绝不记录凭证值或秘密。 */
/**
 * auth 省略时视为拥有全部授权（仅用于测试和 root CLI）；helper 主程序总是传入会话的授权状态。
 */
export async function dispatch(vault: Vault, req: Request, ctx: ClientContext, auth?: SessionAuth): Promise<Response> {
  const p = { ...((req.params && typeof req.params === "object" ? req.params : {}) as Record<string, unknown>) };
  delete p.viaProxy; // 仅限 helper 内部使用的标记，外部请求不得携带
  const isTypeOp = req.op === "createType" || req.op === "deleteType";
  const purpose = cleanPurpose(p.purpose);
  const auditBase = {
    op: req.op,
    type: clip(isTypeOp ? p.name : p.type)?.trim().toLowerCase(),
    name: isTypeOp ? undefined : clip(p.name)?.trim().toLowerCase(),
    kind: clip(p.kind),
    ...(req.op === "httpRequest" ? { target: describeTarget(p as { url: unknown; method?: unknown }) } : {}),
    purpose: purpose ?? undefined,
    session: ctx.session,
    client: ctx,
  };
  // 只读的元数据查询不记日志，避免刷屏
  const quiet = ["exists", "info", "oauthDevicePoll", "auditQuery", "sessionInfo"].includes(req.op) || (req.op === "settings" && p.grant_mode == null);
  try {
    if (!OPS.includes(req.op)) throw new VaultError(`未知操作 ${String(req.op)}`);
    if (PURPOSE_REQUIRED_OPS.has(req.op) && !purpose) throw new VaultError("必须说明本次操作的目的（purpose）");
    if (auth && !auth.grantAll && GRANT_REQUIRED_OPS.has(req.op)) {
      const key = credKey(p.type, p.name);
      if (!auth.grants.has(key)) throw new VaultError(`${GRANT_REQUIRED_PREFIX}${key}`);
    }
    const result = await run(vault, { ...req, params: p }, ctx, auth);
    // 本会话新建/覆盖（已确认）的凭证：秘密刚由用户提供，自动授权
    if (auth && (req.op === "set" || req.op === "setupProtocol")) {
      const r = result as { type: string; name: string };
      auth.grants.add(`${r.type}/${r.name}`);
    }
    try {
      if (!quiet) vault.audit({ ...auditBase, ok: true });
    } catch {
      /* 同上 */
    }
    return { id: req.id, ok: true, result };
  } catch (e) {
    const message = e instanceof VaultError ? e.message : `内部错误：${e instanceof Error ? e.message : String(e)}`;
    try {
      vault.audit({ ...auditBase, ok: false, error: message.slice(0, 500) });
    } catch {
      /* 审计写入失败（如磁盘满）不能让 helper 崩溃 */
    }
    return { id: req.id, ok: false, error: message };
  }
}

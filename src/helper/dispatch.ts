import { GRANT_REQUIRED_OPS, GRANT_REQUIRED_PREFIX, OPS, PURPOSE_REQUIRED_OPS, cleanPurpose, type Request, type Response } from "../shared/protocol.js";
import type { GateResult } from "./auth-gate.js";
import { GRANT_MODES, isLoosening, parseMode, readSettings, rememberActive, rememberUntil, stricter, writeSettings, type GrantMode, type Settings } from "./settings.js";
import { deviceStart, devicePoll, exchangeCode } from "./protocols/oauth2.js";
import { accessToken, aws, publicView, setupProtocol, totp } from "./protocols/index.js";
import { validateHttpConfig } from "./http-config.js";
import { Gateway, requireGateway } from "./gateway.js";
import { configureHttp } from "./http-manage.js";
import { confirmAsUser } from "./user-dialog.js";
import { describeTarget, proxyRequest, testCredential } from "./http-proxy.js";
import { Vault, VaultError, normalizeName, normalizeType, type HttpConfig } from "./vault.js";
import { t } from "../shared/i18n.js";

/** 会话的授权状态（不写入审计日志） */
export interface SessionAuth {
  /** 本会话的本地网关（仅 helper 主程序提供） */
  gateway?: Gateway;
  grantAll: boolean;
  grants: Set<string>;
  /** 本会话生效的授权模式（全局设置与客户端请求中更严格的那个）；省略视为 per_credential */
  mode?: GrantMode;
  /** 客户端请求的模式（只能收严），设置变化后用于重新计算 */
  requested?: GrantMode | null;
  /** per_use 模式：已认证、尚未使用的单次授权 */
  oneShot?: Set<string>;
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
  const perUse = auth.mode === "per_use";
  if (!perUse && (auth.grantAll || auth.grants.has(key))) return { granted: key, already: true };
  const purpose = cleanPurpose(p.purpose) ?? "";
  const where = t(`目的：${purpose}\n来源目录（agent 提供）：${ctx.cwd || "未知"}`, `Purpose: ${purpose}\nWorking directory (reported by agent): ${ctx.cwd || "unknown"}`);
  const r = await auth.authorize(
    perUse
      ? t(`授权本次使用凭证（仅此一次）：${key}\n${where}`, `Authorize a single use of credential: ${key}\n${where}`)
      : t(`授权本次 AI 会话使用凭证：${key}\n${where}`, `Authorize this AI session to use credential: ${key}\n${where}`),
  );
  if (!r.ok) throw new VaultError(r.error);
  if (perUse) (auth.oneShot ??= new Set()).add(key);
  else auth.grants.add(key);
  return { granted: key, already: false, single_use: perUse };
}

/** 按设置更新当前会话的授权状态（设置修改后立即生效） */
export function applyMode(auth: SessionAuth, s: Settings): void {
  auth.mode = stricter(s.grant_mode, auth.requested ?? null);
  if (auth.mode === "per_use") {
    auth.grantAll = false;
    auth.grants.clear();
    auth.oneShot = new Set();
  } else if (auth.mode === "per_credential") {
    auth.grantAll = false;
  } else {
    auth.grantAll = true; // per_session / remember：本会话可使用全部凭证
  }
}

function settingsView(s: Settings, auth?: SessionAuth) {
  return {
    grant_mode: s.grant_mode,
    remember_hours: s.remember_hours,
    remembered_until: rememberActive(s) ? (s.remember_until === Number.MAX_SAFE_INTEGER ? "forever" : new Date(s.remember_until!).toISOString()) : null,
    session: auth
      ? { effective_mode: auth.mode ?? "per_credential", requested_mode: auth.requested ?? null, grants_all: auth.grantAll, granted: [...auth.grants].sort() }
      : null,
  };
}

function describeSettings(s: Settings): string {
  const hours = s.remember_hours === 0 ? t("永久", "forever") : t(`${s.remember_hours} 小时`, `${s.remember_hours} hours`);
  switch (s.grant_mode) {
    case "per_use":
      return t("每次使用凭证都要 Touch ID", "Touch ID for every use of a credential");
    case "per_credential":
      return t("每个会话中，每个凭证按一次 Touch ID", "Touch ID once per credential per session");
    case "per_session":
      return t("每个会话按一次 Touch ID，之后可使用全部凭证", "Touch ID once per session, then all credentials");
    case "remember":
      return t(`按一次 Touch ID，${hours}内所有会话都不再需要认证`, `Touch ID once, then no authentication for any session for ${hours}`);
  }
}

/**
 * 查看/修改授权设置。放宽（更宽松的模式、更长的记住时长）必须由用户按 Touch ID——
 * 指纹无法用脚本伪造，而确认框在终端有“辅助功能”权限时可能被脚本点击。收紧立即生效、无需认证。
 */
async function settingsOp(vault: Vault, p: Record<string, unknown>, auth?: SessionAuth) {
  const current = readSettings(vault.dir);
  if (p.forget === true) {
    const next: Settings = { grant_mode: current.grant_mode, remember_hours: current.remember_hours };
    writeSettings(vault.dir, next);
    if (auth) applyMode(auth, next);
    return { ...settingsView(next, auth), note: t("已清除“记住”状态", "Cleared the remembered authorization") };
  }
  if (p.grant_mode == null && p.remember_hours == null) return settingsView(current, auth);

  const mode = p.grant_mode == null ? current.grant_mode : parseMode(p.grant_mode);
  if (!mode) throw new VaultError(t(`grant_mode 只能是 ${GRANT_MODES.join(" / ")}`, `grant_mode must be one of ${GRANT_MODES.join(" / ")}`));
  let hours = current.remember_hours;
  if (p.remember_hours != null) {
    hours = Number(p.remember_hours);
    if (!Number.isFinite(hours) || hours < 0 || hours > 8760) throw new VaultError(t("remember_hours 必须在 0~8760 之间（0 表示永久）", "remember_hours must be between 0 and 8760 (0 = forever)"));
  }
  const next: Settings = { grant_mode: mode, remember_hours: hours };
  if (mode === "remember" && rememberActive(current)) next.remember_until = current.remember_until;

  if (isLoosening(current, next)) {
    const purpose = cleanPurpose(p.purpose) ?? "";
    const msg = t(
      `修改 KeyValet 授权设置为：${describeSettings(next)}\n目的：${purpose.slice(0, 200)}`,
      `Change KeyValet authorization to: ${describeSettings(next)}\nPurpose: ${purpose.slice(0, 200)}`,
    );
    const approved = auth ? (await auth.authorize(msg)).ok : await confirmAsUser(msg, t("允许修改", "Allow Change"));
    if (!approved) throw new VaultError(t("用户拒绝了该修改", "The user denied this change"));
    if (mode === "remember") next.remember_until = rememberUntil(hours); // 本次 Touch ID 即开始记住
  } else if (next.remember_until !== undefined) {
    next.remember_until = Math.min(next.remember_until, rememberUntil(hours)); // 缩短时长：同时缩短当前窗口
  }
  writeSettings(vault.dir, next);
  if (auth) applyMode(auth, next);
  return { ...settingsView(next, auth), note: t("已生效（包括当前会话）", "In effect now, including this session") };
}

const FIELD_KEY_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/** 模板凭证的多个秘密字段 */
function checkSecrets(v: unknown): Record<string, string> | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(t("secrets 必须是对象", "secrets must be an object"));
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 30) throw new VaultError(t("secrets 最多 30 项", "secrets may have at most 30 entries"));
  const out: Record<string, string> = {};
  for (const [k, x] of entries) {
    if (!FIELD_KEY_RE.test(k)) throw new VaultError(t(`非法的字段名 "${k}"`, `Invalid field name "${k}"`));
    if (typeof x !== "string" || x.length === 0 || x.length > 64 * 1024) throw new VaultError(t(`秘密字段 ${k} 必须是 1~65536 字符的字符串`, `Secret field ${k} must be a string of 1-65536 characters`));
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
  const overwrite = action === "覆盖";
  const tail = overwrite ? t("旧的值和配置将被永久替换。", "The existing value and configuration will be permanently replaced.") : t("此操作不可恢复。", "This cannot be undone.");
  const message = t(
    `AI 会话请求${action}凭证：\n\n${label}\n\n${tail}\n目的：${purpose.slice(0, 200)}`,
    `An AI session is requesting to ${overwrite ? "overwrite" : "delete"} a credential:\n\n${label}\n\n${tail}\nPurpose: ${purpose.slice(0, 200)}`,
  );
  if (!(await confirmAsUser(message, t(`确认${action}`, overwrite ? "Overwrite" : "Delete")))) {
    throw new VaultError(t(`用户拒绝了${action}操作`, `The user denied the ${overwrite ? "overwrite" : "delete"} operation`));
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
      return settingsOp(vault, p, auth);
    case "gatewayOpen": {
      const { type, name, record } = vault.getRecord(p.type, p.name);
      if (!record.http) {
        throw new VaultError(
          t(
            `"${type}/${name}" 没有配置代理调用，请先用 credential_configure_http 设置允许的域名`,
            `"${type}/${name}" has no proxy configuration; set the allowed hosts with credential_configure_http first`,
          ),
        );
      }
      const g = await requireGateway(auth?.gateway).open(type, name, cleanPurpose(p.purpose) ?? undefined);
      const hosts = record.http.allowed_hosts.filter((h) => !h.startsWith("*."));
      return {
        type,
        name,
        base: g.base,
        // 令牌交给 MCP server 写入仅用户可读的环境变量文件，不放进 URL、不返回给 agent
        token: g.token,
        template: record.template ?? null,
        allowed_hosts: record.http.allowed_hosts,
        base_urls: Object.fromEntries(hosts.map((h) => [h, `${g.base}/${h}`])),
      };
    }
    case "sessionInfo":
      return settingsView(readSettings(vault.dir), auth);
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
  const quiet =
    ["exists", "info", "oauthDevicePoll", "auditQuery", "sessionInfo"].includes(req.op) ||
    (req.op === "settings" && p.grant_mode == null && p.remember_hours == null && p.forget !== true);
  try {
    if (!OPS.includes(req.op)) throw new VaultError(t(`未知操作 ${String(req.op)}`, `Unknown operation ${String(req.op)}`));
    if (PURPOSE_REQUIRED_OPS.has(req.op) && !purpose) throw new VaultError(t("必须说明本次操作的目的（purpose）", "A purpose is required for this operation"));
    if (auth && GRANT_REQUIRED_OPS.has(req.op)) {
      const key = credKey(p.type, p.name);
      // per_use：每次 Touch ID 只换来一次使用
      const allowed = auth.mode === "per_use" ? auth.oneShot?.delete(key) === true : auth.grantAll || auth.grants.has(key);
      if (!allowed) throw new VaultError(`${GRANT_REQUIRED_PREFIX}${key}`);
    }
    const result = await run(vault, { ...req, params: p }, ctx, auth);
    // 本会话新建/覆盖（已确认）的凭证：秘密刚由用户提供，自动授权
    if (auth && auth.mode !== "per_use" && (req.op === "set" || req.op === "setupProtocol")) {
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
    const message = e instanceof VaultError ? e.message : t(`内部错误：${e instanceof Error ? e.message : String(e)}`, `Internal error: ${e instanceof Error ? e.message : String(e)}`);
    try {
      vault.audit({ ...auditBase, ok: false, error: message.slice(0, 500) });
    } catch {
      /* 审计写入失败（如磁盘满）不能让 helper 崩溃 */
    }
    return { id: req.id, ok: false, error: message };
  }
}

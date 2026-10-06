// MCP server（普通用户）与 root helper 之间的 JSON-lines 协议。
// 通道是 sudo 子进程的 stdin/stdout 管道，其他进程无法接入。
//
// 握手：server 先发一行 AuthMessage（目的、来源、会话 ID）→ helper 弹 Touch ID →
// 通过则回 { ready: true }，否则回 { ready: false, error } 并退出。之后才是普通请求。

export const PROTOCOL_VERSION = 3;

export const OPS = [
  "listTypes",
  "createType",
  "deleteType",
  "list",
  "exists",
  /** 凭证的非敏感信息（含协议凭证的配置和状态），不含值和秘密 */
  "info",
  /** static 凭证返回值；协议凭证只返回 info */
  "get",
  "set",
  "delete",
  /** 创建/替换协议凭证（oauth2、google_service_account、github_app、jwt、totp、aws） */
  "setupProtocol",
  "oauthExchange",
  "oauthDeviceStart",
  "oauthDevicePoll",
  "accessToken",
  "totp",
  "aws",
  /** 查询审计日志 */
  "auditQuery",
  /** 修改代理调用配置（扩大暴露面时 helper 会弹窗请用户确认） */
  "httpConfigure",
  /** 代理调用：注入凭证后发出 HTTP 请求，只返回响应 */
  "httpRequest",
  /** 用验证请求检查凭证是否可用 */
  "httpTest",
  /** 按凭证授权：弹 Touch ID 授权本会话使用某个凭证 */
  "grant",
  /** 读取/修改凭证库设置（授权范围模式） */
  "settings",
  /** 本会话的授权状态 */
  "sessionInfo",
] as const;

export type Op = (typeof OPS)[number];

/** 必须说明目的的操作：读取凭证/派生 token、修改凭证 */
export const PURPOSE_REQUIRED_OPS: ReadonlySet<Op> = new Set<Op>([
  "createType",
  "deleteType",
  "get",
  "set",
  "delete",
  "setupProtocol",
  "oauthExchange",
  "oauthDeviceStart",
  "accessToken",
  "totp",
  "aws",
  "httpConfigure",
  "httpRequest",
  "httpTest",
  "grant",
]);

/** 需要该凭证已获授权的操作（per_credential 模式下） */
export const GRANT_REQUIRED_OPS: ReadonlySet<Op> = new Set<Op>([
  "get",
  "accessToken",
  "totp",
  "aws",
  "httpRequest",
  "httpTest",
  "httpConfigure",
  "oauthExchange",
  "oauthDeviceStart",
  "oauthDevicePoll",
]);

/** helper 返回的“需要授权”错误前缀，后跟 type/name */
export const GRANT_REQUIRED_PREFIX = "[GRANT_REQUIRED] ";

export interface Request {
  id: number;
  op: Op;
  params: Record<string, unknown>;
}

export type Response =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };

export interface AuthMessage {
  op: "auth";
  purpose: string;
  /** 触发解锁的工具要使用的凭证（per_credential 模式下，本次 Touch ID 即授权该凭证） */
  credential?: { type?: string; name: string };
  cwd: string;
  ppid: number;
  session: string;
  client: string;
}

export type ReadyMessage = { ready: true; protocol: number } | { ready: false; protocol: number; error: string };

export const MAX_LINE_BYTES = 1024 * 1024;

/** 目的文字：去掉控制字符，限制长度 */
export function cleanPurpose(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return s.length >= 2 ? s.slice(0, 300) : null;
}

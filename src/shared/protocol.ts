// JSON-lines protocol between the MCP server (runs as a regular user) and the root helper.
// The channel is the stdin/stdout pipe of the sudo child process; no other process can connect to it.
//
// Handshake: the server first sends one line, an AuthMessage (purpose, source, session ID) -> the helper
// shows a Touch ID prompt -> on success it replies { ready: true }, otherwise { ready: false, error } and exits.
// Only after that do normal requests begin.

export const PROTOCOL_VERSION = 3;

export const OPS = [
  "listTypes",
  "createType",
  "deleteType",
  "list",
  "exists",
  /** Non-sensitive credential info (including protocol-credential config and status); excludes the value and secrets */
  "info",
  /** Returns the value for static credentials; protocol credentials only return info */
  "get",
  "set",
  "delete",
  /** Create/replace a protocol credential (oauth2, google_service_account, github_app, jwt, totp, aws) */
  "setupProtocol",
  "oauthExchange",
  "oauthDeviceStart",
  "oauthDevicePoll",
  "accessToken",
  "totp",
  "aws",
  /** Query the audit log */
  "auditQuery",
  /** Change the proxy-call configuration (the helper prompts for user confirmation when widening exposure) */
  "httpConfigure",
  /** Proxy call: injects the credential, sends the HTTP request, and returns only the response */
  "httpRequest",
  /** Checks whether a credential works, using a verification request */
  "httpTest",
  /** Per-credential authorization: shows a Touch ID prompt to authorize this session to use a given credential */
  "grant",
  /** Read/modify vault settings (grant-scope mode) */
  "settings",
  /** This session's authorization status */
  "sessionInfo",
  /** Opens the local gateway endpoint (for the SDK / CLI, supports streaming responses) */
  "gatewayOpen",
] as const;

export type Op = (typeof OPS)[number];

/** Operations that require stating a purpose: reading a credential/deriving a token, modifying a credential */
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
  "gatewayOpen",
]);

/** Operations that require the credential to already be authorized (in per_credential mode) */
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
  "gatewayOpen",
]);

/** Prefix the helper returns for a "needs authorization" error, followed by type/name */
export const GRANT_REQUIRED_PREFIX = "[GRANT_REQUIRED] ";

/** Error marker the helper returns for "endpoint/client has changed, can't keep reusing the old client secret" (independent of UI language) */
export const SECRET_REBIND_MARK = "[SECRET_REBIND]";

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
  /** Authorization mode requested by the client (from KEYVALET_GRANT_MODE): can only be stricter than the global setting */
  requested_mode?: string;
  /** UI language (keeps the helper's prompts, dialogs, and error messages consistent with the MCP server) */
  lang?: "en" | "zh";
  /** Credential the unlocking tool is about to use (in per_credential mode, this Touch ID also authorizes that credential) */
  credential?: { type?: string; name: string };
  cwd: string;
  ppid: number;
  session: string;
  client: string;
}

export type ReadyMessage = { ready: true; protocol: number } | { ready: false; protocol: number; error: string };

export const MAX_LINE_BYTES = 1024 * 1024;

/** Purpose text: strip control characters, cap the length */
export function cleanPurpose(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return s.length >= 2 ? s.slice(0, 300) : null;
}

// OAuth 2.0: authorization code + PKCE (RFC 6749/7636), device code (RFC 8628), client credentials.
// The client secret and refresh token exist only in the root helper; the agent can only get a short-lived access token.

import { t } from "../../shared/i18n.js";
import { Vault, VaultError, type CredentialRecord } from "../vault.js";
import { int, oneOf, optStr, str, strList, strRecord } from "./check.js";
import { assertHttpsUrl, obj, postForm, remoteError, type HttpResult } from "./http.js";
import { decodeJwtPayload } from "./jwt.js";

export const OAUTH_FLOWS = ["authorization_code", "device_code", "client_credentials"] as const;
export type OAuthFlow = (typeof OAUTH_FLOWS)[number];
const AUTH_METHODS = ["client_secret_post", "client_secret_basic", "none"] as const;

export interface OAuth2Config {
  provider: string;
  flow: OAuthFlow;
  client_id: string;
  token_url: string;
  authorization_url?: string;
  device_authorization_url?: string;
  scopes: string[];
  extra_auth_params: Record<string, string>;
  token_auth_method: (typeof AUTH_METHODS)[number];
  /** A fixed redirect URI (some providers require an exact port match); if unset, a random-port http://127.0.0.1:<port>/callback is used */
  redirect_uri?: string;
}

interface OAuth2State {
  access_token?: string;
  token_type?: string;
  expires_at?: number | null;
  scope?: string;
  account?: string;
  authorized_at?: string;
  needs_reauth?: boolean;
}

const EXPIRY_MARGIN_MS = 60_000;

export function validateRedirectUri(raw: unknown): string {
  const s = str(raw, "redirect_uri", 300);
  const u = new URL(s);
  if (u.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)) {
    throw new VaultError(t("redirect_uri 必须是本机回环地址，如 http://127.0.0.1:8765/callback", "redirect_uri must be a local loopback address, e.g. http://127.0.0.1:8765/callback"));
  }
  return u.toString();
}

export function validateOAuth2Setup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  const flow = oneOf(config.flow, "flow", OAUTH_FLOWS, "authorization_code");
  const clientSecret = optStr(secrets.client_secret, "client_secret", 2000);
  const cfg: OAuth2Config = {
    provider: str(config.provider ?? "custom", "provider", 50),
    flow,
    client_id: str(config.client_id, "client_id", 500),
    token_url: assertHttpsUrl(config.token_url, "token_url"),
    scopes: strList(config.scopes, "scopes"),
    extra_auth_params: strRecord(config.extra_auth_params, "extra_auth_params"),
    token_auth_method: oneOf(config.token_auth_method, "token_auth_method", AUTH_METHODS, clientSecret ? "client_secret_post" : "none"),
  };
  if (cfg.token_auth_method !== "none" && !clientSecret) throw new VaultError(t(`${cfg.token_auth_method} 需要 client_secret`, `${cfg.token_auth_method} requires client_secret`));
  if (flow === "authorization_code") {
    cfg.authorization_url = assertHttpsUrl(config.authorization_url, "authorization_url");
    if (config.redirect_uri) cfg.redirect_uri = validateRedirectUri(config.redirect_uri);
  }
  if (flow === "device_code") cfg.device_authorization_url = assertHttpsUrl(config.device_authorization_url, "device_authorization_url");
  if (flow === "client_credentials" && !clientSecret) throw new VaultError(t("client_credentials 流程需要 client_secret", "The client_credentials flow requires client_secret"));
  // These parameters are controlled by this program and must not be overridden via extra_auth_params
  for (const k of ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type", "scope"]) {
    if (Object.hasOwn(cfg.extra_auth_params, k)) throw new VaultError(t(`extra_auth_params 不能包含 ${k}`, `extra_auth_params must not contain ${k}`));
  }
  const outSecrets: Record<string, string> = clientSecret ? { client_secret: clientSecret } : {};
  return { config: cfg as unknown as Record<string, unknown>, secrets: outSecrets };
}

function load(vault: Vault, type: unknown, name: unknown) {
  const { type: ty, name: n, record } = vault.getRecord(type, name);
  if (record.kind !== "oauth2") throw new VaultError(t(`"${ty}/${n}" 不是 OAuth 2.0 凭证`, `"${ty}/${n}" is not an OAuth 2.0 credential`));
  return { ty, n, record, cfg: record.config as unknown as OAuth2Config, secrets: record.secrets ?? {}, state: (record.state ?? {}) as OAuth2State };
}

/** Client authentication: put it in the form body or the Basic header */
function clientAuth(cfg: OAuth2Config, secrets: Record<string, string>): { form: Record<string, string>; headers: Record<string, string> } {
  if (cfg.token_auth_method === "client_secret_basic") {
    const enc = (s: string) => encodeURIComponent(s);
    const basic = Buffer.from(`${enc(cfg.client_id)}:${enc(secrets.client_secret ?? "")}`).toString("base64");
    return { form: {}, headers: { Authorization: `Basic ${basic}` } };
  }
  if (cfg.token_auth_method === "client_secret_post") {
    return { form: { client_id: cfg.client_id, client_secret: secrets.client_secret ?? "" }, headers: {} };
  }
  return { form: { client_id: cfg.client_id }, headers: {} };
}

async function tokenRequest(cfg: OAuth2Config, secrets: Record<string, string>, form: Record<string, string>): Promise<HttpResult> {
  const auth = clientAuth(cfg, secrets);
  return postForm(cfg.token_url, { ...form, ...auth.form }, auth.headers);
}

/**
 * Write the token response into the credential: access token goes into state, refresh token goes into secrets.
 * fresh=true means a brand-new authorization: discard the old refresh token and state (which may belong to a different account).
 */
function saveTokens(vault: Vault, ty: string, n: string, gen: string | undefined, r: HttpResult, fresh = false): OAuth2State {
  const j = obj(r);
  if (typeof j.access_token !== "string" || !j.access_token) throw new VaultError(t("token 响应缺少 access_token", "Token response is missing access_token"));
  const expiresIn = Number(j.expires_in);
  const next: OAuth2State = {
    access_token: j.access_token,
    token_type: typeof j.token_type === "string" ? j.token_type : "Bearer",
    expires_at: j.expires_in != null && Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : null,
    scope: typeof j.scope === "string" ? j.scope : undefined,
    needs_reauth: false,
  };
  const claims = typeof j.id_token === "string" ? decodeJwtPayload(j.id_token) : null;
  const account = claims?.email ?? claims?.preferred_username ?? claims?.upn;
  vault.patchRecord(ty, n, "oauth2", gen, (rec: CredentialRecord) => {
    if (fresh) {
      rec.state = {};
      rec.secrets = { ...rec.secrets };
      delete rec.secrets.refresh_token;
    }
    const prev = (rec.state ?? {}) as OAuth2State;
    rec.state = {
      ...prev,
      ...next,
      scope: next.scope ?? prev.scope,
      account: typeof account === "string" ? account : prev.account,
      authorized_at: prev.authorized_at ?? new Date().toISOString(),
    };
    if (typeof j.refresh_token === "string" && j.refresh_token) {
      rec.secrets = { ...rec.secrets, refresh_token: j.refresh_token }; // supports refresh token rotation
    }
  });
  return { ...next, account: typeof account === "string" ? account : undefined };
}

function isTokenResponse(r: HttpResult): boolean {
  return r.status >= 200 && r.status < 300 && typeof obj(r).access_token === "string";
}

/** Exchange the authorization code for a token (the last step of the browser flow) */
export async function exchangeCode(vault: Vault, p: { type: unknown; name: unknown; code: unknown; code_verifier: unknown; redirect_uri: unknown }) {
  const { ty, n, record, cfg, secrets } = load(vault, p.type, p.name);
  if (cfg.flow !== "authorization_code") throw new VaultError(t(`"${ty}/${n}" 不是授权码流程`, `"${ty}/${n}" does not use the authorization code flow`));
  const r = await tokenRequest(cfg, secrets, {
    grant_type: "authorization_code",
    code: str(p.code, "code", 4000),
    code_verifier: str(p.code_verifier, "code_verifier", 200),
    redirect_uri: validateRedirectUri(p.redirect_uri),
  });
  if (!isTokenResponse(r)) throw remoteError(new URL(cfg.token_url).host, r);
  const s = saveTokens(vault, ty, n, record.generation, r, true);
  return summary(s, !!obj(r).refresh_token);
}

/** Device code flow step one: request a user_code from the provider */
export async function deviceStart(vault: Vault, p: { type: unknown; name: unknown }) {
  const { ty, n, cfg } = load(vault, p.type, p.name);
  if (cfg.flow !== "device_code" || !cfg.device_authorization_url) throw new VaultError(t(`"${ty}/${n}" 不是设备码流程`, `"${ty}/${n}" does not use the device code flow`));
  const form: Record<string, string> = { client_id: cfg.client_id };
  if (cfg.scopes.length) form.scope = cfg.scopes.join(" ");
  const r = await postForm(cfg.device_authorization_url, form);
  const j = obj(r);
  if (r.status >= 300 || typeof j.device_code !== "string" || typeof j.user_code !== "string") {
    throw remoteError(new URL(cfg.device_authorization_url).host, r);
  }
  const verification = j.verification_uri ?? j.verification_url; // Google uses verification_url
  return {
    device_code: j.device_code,
    user_code: j.user_code,
    verification_uri: typeof verification === "string" ? assertHttpsUrl(verification, "verification_uri") : null,
    verification_uri_complete:
      typeof j.verification_uri_complete === "string" ? assertHttpsUrl(j.verification_uri_complete, "verification_uri_complete") : null,
    interval: int(Number(j.interval ?? 5), "interval", 1, 60, 5),
    expires_in: int(Number(j.expires_in ?? 600), "expires_in", 30, 3600, 600),
  };
}

/** Device code flow step two: poll once */
export async function devicePoll(vault: Vault, p: { type: unknown; name: unknown; device_code: unknown }) {
  const { ty, n, record, cfg, secrets } = load(vault, p.type, p.name);
  if (cfg.flow !== "device_code") throw new VaultError(t(`"${ty}/${n}" 不是设备码流程`, `"${ty}/${n}" does not use the device code flow`));
  const r = await tokenRequest(cfg, secrets, {
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    device_code: str(p.device_code, "device_code", 2000),
  });
  if (isTokenResponse(r)) {
    const s = saveTokens(vault, ty, n, record.generation, r, true);
    return { status: "done" as const, ...summary(s, !!obj(r).refresh_token) };
  }
  const err = obj(r).error;
  if (err === "authorization_pending") return { status: "pending" as const };
  if (err === "slow_down") return { status: "slow_down" as const };
  if (err === "access_denied") return { status: "denied" as const };
  if (err === "expired_token") return { status: "expired" as const };
  throw remoteError(new URL(cfg.token_url).host, r);
}

/** Get a valid access token: return the cached one directly if still valid, otherwise refresh */
export async function accessToken(vault: Vault, p: { type: unknown; name: unknown; force?: unknown }) {
  const { ty, n, record, cfg, secrets, state } = load(vault, p.type, p.name);
  const gen = record.generation;
  const force = p.force === true;
  const valid = state.access_token && (state.expires_at == null || state.expires_at - EXPIRY_MARGIN_MS > Date.now());
  if (valid && !force) return tokenOut(state);

  if (cfg.flow === "client_credentials") {
    const form: Record<string, string> = { grant_type: "client_credentials" };
    if (cfg.scopes.length) form.scope = cfg.scopes.join(" ");
    const r = await tokenRequest(cfg, secrets, form);
    if (!isTokenResponse(r)) throw remoteError(new URL(cfg.token_url).host, r);
    return tokenOut({ ...saveTokens(vault, ty, n, gen, r), account: state.account });
  }

  if (secrets.refresh_token) {
    const form: Record<string, string> = { grant_type: "refresh_token", refresh_token: secrets.refresh_token };
    // Microsoft v2 endpoints require scope on refresh; other providers omit it (optional per RFC 6749)
    if (/^https:\/\/login\.microsoftonline\.com\//.test(cfg.token_url) && cfg.scopes.length) form.scope = cfg.scopes.join(" ");
    const r = await tokenRequest(cfg, secrets, form);
    if (isTokenResponse(r)) return tokenOut({ ...saveTokens(vault, ty, n, gen, r), account: state.account });
    if (obj(r).error === "invalid_grant") {
      vault.patchRecord(ty, n, "oauth2", gen, (rec) => {
        rec.state = { ...rec.state, needs_reauth: true, access_token: undefined };
      });
      throw new VaultError(
        t(
          `"${ty}/${n}" 的授权已失效（refresh token 被撤销或过期${cfg.provider === "google" ? "；Testing 状态的 Google 应用 7 天过期" : ""}）。请调用 credential_oauth_login 重新授权。`,
          `Authorization for "${ty}/${n}" is no longer valid (the refresh token was revoked or expired${cfg.provider === "google" ? "; Google apps in Testing status expire after 7 days" : ""}). Call credential_oauth_login to re-authorize.`,
        ),
      );
    }
    throw remoteError(new URL(cfg.token_url).host, r);
  }

  // Tokens that never expire (e.g. GitHub OAuth App classic tokens)
  if (state.access_token && state.expires_at == null) return tokenOut(state);
  throw new VaultError(t(`"${ty}/${n}" 尚未授权或授权已过期，请调用 credential_oauth_login 授权。`, `"${ty}/${n}" is not authorized or its authorization has expired; call credential_oauth_login to authorize.`));
}

function tokenOut(s: OAuth2State) {
  return {
    access_token: s.access_token!,
    token_type: s.token_type ?? "Bearer",
    expires_at: s.expires_at ? new Date(s.expires_at).toISOString() : null,
    scope: s.scope ?? null,
    account: s.account ?? null,
  };
}

function summary(s: OAuth2State, gotRefreshToken: boolean) {
  return {
    account: s.account ?? null,
    scope: s.scope ?? null,
    expires_at: s.expires_at ? new Date(s.expires_at).toISOString() : null,
    refresh_token: gotRefreshToken,
  };
}

export function publicState(record: CredentialRecord) {
  const s = (record.state ?? {}) as OAuth2State;
  return {
    authorized: !!(s.access_token || record.secrets?.refresh_token) && !s.needs_reauth,
    needs_reauth: !!s.needs_reauth,
    has_refresh_token: !!record.secrets?.refresh_token,
    account: s.account ?? null,
    scope: s.scope ?? null,
    access_token_expires_at: s.expires_at ? new Date(s.expires_at).toISOString() : null,
    authorized_at: s.authorized_at ?? null,
  };
}

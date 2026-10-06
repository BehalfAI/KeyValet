// Google 服务账号：用私钥签 JWT 换 access token（RFC 7523 JWT bearer grant）。

import { Vault, VaultError, type CredentialRecord } from "../vault.js";
import { nowSec, optStr, str, strList } from "./check.js";
import { assertHttpsUrl, obj, postForm, remoteError } from "./http.js";
import { checkJwtKey, signJwt } from "./jwt.js";

interface SAConfig {
  client_email: string;
  project_id?: string;
  token_uri: string;
  scopes: string[];
  /** 域范围授权时模拟的用户；只能在设置时指定，agent 取 token 时不能更改 */
  subject?: string;
}

interface CachedToken {
  access_token: string;
  expires_at: number;
}

const DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"];
const MAX_CACHE = 20;

/** 解析并校验服务账号 JSON 密钥文件 */
export function validateServiceAccountSetup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  let key: Record<string, unknown>;
  try {
    key = JSON.parse(str(secrets.key_json, "服务账号密钥文件", 20_000)) as Record<string, unknown>;
  } catch (e) {
    throw e instanceof VaultError ? e : new VaultError("服务账号密钥文件不是合法 JSON");
  }
  if (key.type !== "service_account") throw new VaultError('密钥文件的 type 不是 "service_account"');
  const privateKey = checkJwtKey("RS256", str(key.private_key, "private_key", 10_000));
  const scopes = strList(config.scopes, "scopes");
  const cfg: SAConfig = {
    client_email: str(key.client_email, "client_email", 300),
    project_id: optStr(key.project_id, "project_id", 200),
    token_uri: assertHttpsUrl(key.token_uri ?? "https://oauth2.googleapis.com/token", "token_uri"),
    scopes: scopes.length ? scopes : DEFAULT_SCOPES,
    subject: optStr(config.subject, "subject", 300),
  };
  return {
    config: cfg as unknown as Record<string, unknown>,
    secrets: { private_key: privateKey, private_key_id: optStr(key.private_key_id, "private_key_id", 200) ?? "" },
  };
}

export async function serviceAccountToken(vault: Vault, p: { type: unknown; name: unknown; scopes?: unknown; force?: unknown }) {
  const { type: t, name: n, record } = vault.getRecord(p.type, p.name);
  if (record.kind !== "google_service_account") throw new VaultError(`"${t}/${n}" 不是 Google 服务账号凭证`);
  const cfg = record.config as unknown as SAConfig;
  const requested = strList(p.scopes, "scopes");
  // 只允许请求设置时配置的 scope 的子集（配合域范围授权时尤其重要）
  const extra = requested.filter((s) => !cfg.scopes.includes(s));
  if (extra.length) throw new VaultError(`请求的 scope 不在该凭证允许的范围内：${extra.join(" ")}（允许：${cfg.scopes.join(" ")}）`);
  const scopes = [...new Set(requested.length ? requested : cfg.scopes)].sort();
  const cacheKey = scopes.join(" ");
  const cache = ((record.state ?? {}).tokens ?? {}) as Record<string, CachedToken>;
  const hit = Object.hasOwn(cache, cacheKey) ? cache[cacheKey] : undefined;
  if (hit && p.force !== true && hit.expires_at - 60_000 > Date.now()) return out(hit, cacheKey, cfg);

  const iat = nowSec();
  const claims: Record<string, unknown> = { iss: cfg.client_email, scope: cacheKey, aud: cfg.token_uri, iat, exp: iat + 3600 };
  if (cfg.subject) claims.sub = cfg.subject;
  const header = record.secrets?.private_key_id ? { kid: record.secrets.private_key_id } : {};
  const assertion = signJwt("RS256", record.secrets!.private_key!, claims, header);
  const r = await postForm(cfg.token_uri, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion });
  const j = obj(r);
  if (r.status >= 300 || typeof j.access_token !== "string") throw remoteError(new URL(cfg.token_uri).host, r);
  const expiresIn = Number(j.expires_in ?? 3600);
  const tok: CachedToken = {
    access_token: j.access_token,
    expires_at: Date.now() + (Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : 3600) * 1000,
  };

  vault.patchRecord(t, n, "google_service_account", record.generation, (rec: CredentialRecord) => {
    const tokens = { ...((rec.state?.tokens ?? {}) as Record<string, CachedToken>), [cacheKey]: tok };
    const keys = Object.keys(tokens);
    for (const k of keys.slice(0, Math.max(0, keys.length - MAX_CACHE))) delete tokens[k];
    rec.state = { ...rec.state, tokens };
  });
  return out(tok, cacheKey, cfg);
}

function out(tok: CachedToken, scope: string, cfg: SAConfig) {
  return {
    access_token: tok.access_token,
    token_type: "Bearer",
    expires_at: new Date(tok.expires_at).toISOString(),
    scope,
    account: cfg.subject ?? cfg.client_email,
  };
}

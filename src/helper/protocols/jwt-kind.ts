// Generic JWT signing: e.g. the App Store Connect API (ES256), and other services that require self-signed JWTs.
// All claims are fixed at setup time; the agent can only get short-lived JWTs signed from this template, never the private key.

import { t } from "../../shared/i18n.js";
import { Vault, VaultError } from "../vault.js";
import { int, jsonRecord, nowSec, oneOf, optStr, str } from "./check.js";
import { JWT_ALGORITHMS, checkJwtKey, signJwt, type JwtAlgorithm } from "./jwt.js";

interface JwtConfig {
  algorithm: JwtAlgorithm;
  issuer?: string;
  subject?: string;
  audience?: string | string[];
  key_id?: string;
  lifetime_seconds: number;
  claims: Record<string, unknown>;
  header: Record<string, unknown>;
}

const RESERVED = ["iss", "sub", "aud", "iat", "exp", "nbf", "jti"];

export function validateJwtSetup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  const algorithm = oneOf(config.algorithm, "algorithm", JWT_ALGORITHMS, "ES256");
  const aud = config.audience;
  let audience: string | string[] | undefined;
  if (Array.isArray(aud)) audience = aud.map((a, i) => str(a, `audience[${i}]`, 300));
  else audience = optStr(aud, "audience", 300);
  const claims = jsonRecord(config.claims, "claims");
  for (const k of RESERVED) if (Object.hasOwn(claims, k)) throw new VaultError(t(`claims 不能包含保留字段 ${k}，请使用对应的专用参数`, `claims must not contain reserved field ${k}; use the corresponding dedicated parameter instead`));
  const header = jsonRecord(config.header, "header", 2048);
  for (const k of ["alg", "typ", "kid"]) if (Object.hasOwn(header, k)) throw new VaultError(t(`header 不能包含 ${k}`, `header must not contain ${k}`));
  const cfg: JwtConfig = {
    algorithm,
    issuer: optStr(config.issuer, "issuer", 300),
    subject: optStr(config.subject, "subject", 300),
    audience,
    key_id: optStr(config.key_id, "key_id", 200),
    lifetime_seconds: int(config.lifetime_seconds, "lifetime_seconds", 30, 86_400, 1200),
    claims,
    header,
  };
  return {
    config: cfg as unknown as Record<string, unknown>,
    secrets: { key: checkJwtKey(algorithm, str(secrets.key, "key", 10_000)) },
  };
}

export function jwtToken(vault: Vault, p: { type: unknown; name: unknown }) {
  const { type: ty, name: n, record } = vault.getRecord(p.type, p.name);
  if (record.kind !== "jwt") throw new VaultError(t(`"${ty}/${n}" 不是 JWT 签发凭证`, `"${ty}/${n}" is not a JWT signing credential`));
  const cfg = record.config as unknown as JwtConfig;
  const iat = nowSec();
  const claims: Record<string, unknown> = { ...cfg.claims, iat, exp: iat + cfg.lifetime_seconds };
  if (cfg.issuer) claims.iss = cfg.issuer;
  if (cfg.subject) claims.sub = cfg.subject;
  if (cfg.audience) claims.aud = cfg.audience;
  const header = { ...cfg.header, ...(cfg.key_id ? { kid: cfg.key_id } : {}) };
  return {
    access_token: signJwt(cfg.algorithm, record.secrets!.key!, claims, header),
    token_type: "Bearer",
    expires_at: new Date((iat + cfg.lifetime_seconds) * 1000).toISOString(),
  };
}

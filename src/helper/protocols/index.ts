import { t } from "../../shared/i18n.js";
import { SECRET_REBIND_MARK } from "../../shared/protocol.js";
import { Vault, VaultError, normalizeName, normalizeType, type CredentialRecord, type Kind } from "../vault.js";
import { awsCredentials, validateAwsSetup } from "./aws.js";
import { gitHubAppToken, validateGitHubAppSetup } from "./github-app.js";
import { serviceAccountToken, validateServiceAccountSetup } from "./google-sa.js";
import { jwtToken, validateJwtSetup } from "./jwt-kind.js";
import { accessToken as oauth2Token, publicState as oauth2State, validateOAuth2Setup } from "./oauth2.js";
import { totpCode, validateTotpSetup } from "./totp.js";

type Validator = (config: Record<string, unknown>, secrets: Record<string, unknown>) => {
  config: Record<string, unknown>;
  secrets: Record<string, string>;
};

const VALIDATORS: Record<Exclude<Kind, "static">, Validator> = {
  oauth2: validateOAuth2Setup,
  google_service_account: validateServiceAccountSetup,
  github_app: validateGitHubAppSetup,
  jwt: validateJwtSetup,
  totp: validateTotpSetup,
  aws: validateAwsSetup,
};

function asRecord(v: unknown, what: string): Record<string, unknown> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(t(`${what} 必须是对象`, `${what} must be an object`));
  return v as Record<string, unknown>;
}

/** 创建/替换协议凭证。凭证类型不存在时会先创建类型（与 static 凭证一致）。 */
export function setupProtocol(vault: Vault, p: Record<string, unknown>) {
  const kind = p.kind as Kind;
  if (typeof kind !== "string" || kind === "static" || !Object.hasOwn(VALIDATORS, kind)) {
    throw new VaultError(t(`未知的协议种类 ${String(p.kind)}`, `Unknown protocol kind ${String(p.kind)}`));
  }
  const inSecrets = { ...asRecord(p.secrets, "secrets") };
  let previous: CredentialRecord | undefined;
  if (p.reuseClientSecret === true) {
    // 只改 scope 等时沿用旧 client secret；但端点或 client 一旦变化就必须重新输入，
    // 防止把已保存的 secret 发往新的（可能是恶意的）地址。
    if (kind !== "oauth2") throw new VaultError(t("只有 oauth2 凭证可以沿用 client secret", "Only oauth2 credentials can reuse the client secret"));
    previous = vault.getRecord(p.type, p.name).record;
    if (previous.kind !== "oauth2") throw new VaultError(t("已有凭证不是 oauth2，不能沿用 client secret", "The existing credential is not oauth2; cannot reuse the client secret"));
    if (previous.secrets?.client_secret) inSecrets.client_secret = previous.secrets.client_secret;
  }
  const { config, secrets } = VALIDATORS[kind as Exclude<Kind, "static">](asRecord(p.config, "config"), inSecrets);
  if (previous) {
    for (const k of ["client_id", "token_url", "authorization_url", "device_authorization_url", "token_auth_method"]) {
      if ((previous.config ?? {})[k] !== config[k]) {
        throw new VaultError(
          t(
            `${SECRET_REBIND_MARK} ${k} 已变化，不能沿用旧的 client secret，请重新输入`,
            `${SECRET_REBIND_MARK} ${k} has changed; the old client secret cannot be reused, please enter it again`,
          ),
        );
      }
    }
  }
  if (kind === "aws" && config.mfa_totp) {
    const ref = config.mfa_totp as { type: string; name: string };
    const target = vault.getRecord(ref.type, ref.name);
    if (target.record.kind !== "totp") throw new VaultError(t(`mfa_totp 指向的 "${target.type}/${target.name}" 不是 TOTP 凭证`, `"${target.type}/${target.name}" referenced by mfa_totp is not a TOTP credential`));
    config.mfa_totp = { type: target.type, name: target.name };
  }
  return vault.setProtocol({
    type: p.type,
    name: p.name,
    kind,
    config,
    secrets,
    description: p.description,
    typeDescription: p.typeDescription,
    overwrite: p.overwrite === true,
  });
}

/** 给 agent 看的视图：配置和状态，不含任何秘密和缓存的 token */
export function publicView(type: string, name: string, rec: CredentialRecord) {
  const kind = rec.kind ?? "static";
  const base = { type, name, kind, description: rec.description, updatedAt: rec.updatedAt };
  const cfg = { ...(rec.config ?? {}) };
  switch (kind) {
    case "oauth2":
      return { ...base, config: cfg, status: oauth2State(rec), how_to_use: t("调用 credential_access_token 获取 access token", "Call credential_access_token to get an access token") };
    case "google_service_account":
    case "github_app":
    case "jwt":
      return { ...base, config: cfg, how_to_use: t("调用 credential_access_token 获取短期 token", "Call credential_access_token to get a short-lived token") };
    case "totp":
      return { ...base, config: cfg, how_to_use: t("调用 credential_totp_code 获取当前验证码", "Call credential_totp_code to get the current code") };
    case "aws":
      return { ...base, config: cfg, how_to_use: t("调用 credential_aws_credentials 获取临时凭证", "Call credential_aws_credentials to get temporary credentials") };
    default:
      throw new VaultError(t("static 凭证请使用 get", "Use get for static credentials"));
  }
}

// 同一凭证的并发 token 请求合并为一次（避免重复刷新、以及 refresh token 轮换时互相作废）
const inflight = new Map<string, Promise<unknown>>();
function singleFlight<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const existing = inflight.get(key);
  if (existing) return existing as Promise<T>;
  const p = fn().finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

/** 统一的“取短期 token”入口：oauth2 / google_service_account / github_app / jwt */
export async function accessToken(vault: Vault, p: Record<string, unknown>): Promise<unknown> {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  // 只能代理调用的凭证：token 只在代理内部使用，不返回给调用方（p.viaProxy 只能由 helper 内部设置，见 dispatch）
  if (record.http?.proxy_only && p.viaProxy !== true) {
    throw new VaultError(
      t(
        `"${type}/${name}" 设置为只能代理调用，不能取出 access token；请用 credential_http_request`,
        `"${type}/${name}" is proxy-only; its access token cannot be retrieved. Use credential_http_request instead`,
      ),
    );
  }
  const args = { ...p, type, name };
  const key = `${type}/${name}:${JSON.stringify([p.scopes ?? null, p.repositories ?? null, p.permissions ?? null, p.force === true])}`;
  switch (record.kind) {
    case "oauth2":
      return singleFlight(key, () => oauth2Token(vault, args));
    case "google_service_account":
      return singleFlight(key, () => serviceAccountToken(vault, args));
    case "github_app":
      return singleFlight(key, () => gitHubAppToken(vault, args));
    case "jwt":
      return jwtToken(vault, args);
    default:
      throw new VaultError(t(`"${type}/${name}" 是 ${record.kind ?? "static"} 凭证，不能用于获取 access token`, `"${type}/${name}" is a ${record.kind ?? "static"} credential and cannot be used to get an access token`));
  }
}

export function totp(vault: Vault, p: Record<string, unknown>) {
  return totpCode(vault, { type: normalizeType(p.type), name: normalizeName(p.name) });
}

export function aws(vault: Vault, p: Record<string, unknown>) {
  const type = normalizeType(p.type);
  const name = normalizeName(p.name);
  const key = `aws:${type}/${name}:${JSON.stringify([p.duration_seconds ?? null, p.force === true])}`;
  return singleFlight(key, () => awsCredentials(vault, { ...p, type, name }));
}

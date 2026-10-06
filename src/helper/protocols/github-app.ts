// GitHub App：用 App 私钥签 JWT，换取 1 小时有效的 installation access token。

import { Vault, VaultError, type CredentialRecord } from "../vault.js";
import { nowSec, str, strList } from "./check.js";
import { assertHttpsUrl, httpRequest, obj, remoteError } from "./http.js";
import { checkJwtKey, signJwt } from "./jwt.js";

interface GitHubAppConfig {
  app_id: string;
  installation_id?: string;
  api_base_url: string;
}

interface CachedToken {
  token: string;
  expires_at: number;
  permissions?: unknown;
  repository_selection?: unknown;
}

export function validateGitHubAppSetup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  const appId = str(String(config.app_id ?? ""), "app_id", 100);
  if (!/^(\d+|Iv[0-9A-Za-z.]+)$/.test(appId)) throw new VaultError("app_id 应为数字 App ID 或 Client ID（Iv 开头）");
  const inst = config.installation_id == null || config.installation_id === "" ? undefined : String(config.installation_id);
  if (inst !== undefined && !/^\d+$/.test(inst)) throw new VaultError("installation_id 必须是数字");
  const cfg: GitHubAppConfig = {
    app_id: appId,
    installation_id: inst,
    api_base_url: assertHttpsUrl(config.api_base_url ?? "https://api.github.com", "api_base_url").replace(/\/+$/, ""),
  };
  return {
    config: cfg as unknown as Record<string, unknown>,
    secrets: { private_key: checkJwtKey("RS256", str(secrets.private_key, "private_key", 10_000)) },
  };
}

function ghHeaders(jwt: string): Record<string, string> {
  return { Accept: "application/vnd.github+json", Authorization: `Bearer ${jwt}`, "X-GitHub-Api-Version": "2022-11-28" };
}

export async function gitHubAppToken(
  vault: Vault,
  p: { type: unknown; name: unknown; repositories?: unknown; permissions?: unknown; force?: unknown },
) {
  const { type: t, name: n, record } = vault.getRecord(p.type, p.name);
  if (record.kind !== "github_app") throw new VaultError(`"${t}/${n}" 不是 GitHub App 凭证`);
  const cfg = record.config as unknown as GitHubAppConfig;
  const repositories = strList(p.repositories, "repositories", 100);
  const permissions = p.permissions == null ? undefined : (p.permissions as Record<string, unknown>);
  if (permissions !== undefined && (typeof permissions !== "object" || Array.isArray(permissions))) {
    throw new VaultError("permissions 必须是对象，如 {\"contents\": \"read\"}");
  }
  const narrowed = repositories.length > 0 || permissions !== undefined;

  // 只缓存未收窄权限的 token
  const cached = (record.state ?? {}).token as CachedToken | undefined;
  if (!narrowed && cached && p.force !== true && cached.expires_at - 5 * 60_000 > Date.now()) return out(cached, cfg);

  const iat = nowSec() - 60; // 容忍时钟偏差
  const jwt = signJwt("RS256", record.secrets!.private_key!, { iat, exp: iat + 600, iss: cfg.app_id });

  let installationId = cfg.installation_id;
  if (!installationId) {
    const r = await httpRequest(`${cfg.api_base_url}/app/installations`, { method: "GET", headers: ghHeaders(jwt) });
    if (r.status >= 300 || !Array.isArray(r.json)) throw remoteError(new URL(cfg.api_base_url).host, r);
    const list = r.json as Array<{ id: number; account?: { login?: string } }>;
    if (list.length !== 1) {
      const desc = list.map((i) => `${i.id}（${i.account?.login ?? "?"}）`).join("、") || "无";
      throw new VaultError(`该 App 有 ${list.length} 个 installation：${desc}。请重新设置并指定 installation_id。`);
    }
    installationId = String(list[0]!.id);
  }

  const body: Record<string, unknown> = {};
  if (repositories.length) body.repositories = repositories;
  if (permissions) body.permissions = permissions;
  const r = await httpRequest(`${cfg.api_base_url}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: { ...ghHeaders(jwt), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = obj(r);
  if (r.status >= 300 || typeof j.token !== "string") throw remoteError(new URL(cfg.api_base_url).host, r);
  const tok: CachedToken = {
    token: j.token,
    expires_at: Date.parse(String(j.expires_at)) || Date.now() + 3600_000,
    permissions: j.permissions,
    repository_selection: j.repository_selection,
  };
  if (!narrowed) {
    vault.patchRecord(t, n, "github_app", record.generation, (rec: CredentialRecord) => {
      rec.state = { ...rec.state, token: tok, installation_id: installationId };
    });
  }
  return out(tok, cfg);
}

function out(tok: CachedToken, cfg: GitHubAppConfig) {
  return {
    access_token: tok.token,
    token_type: "token",
    expires_at: new Date(tok.expires_at).toISOString(),
    permissions: tok.permissions ?? null,
    repository_selection: tok.repository_selection ?? null,
    api_base_url: cfg.api_base_url,
  };
}

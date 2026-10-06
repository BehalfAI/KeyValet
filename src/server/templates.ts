// 模板库：内置通用模板 + 自带模板库（templates/catalog.json）+ 可选的本地 n8n 模板库（templates/n8n-catalog.json）。
// 安装时随代码复制到 root 所有的目录。

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { OAUTH_PRESETS, resolvePreset, type OAuthPreset } from "../shared/oauth-presets.js";
import { BUILTIN_TEMPLATES, type CredentialTemplate } from "../shared/templates.js";

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "templates");

let cache: CredentialTemplate[] | null = null;

function load(file: string): CredentialTemplate[] {
  try {
    return (JSON.parse(fs.readFileSync(path.join(DIR, file), "utf8")) as { templates: CredentialTemplate[] }).templates;
  } catch {
    return []; // 文件不存在（如没有生成 n8n 模板库）
  }
}

export function allTemplates(): CredentialTemplate[] {
  if (cache) return cache;
  // 按优先级合并，id 相同（不区分大小写）时保留优先级高的
  const seen = new Set<string>();
  cache = [];
  for (const t of [...BUILTIN_TEMPLATES, ...load("catalog.json"), ...load("n8n-catalog.json")]) {
    const k = t.id.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    cache.push(t);
  }
  return cache;
}

export function getTemplate(id: string): CredentialTemplate | undefined {
  const lower = id.trim().toLowerCase();
  return allTemplates().find((t) => t.id.toLowerCase() === lower);
}

/** 按 id / 名称模糊搜索：完全匹配 > 前缀 > 包含 */
export function searchTemplates(query: string | undefined, kind: string | undefined, limit: number): CredentialTemplate[] {
  const q = (query ?? "").trim().toLowerCase();
  const scored: Array<[number, CredentialTemplate]> = [];
  for (const t of allTemplates()) {
    if (kind && t.kind !== kind) continue;
    const id = t.id.toLowerCase();
    const name = t.name.toLowerCase();
    let score = 0;
    if (!q) score = 1;
    else if (id === q || name === q) score = 100;
    else if (id.startsWith(q) || name.startsWith(q)) score = 50;
    else if (id.includes(q) || name.includes(q)) score = 10;
    if (score) scored.push([score + (t.source === "builtin" ? 0.6 : t.source === "catalog" ? 0.5 : 0), t]);
  }
  return scored.sort((a, b) => b[0] - a[0] || a[1].name.localeCompare(b[1].name)).slice(0, limit).map(([, t]) => t);
}

export function summarize(t: CredentialTemplate) {
  return {
    id: t.id,
    name: t.name,
    kind: t.kind,
    secret_fields: t.fields.filter((f) => f.secret).map((f) => f.name),
    proxy: t.kind === "oauth2" ? "授权后可代理（需设置允许的域名）" : t.inject ? "可代理调用" : "不可代理（仅存储）",
    can_test: !!t.test,
    hosts: t.hosts ?? [],
  };
}

/** OAuth 服务商：内置预设优先，其次 n8n 的 OAuth2 模板（按模板 id） */
export function resolveOAuthProvider(provider: string, tenant?: string): (OAuthPreset & { token_auth_method?: string }) | null {
  const builtin = resolvePreset(provider, tenant);
  if (builtin) return builtin;
  const t = getTemplate(provider);
  if (!t?.oauth2) return null;
  return {
    label: t.name,
    authorization_url: t.oauth2.authorization_url,
    token_url: t.oauth2.token_url,
    extra_auth_params: t.oauth2.extra_auth_params,
    default_scopes: t.oauth2.scopes,
    token_auth_method: t.oauth2.token_auth_method,
    notes: t.docs ? `参考：${t.docs}` : "",
  };
}

export function oauthProviderNames(): string {
  const extra = allTemplates().filter((t) => t.oauth2).length;
  return `${Object.keys(OAUTH_PRESETS).join("、")}${extra ? `，以及模板库中的 ${extra} 个 OAuth2 模板（用 credential_templates kind=oauth2 搜索，以模板 id 作为 provider）` : ""}`;
}

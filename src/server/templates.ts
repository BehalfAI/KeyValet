// Template catalog: built-in generic templates + the bundled catalog (templates/catalog.json)
// + an optional local n8n catalog (templates/n8n-catalog.json).
// Copied alongside the code into the root-owned directory at install time.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { OAUTH_PRESETS, resolvePreset, type OAuthPreset } from "../shared/oauth-presets.js";
import { BUILTIN_TEMPLATES, type CredentialTemplate } from "../shared/templates.js";
import { t } from "../shared/i18n.js";

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "templates");

let cache: CredentialTemplate[] | null = null;

function load(file: string): CredentialTemplate[] {
  try {
    return (JSON.parse(fs.readFileSync(path.join(DIR, file), "utf8")) as { templates: CredentialTemplate[] }).templates;
  } catch {
    return []; // File doesn't exist (e.g., the n8n catalog wasn't generated)
  }
}

export function allTemplates(): CredentialTemplate[] {
  if (cache) return cache;
  // Merge by priority; when ids match (case-insensitive), keep the higher-priority one
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

/** Fuzzy search by id / name: exact match > prefix > contains */
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

export function summarize(tpl: CredentialTemplate) {
  return {
    id: tpl.id,
    name: tpl.name,
    kind: tpl.kind,
    secret_fields: tpl.fields.filter((f) => f.secret).map((f) => f.name),
    proxy:
      tpl.kind === "oauth2"
        ? t("授权后可代理（需设置允许的域名）", "Proxyable after authorization (allowed hosts must be set)")
        : tpl.inject
          ? t("可代理调用", "Proxyable")
          : t("不可代理（仅存储）", "Not proxyable (storage only)"),
    can_test: !!tpl.test,
    hosts: tpl.hosts ?? [],
  };
}

/** OAuth providers: built-in presets take priority, then n8n's OAuth2 templates (by template id) */
export function resolveOAuthProvider(provider: string, tenant?: string): (OAuthPreset & { token_auth_method?: string }) | null {
  const builtin = resolvePreset(provider, tenant);
  if (builtin) return builtin;
  const tpl = getTemplate(provider);
  if (!tpl?.oauth2) return null;
  return {
    label: tpl.name,
    authorization_url: tpl.oauth2.authorization_url,
    token_url: tpl.oauth2.token_url,
    extra_auth_params: tpl.oauth2.extra_auth_params,
    default_scopes: tpl.oauth2.scopes,
    token_auth_method: tpl.oauth2.token_auth_method,
    notes: tpl.docs ? t(`参考：${tpl.docs}`, `See: ${tpl.docs}`) : "",
  };
}

export function oauthProviderNames(): string {
  const extra = allTemplates().filter((tpl) => tpl.oauth2).length;
  return t(
    `${Object.keys(OAUTH_PRESETS).join("、")}${extra ? `，以及模板库中的 ${extra} 个 OAuth2 模板（用 credential_templates kind=oauth2 搜索，以模板 id 作为 provider）` : ""}`,
    `${Object.keys(OAUTH_PRESETS).join(", ")}${extra ? `, plus ${extra} OAuth2 templates from the catalog (search with credential_templates kind=oauth2 and use the template id as provider)` : ""}`,
  );
}

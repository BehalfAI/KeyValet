// 凭证模板的数据格式。来源（优先级从高到低）：
//   builtin：内置的通用模板（Bearer / Header / Query / Basic）
//   catalog：KeyValet 自带的模板库 templates/catalog.json（scripts/build-catalog.mjs 生成，随项目分发）
//   n8n：可选，用户从本地 n8n 源码生成的 templates/n8n-catalog.json（n8n 许可证不允许再分发，不随项目提供）
//
// 占位符语法：{{字段名}}，引用凭证的秘密字段或非敏感字段；{{value}} 表示单值凭证的值。

export interface TemplateField {
  name: string;
  label: string;
  /** 是否为秘密（需弹窗输入、加密保存、不返回给 agent） */
  secret: boolean;
  required: boolean;
  default?: string | number | boolean;
  description?: string;
  /** options 类型字段的可选值 */
  options?: string[];
}

/** 把凭证注入 HTTP 请求的规则 */
export interface InjectRule {
  headers?: Record<string, string>;
  query?: Record<string, string>;
  basic?: { username: string; password: string };
}

/** 验证凭证是否可用的请求 */
export interface TestRequest {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
  /** 完整 URL 模板，如 https://api.openai.com/v1/models 或 {{url}}/models */
  url: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
}

export interface OAuthTemplate {
  authorization_url: string;
  token_url: string;
  scopes: string[];
  extra_auth_params: Record<string, string>;
  token_auth_method: "client_secret_post" | "client_secret_basic";
}

export interface CredentialTemplate {
  id: string;
  name: string;
  source: "builtin" | "catalog" | "n8n";
  docs?: string;
  /** static：存值并可代理调用；oauth2：用 credential_oauth_login 授权 */
  kind: "static" | "oauth2";
  fields: TemplateField[];
  inject?: InjectRule;
  test?: TestRequest;
  /** 模板中写死的 API 域名（URL 中含字段占位符时，在设置时按字段值计算） */
  hosts?: string[];
  oauth2?: OAuthTemplate;
}

export const PLACEHOLDER_RE = /\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g;

/** 模板引用到的所有字段名 */
export function placeholders(values: Array<string | undefined>): string[] {
  const out = new Set<string>();
  for (const v of values) for (const m of (v ?? "").matchAll(PLACEHOLDER_RE)) out.add(m[1]!);
  return [...out];
}

export function injectStrings(rule: InjectRule | undefined): string[] {
  if (!rule) return [];
  return [
    ...Object.values(rule.headers ?? {}),
    ...Object.values(rule.query ?? {}),
    ...(rule.basic ? [rule.basic.username, rule.basic.password] : []),
  ];
}

/** 内置的通用模板：没有现成模板的 HTTP API 用这些 */
export const BUILTIN_TEMPLATES: CredentialTemplate[] = [
  {
    id: "bearer",
    name: "Generic Bearer token (Authorization: Bearer <token>)",
    source: "builtin",
    kind: "static",
    fields: [{ name: "token", label: "Token", secret: true, required: true }],
    inject: { headers: { Authorization: "Bearer {{token}}" } },
  },
  {
    id: "header",
    name: "Generic header auth (custom header name, e.g. X-Api-Key)",
    source: "builtin",
    kind: "static",
    fields: [
      { name: "headerName", label: "Header name", secret: false, required: true, default: "X-Api-Key" },
      { name: "key", label: "Key", secret: true, required: true },
    ],
    // 头名称来自字段值，由 helper 在设置时展开为固定规则
    inject: { headers: { "{{headerName}}": "{{key}}" } },
  },
  {
    id: "query",
    name: "Generic query parameter auth (e.g. ?api_key=...)",
    source: "builtin",
    kind: "static",
    fields: [
      { name: "paramName", label: "Parameter name", secret: false, required: true, default: "api_key" },
      { name: "key", label: "Key", secret: true, required: true },
    ],
    inject: { query: { "{{paramName}}": "{{key}}" } },
  },
  {
    id: "basic",
    name: "Generic HTTP Basic auth (username + password)",
    source: "builtin",
    kind: "static",
    fields: [
      { name: "user", label: "Username", secret: false, required: true },
      { name: "password", label: "Password", secret: true, required: true },
    ],
    inject: { basic: { username: "{{user}}", password: "{{password}}" } },
  },
];

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { confirm, promptSecret } from "../dialog.js";
import type { HelperSession } from "../session.js";
import { fail, guardOverwrite, importFile, norm, ok, optionalPurposeField, purposeField, resolveType, wrap } from "./common.js";
import { setFromTemplate } from "./http.js";

export const typeField = z.string().describe("凭证类型，如 api_key、password、token、ssh_key（小写，不存在时自动创建）");
export const nameField = z.string().describe("凭证名，如 openai、github、aws-prod（小写）");

export function registerBasicTools(server: McpServer, session: HelperSession): void {
  server.registerTool(
    "credential_status",
    { description: "查看凭证库在本 session 中是否已解锁、授权模式、本会话已授权的凭证（不会触发认证）", inputSchema: {} },
    wrap(async () => {
      const st = session.status();
      const grants = st.state === "unlocked" ? await session.request("sessionInfo", {}).catch(() => null) : null;
      return ok("状态：", { ...st, ...(grants ? { grants } : {}) });
    }),
  );

  server.registerTool(
    "credential_unlock",
    {
      description:
        "弹出 Touch ID 认证（显示目的），通过后解锁凭证库。授权模式为 per_credential（默认）时，传 name 可同时授权使用该凭证；" +
        "使用其他凭证时会再次弹 Touch ID。模式为 all 时一次解锁全部。其他工具在需要时也会自动触发认证。",
      inputSchema: {
        purpose: purposeField,
        name: z.string().optional().describe("要授权使用的凭证名"),
        type: z.string().optional().describe("凭证类型；省略时按名字查找"),
      },
    },
    wrap(async ({ purpose, name, type }) => {
      const target = name ? { type, name } : undefined;
      await session.unlock(purpose, target);
      if (name) {
        const s = session.scoped(purpose, target);
        const t = type ?? (await resolveType(s, name, undefined, ["static", "oauth2", "google_service_account", "github_app", "jwt", "totp", "aws"]));
        await session.grant(t, norm(name), purpose);
      }
      return ok("凭证库已解锁。", { session: session.sessionId, ...(await session.request("sessionInfo", {})) as object });
    }),
  );

  server.registerTool(
    "credential_lock",
    { description: "立即锁定凭证库，之后再访问需要重新通过 Touch ID 认证", inputSchema: {} },
    wrap(async () => {
      session.lock();
      return ok("凭证库已锁定。");
    }),
  );

  server.registerTool(
    "credential_list_types",
    { description: "列出所有凭证类型及每种类型下的凭证数量", inputSchema: { purpose: optionalPurposeField } },
    wrap(async ({ purpose }) => ok("凭证类型：", await session.request("listTypes", {}, purpose ?? "查看凭证类型"))),
  );

  server.registerTool(
    "credential_create_type",
    {
      description: "创建凭证类型（已存在则不做任何事）。一般不需要手动调用，写入凭证时会自动创建缺失的类型。",
      inputSchema: { name: typeField, description: z.string().optional().describe("类型说明"), purpose: purposeField },
    },
    wrap(async ({ name, description, purpose }) => {
      const r = await session.scoped(purpose).request<{ name: string; created: boolean }>("createType", { name, description });
      return ok(r.created ? `已创建凭证类型 "${r.name}"。` : `凭证类型 "${r.name}" 已存在。`);
    }),
  );

  server.registerTool(
    "credential_list",
    {
      description: "列出凭证（类型、名称、kind、说明和非敏感属性，不含凭证值）。kind 不是 static 的是协议凭证，需用对应工具取 token。",
      inputSchema: { type: typeField.optional().describe("只列出该类型；省略则列出全部"), purpose: optionalPurposeField },
    },
    wrap(async ({ type, purpose }) => ok("凭证列表：", await session.request("list", { type }, purpose ?? "查看凭证列表"))),
  );

  server.registerTool(
    "credential_get",
    {
      description:
        "读取一个凭证。static 凭证返回值及说明、非敏感属性；" +
        "协议凭证（oauth2、google_service_account、github_app、jwt、totp、aws）只返回配置和状态，长期秘密不会返回，" +
        "请用 credential_access_token / credential_totp_code / credential_aws_credentials 获取短期凭证。",
      inputSchema: { type: typeField, name: nameField, purpose: purposeField },
    },
    wrap(async ({ type, name, purpose }) => ok("凭证：", await session.scoped(purpose, { type, name }).request("get", { type, name }))),
  );

  server.registerTool(
    "credential_set",
    {
      description:
        "保存 static 凭证（API key、密码、token、SSH 私钥等）。会先检查凭证类型是否存在，不存在则先创建该类型，再写入值。" +
        "推荐传 template（用 credential_templates 搜索，如 openai、anthropic、github，或通用的 bearer / header / query / basic）：" +
        "按模板逐个弹窗输入秘密字段，并自动配置代理调用（credential_http_request）和验证。" +
        "value 和 value_file 都省略时会弹出 macOS 隐藏输入框让用户直接输入（推荐，凭证不经过 AI 上下文）；" +
        "多行内容（如私钥）用 value_file 从文件导入。覆盖已有凭证需要 overwrite=true，并且会弹窗请用户确认。",
      inputSchema: {
        type: typeField.optional().describe("凭证类型（不存在时自动创建）；使用模板时可省略，按模板命名"),
        name: nameField,
        template: z.string().optional().describe("模板 id，如 openai、anthropic、github、bearer、header、basic"),
        fields: z
          .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe("仅模板：非敏感字段的值（如 Base URL、子域名）；秘密字段不要放这里"),
        secret_fields: z.array(z.string()).optional().describe("仅模板：要输入的秘密字段（默认为必填的和注入需要的）"),
        allowed_hosts: z.array(z.string()).optional().describe("仅模板：代理允许的域名（默认按模板计算）"),
        proxy_only: z.boolean().optional().describe("仅模板：只能代理调用，禁止 credential_get 读出原值"),
        verify: z.boolean().optional().describe("仅模板：保存后立即验证（默认 true）"),
        value: z.string().optional().describe("凭证值；省略则由用户在弹窗中输入"),
        value_file: z.string().optional().describe("从该文件读取凭证值（内容不会进入 AI 上下文），如 ~/.ssh/id_ed25519"),
        description: z.string().optional().describe("凭证说明，例如用途"),
        attributes: z
          .record(z.string(), z.string())
          .optional()
          .describe("非敏感附加信息，如 {\"username\": \"...\", \"url\": \"...\"}；不要把秘密放在这里"),
        type_description: z.string().optional().describe("类型不存在需要新建时，类型的说明"),
        overwrite: z.boolean().optional().describe("已存在时是否覆盖，默认 false"),
        purpose: purposeField,
      },
    },
    wrap(async (a) => {
      const { name, value, value_file, description, attributes, type_description, overwrite, purpose } = a;
      const s = session.scoped(purpose, { type: a.type, name });
      if (a.template) {
        if (value || value_file || attributes) return fail("使用模板时请用 fields 传非敏感字段，秘密字段会弹窗输入（不要传 value / value_file / attributes）。");
        const r = await setFromTemplate(s, { ...a, template: a.template });
        const head = `${r.typeCreated ? `凭证类型 "${r.type}" 不存在，已先创建；` : ""}${r.replaced ? "已覆盖" : "已保存"}凭证 "${r.type}/${r.name}"（模板 ${r.template}）。`;
        return ok(head, r);
      }
      if (!a.type) return fail("缺少 type（或改用 template）。");
      const type = a.type;
      if (value && value_file) return fail("value 和 value_file 只能二选一。");
      // 先解锁并检查是否已存在：避免用户输完值才发现不能写
      const exists = await guardOverwrite(s, type, name, overwrite);
      const label = `${norm(type)}/${norm(name)}`;
      let secret = value;
      let source = "";
      if (value_file) {
        const f = await importFile(value_file, label);
        secret = f.content;
        source = f.path;
      } else if (!secret) {
        secret = (await promptSecret(`请输入要保存的凭证值：\n\n${label}\n\n注意：保存后，解锁凭证库的 AI 会话可以读取它。`)) ?? undefined;
        if (!secret) return fail("用户取消了输入，未保存。");
      }
      const r = await s.request<{ type: string; name: string; typeCreated: boolean; replaced: boolean }>("set", {
        type,
        name,
        value: secret,
        description,
        attributes,
        typeDescription: type_description,
        overwrite: exists,
      });
      const steps = [];
      if (r.typeCreated) steps.push(`凭证类型 "${r.type}" 不存在，已先创建`);
      steps.push(r.replaced ? `已覆盖凭证 "${r.type}/${r.name}"` : `已保存凭证 "${r.type}/${r.name}"`);
      if (source) steps.push(`内容来自 ${source}（如不再需要，建议删除原文件）`);
      return ok(steps.join("；") + "。");
    }),
  );

  server.registerTool(
    "credential_delete",
    {
      description: "删除一个凭证（会弹窗请用户确认）",
      inputSchema: { type: typeField, name: nameField, purpose: purposeField },
    },
    wrap(async ({ type, name, purpose }) => {
      const s = session.scoped(purpose);
      const exists = await s.request<boolean>("exists", { type, name });
      const label = `${norm(type)}/${norm(name)}`;
      if (!exists) return fail(`凭证 "${label}" 不存在。`);
      await s.request("delete", { type, name }); // 由 root helper 弹窗确认
      return ok(`已删除凭证 "${label}"。`);
    }),
  );

  server.registerTool(
    "credential_delete_type",
    {
      description: "删除一个空的凭证类型（类型下还有凭证时会失败；会弹窗请用户确认）",
      inputSchema: { name: typeField, purpose: purposeField },
    },
    wrap(async ({ name, purpose }) => {
      const s = session.scoped(purpose);
      const label = norm(name);
      const types = await s.request<Array<{ name: string; count: number }>>("listTypes", {});
      const t = types.find((x) => x.name === label);
      if (!t) return fail(`凭证类型 "${label}" 不存在。`);
      if (t.count > 0) return fail(`凭证类型 "${label}" 下还有 ${t.count} 个凭证，请先删除它们。`);
      if (!(await confirm(`AI agent 请求删除凭证类型：\n\n${label}`, "确认删除"))) {
        return fail("用户拒绝了删除操作。");
      }
      await s.request("deleteType", { name });
      return ok(`已删除凭证类型 "${label}"。`);
    }),
  );

  server.registerTool(
    "credential_audit_log",
    {
      description:
        "查询凭证库的操作记录（最新的在前）：解锁、读取凭证、获取 token、修改/删除等，每条含时间、会话、操作、凭证、目的和结果。" +
        "不含任何凭证值。可按本会话、凭证、操作、时间过滤。",
      inputSchema: {
        this_session_only: z.boolean().optional().describe("只看本会话的记录"),
        session: z.string().optional().describe("指定会话 ID"),
        type: z.string().optional().describe("凭证类型"),
        name: z.string().optional().describe("凭证名"),
        op: z.string().optional().describe("操作，如 unlock、get、accessToken、set、delete"),
        since: z.string().optional().describe("起始时间（ISO 8601），如 2026-10-06T00:00:00Z"),
        limit: z.number().int().optional().describe("最多返回条数，默认 50，最多 500"),
        purpose: optionalPurposeField,
      },
    },
    wrap(async (a) => {
      const r = await session.request(
        "auditQuery",
        { this_session: a.this_session_only === true, session: a.session, type: a.type, name: a.name, op: a.op, since: a.since, limit: a.limit },
        a.purpose ?? "查询凭证操作记录",
      );
      return ok("操作记录：", r);
    }),
  );

  server.registerTool(
    "credential_settings",
    {
      description:
        "查看或修改凭证库设置。grant_mode：per_credential（默认，每个凭证单独 Touch ID 授权）或 all（每个会话一次授权全部凭证）。" +
        "改为 all 会由凭证库弹窗请用户确认；改回 per_credential 不需要。修改对新的会话生效。",
      inputSchema: {
        grant_mode: z.enum(["per_credential", "all"]).optional().describe("省略则只查看"),
        purpose: optionalPurposeField,
      },
    },
    wrap(async (a) => {
      if (a.grant_mode && !a.purpose) return fail("修改设置需要说明目的（purpose）。");
      const r = await session.request("settings", { grant_mode: a.grant_mode, purpose: a.purpose }, a.purpose ?? "查看凭证库设置");
      return ok(a.grant_mode ? "设置已更新：" : "当前设置：", r);
    }),
  );
}

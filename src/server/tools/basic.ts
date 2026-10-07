import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { confirm, promptSecret } from "../dialog.js";
import { recordSecrets, writeSecretFile } from "../gateway-env.js";
import type { HelperSession } from "../session.js";
import { confirmDeleteSourceFile, fail, guardOverwrite, importFile, norm, ok, optionalPurposeField, purposeField, resolveType, wrap } from "./common.js";
import { setFromTemplate } from "./http.js";
import { t } from "../../shared/i18n.js";

export const typeField = z
  .string()
  .describe(t("凭证类型，如 api_key、password、token、ssh_key（小写，不存在时自动创建）", "Credential type, e.g. api_key, password, token, ssh_key (lowercase; created automatically if missing)"));
export const nameField = z.string().describe(t("凭证名，如 openai、github、aws-prod（小写）", "Credential name, e.g. openai, github, aws-prod (lowercase)"));

export function registerBasicTools(server: McpServer, session: HelperSession): void {
  server.registerTool(
    "credential_status",
    {
      description: t(
        "查看凭证库在本 session 中是否已解锁、授权模式、本会话已授权的凭证（不会触发认证）",
        "Show whether the vault is unlocked for this session, the grant mode, and which credentials this session has been granted (does not trigger authentication)",
      ),
      inputSchema: {},
    },
    wrap(async () => {
      const st = session.status();
      const grants = st.state === "unlocked" ? await session.request("sessionInfo", {}).catch(() => null) : null;
      return ok(t("状态：", "Status:"), { ...st, ...(grants ? { grants } : {}) });
    }),
  );

  server.registerTool(
    "credential_unlock",
    {
      description: t(
        "弹出 Touch ID 认证（显示目的），通过后解锁凭证库。授权模式为 per_credential（默认）时，传 name 可同时授权使用该凭证；" +
          "使用其他凭证时会再次弹 Touch ID。模式为 all 时一次解锁全部。其他工具在需要时也会自动触发认证。",
        "Show a Touch ID prompt (displaying the purpose) and unlock the vault once approved. In per_credential grant mode (default), pass name to also grant use of that credential; " +
          "using other credentials will prompt Touch ID again. In all mode, one unlock grants everything. Other tools also trigger authentication automatically when needed.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string().optional().describe(t("要授权使用的凭证名", "Name of the credential to grant use of")),
        type: z.string().optional().describe(t("凭证类型；省略时按名字查找", "Credential type; looked up by name if omitted")),
      },
    },
    wrap(async ({ purpose, name, type }) => {
      const target = name ? { type, name } : undefined;
      await session.unlock(purpose, target);
      if (name) {
        const s = session.scoped(purpose, target);
        const resolvedType = type ?? (await resolveType(s, name, undefined, ["static", "oauth2", "google_service_account", "github_app", "jwt", "totp", "aws"]));
        await session.grant(resolvedType, norm(name), purpose);
      }
      return ok(t("凭证库已解锁。", "Vault unlocked."), { session: session.sessionId, ...(await session.request("sessionInfo", {})) as object });
    }),
  );

  server.registerTool(
    "credential_lock",
    {
      description: t(
        "立即锁定凭证库，之后再访问需要重新通过 Touch ID 认证。remember 模式下传 forget=true 同时清除“记住”状态（否则下次访问会自动解锁）。",
        "Lock the vault now; further access requires Touch ID again. In remember mode pass forget=true to also clear the remembered authorization (otherwise the next access unlocks automatically).",
      ),
      inputSchema: { forget: z.boolean().optional().describe(t("同时清除“记住”状态", "Also clear the remembered authorization")) },
    },
    wrap(async ({ forget }) => {
      if (forget) await session.request("settings", { forget: true, purpose: t("锁定并清除记住状态", "Lock and forget") }, t("锁定并清除记住状态", "Lock and forget"));
      session.lock();
      return ok(forget ? t("凭证库已锁定，“记住”状态已清除。", "Vault locked and remembered authorization cleared.") : t("凭证库已锁定。", "Vault locked."));
    }),
  );

  server.registerTool(
    "credential_list_types",
    { description: t("列出所有凭证类型及每种类型下的凭证数量", "List all credential types and the number of credentials of each type"), inputSchema: { purpose: optionalPurposeField } },
    wrap(async ({ purpose }) => ok(t("凭证类型：", "Credential types:"), await session.request("listTypes", {}, purpose ?? t("查看凭证类型", "List credential types")))),
  );

  server.registerTool(
    "credential_create_type",
    {
      description: t(
        "创建凭证类型（已存在则不做任何事）。一般不需要手动调用，写入凭证时会自动创建缺失的类型。",
        "Create a credential type (no-op if it already exists). Usually unnecessary: missing types are created automatically when a credential is saved.",
      ),
      inputSchema: { name: typeField, description: z.string().optional().describe(t("类型说明", "Type description")), purpose: purposeField },
    },
    wrap(async ({ name, description, purpose }) => {
      const r = await session.scoped(purpose).request<{ name: string; created: boolean }>("createType", { name, description });
      return ok(
        r.created
          ? t(`已创建凭证类型 "${r.name}"。`, `Created credential type "${r.name}".`)
          : t(`凭证类型 "${r.name}" 已存在。`, `Credential type "${r.name}" already exists.`),
      );
    }),
  );

  server.registerTool(
    "credential_list",
    {
      description: t(
        "列出凭证（类型、名称、kind、说明和非敏感属性，不含凭证值）。kind 不是 static 的是协议凭证，需用对应工具取 token。",
        "List credentials (type, name, kind, description and non-sensitive attributes; no secret values). Credentials whose kind is not static are protocol credentials; use the matching tool to obtain tokens.",
      ),
      inputSchema: { type: typeField.optional().describe(t("只列出该类型；省略则列出全部", "Only list this type; lists all if omitted")), purpose: optionalPurposeField },
    },
    wrap(async ({ type, purpose }) => ok(t("凭证列表：", "Credentials:"), await session.request("list", { type }, purpose ?? t("查看凭证列表", "List credentials")))),
  );

  server.registerTool(
    "credential_get",
    {
      description: t(
        "读取一个凭证。static 凭证返回值及说明、非敏感属性；" +
          "协议凭证（oauth2、google_service_account、github_app、jwt、totp、aws）只返回配置和状态，长期秘密不会返回，" +
          "请用 credential_access_token / credential_totp_code / credential_aws_credentials 获取短期凭证。",
        "Read a credential. For static credentials, returns the value, description and non-sensitive attributes; " +
          "for protocol credentials (oauth2, google_service_account, github_app, jwt, totp, aws), returns only configuration and status (long-lived secrets are never returned) - " +
          "use credential_access_token / credential_totp_code / credential_aws_credentials to obtain short-lived credentials.",
      ),
      inputSchema: { type: typeField, name: nameField, purpose: purposeField },
    },
    wrap(async ({ type, name, purpose }) => {
      const r = await session.scoped(purpose, { type, name }).request<{ value?: string; fields?: Record<string, string> }>("get", { type, name });
      recordSecrets(session.sessionId, [r.value, ...Object.values(r.fields ?? {})]);
      return ok(t("凭证：", "Credential:"), r);
    }),
  );

  server.registerTool(
    "credential_export_file",
    {
      description: t(
        "把一个 static 凭证的原始值写入只有你本人账户可读的私有临时文件（~/.keyvalet/run，0600），只把文件路径返回给 AI，内容本身不经过 AI 上下文。" +
          "用于必须读本地文件才能工作的场景，典型例子是 SSH 私钥（配合 ssh -i <路径> 使用）、证书等。" +
          "能走代理时优先用 credential_http_request / credential_gateway；只有代理不适用、又必须落地成文件时才用这个——" +
          "不要先 credential_get 拿到值再自己写文件，那样秘密会先经过 AI 上下文。文件在本会话结束时自动删除。",
        "Write a static credential's raw value to a private temp file readable only by your own account (~/.keyvalet/run, 0600); only the file path is returned, never the content. " +
          "For cases where a program must read a local file to work - the typical examples are SSH private keys (used with ssh -i <path>) and certificates. " +
          "Prefer the proxy (credential_http_request / credential_gateway) when it applies; use this only when the proxy doesn't fit and the secret must land on disk as a file - " +
          "don't call credential_get and write the file yourself, since that routes the secret through the AI context first. The file is deleted automatically when this session ends.",
      ),
      inputSchema: {
        type: typeField.optional().describe(t("凭证类型；省略时按名字在 static 凭证中查找", "Credential type; looked up among static credentials by name if omitted")),
        name: nameField,
        field: z
          .string()
          .optional()
          .describe(t("多秘密字段的模板凭证：要导出的字段名；省略则导出主值（value）", "For template credentials with multiple secret fields: which field to export; omitted exports the main value")),
        purpose: purposeField,
      },
    },
    wrap(async ({ type, name, field, purpose }) => {
      const s = session.scoped(purpose, { type, name });
      const resolvedType = type ?? (await resolveType(s, name, undefined, ["static"]));
      const r = await s.request<{ type: string; name: string; value?: string; fields?: Record<string, string>; kind?: string }>("get", { type: resolvedType, name });
      if (typeof r.value !== "string") {
        return fail(
          t(
            `凭证 "${r.type}/${r.name}" 不是 static 凭证，没有可导出的原始值。`,
            `Credential "${r.type}/${r.name}" is not a static credential; it has no raw value to export.`,
          ),
        );
      }
      const secret = field ? r.fields?.[field] : r.value || undefined;
      if (!secret) {
        const available = Object.keys(r.fields ?? {}).join(t("、", ", "));
        return fail(
          field
            ? t(`凭证 "${r.type}/${r.name}" 没有字段 "${field}"（可用：${available || "无"}）`, `Credential "${r.type}/${r.name}" has no field "${field}" (available: ${available || "none"})`)
            : t(
                `凭证 "${r.type}/${r.name}" 没有主值，请传 field 指定具体字段（可用：${available || "无"}）`,
                `Credential "${r.type}/${r.name}" has no main value; pass field to select one (available: ${available || "none"})`,
              ),
        );
      }
      const path = writeSecretFile(session.sessionId, r.type, r.name, field, secret);
      return ok(t("已写入私有文件（内容未返回给我）：", "Written to a private file (content not returned to me):"), {
        path,
        note: t(
          "只有你本人账户可读；本会话结束时自动删除，提前用完也可以自己删掉。不要让我读取或打印它的内容，直接把这个路径传给需要文件的命令（如 ssh -i）。",
          "Readable only by your own account; deleted automatically when this session ends, or delete it yourself once done. Don't have me read or print its contents - pass this path directly to the command that needs a file (e.g. ssh -i).",
        ),
      });
    }),
  );

  server.registerTool(
    "credential_set",
    {
      description: t(
        "保存 static 凭证（API key、密码、token、SSH 私钥等）。会先检查凭证类型是否存在，不存在则先创建该类型，再写入值。" +
          "推荐传 template（用 credential_templates 搜索，如 openai、anthropic、github，或通用的 bearer / header / query / basic）：" +
          "按模板逐个弹窗输入秘密字段，并自动配置代理调用（credential_http_request）和验证。" +
          "value 和 value_file 都省略时会弹出 macOS 隐藏输入框让用户直接输入（推荐，凭证不经过 AI 上下文）；" +
          "用户已在对话中给出秘密时，直接用 value 传入并主动保存。" +
          "多行内容（如私钥）用 value_file 从文件导入；可加 delete_source_file: true，在保存成功后弹窗请用户确认删除原文件，避免明文留两份。" +
          "覆盖已有凭证需要 overwrite=true，并且会弹窗请用户确认。之后要把 SSH 私钥这类文件型秘密用到本地程序（如 ssh -i）时，用 credential_export_file，不要用 credential_get。",
        "Save a static credential (API key, password, token, SSH private key, etc.). The credential type is created first if it does not exist. " +
          "Passing template is recommended (search with credential_templates, e.g. openai, anthropic, github, or the generic bearer / header / query / basic): " +
          "the user is prompted for each secret field in a dialog, and proxied calls (credential_http_request) and verification are configured automatically. " +
          "If both value and value_file are omitted, a hidden macOS input dialog lets the user type the value directly (recommended - the secret never passes through the AI context); " +
          "if the user already gave the secret in the chat, pass it via value and store it proactively. " +
          "Import multi-line content (e.g. private keys) from a file with value_file; add delete_source_file: true to have the user confirm deleting the original file once the save succeeds, so the plaintext doesn't end up in two places. " +
          "Overwriting an existing credential requires overwrite=true and the user is asked to confirm. Later, to use a file-shaped secret like an SSH private key with a local program (e.g. ssh -i), use credential_export_file, not credential_get.",
      ),
      inputSchema: {
        type: typeField
          .optional()
          .describe(t("凭证类型（不存在时自动创建）；使用模板时可省略，按模板命名", "Credential type (created if missing); optional with template, defaults to a name derived from the template")),
        name: nameField,
        template: z.string().optional().describe(t("模板 id，如 openai、anthropic、github、bearer、header、basic", "Template id, e.g. openai, anthropic, github, bearer, header, basic")),
        fields: z
          .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe(t("仅模板：非敏感字段的值（如 Base URL、子域名）；秘密字段不要放这里", "Template only: values for non-sensitive fields (e.g. base URL, subdomain); never put secret fields here")),
        secret_fields: z.array(z.string()).optional().describe(t("仅模板：要输入的秘密字段（默认为必填的和注入需要的）", "Template only: secret fields to prompt for (default: required ones and those used by injection)")),
        allowed_hosts: z.array(z.string()).optional().describe(t("仅模板：代理允许的域名（默认按模板计算）", "Template only: hosts the proxy may send to (default: derived from the template)")),
        proxy_only: z.boolean().optional().describe(t("仅模板：只能代理调用，禁止 credential_get 读出原值", "Template only: proxy-only - credential_get cannot read the raw value")),
        verify: z.boolean().optional().describe(t("仅模板：保存后立即验证（默认 true）", "Template only: verify right after saving (default true)")),
        value: z
          .string()
          .optional()
          .describe(
            t(
              "凭证值；省略则由用户在弹窗中输入。用户已在对话中给出密钥时直接传入（配合模板时，模板须只有一个秘密字段）",
              "Credential value; if omitted, the user enters it in a dialog. Pass it when the user already gave the secret in the chat (with a template, the template must have a single secret field)",
            ),
          ),
        value_file: z.string().optional().describe(t("从该文件读取凭证值（内容不会进入 AI 上下文），如 ~/.ssh/id_ed25519", "Read the credential value from this file (content never enters the AI context), e.g. ~/.ssh/id_ed25519")),
        delete_source_file: z
          .boolean()
          .optional()
          .describe(
            t(
              "配合 value_file：保存成功后删除原文件（会弹窗请用户单独确认，不可恢复）。默认 false，即原文件原样保留",
              "With value_file: delete the original file after a successful save (the user is asked to confirm separately; cannot be undone). Default false - the original file is left in place",
            ),
          ),
        description: z.string().optional().describe(t("凭证说明，例如用途", "Credential description, e.g. what it is used for")),
        attributes: z
          .record(z.string(), z.string())
          .optional()
          .describe(
            t(
              "非敏感附加信息，如 {\"username\": \"...\", \"url\": \"...\"}；不要把秘密放在这里",
              "Non-sensitive extra info, e.g. {\"username\": \"...\", \"url\": \"...\"}; never put secrets here",
            ),
          ),
        type_description: z.string().optional().describe(t("类型不存在需要新建时，类型的说明", "Description for the type, if it has to be created")),
        overwrite: z.boolean().optional().describe(t("已存在时是否覆盖，默认 false", "Overwrite if it already exists (default false)")),
        purpose: purposeField,
      },
    },
    wrap(async (a) => {
      const { name, value, value_file, delete_source_file, description, attributes, type_description, overwrite, purpose } = a;
      const s = session.scoped(purpose, { type: a.type, name });
      if (delete_source_file && !value_file) return fail(t("delete_source_file 只能配合 value_file 使用。", "delete_source_file can only be used together with value_file."));
      if (a.template) {
        if (value_file || attributes) return fail(
            t(
              "使用模板时请用 fields 传非敏感字段；秘密字段会弹窗输入，或者用户已在对话中给出时通过 value 传入（不要传 value_file / attributes）。",
              "With a template, pass non-sensitive fields via fields; secret fields are entered in a dialog, or passed via value when the user already gave it in the chat (do not pass value_file / attributes).",
            ),
          );
        const r = await setFromTemplate(s, { ...a, template: a.template });
        const head = t(
          `${r.typeCreated ? `凭证类型 "${r.type}" 不存在，已先创建；` : ""}${r.replaced ? "已覆盖" : "已保存"}凭证 "${r.type}/${r.name}"（模板 ${r.template}）。`,
          `${r.typeCreated ? `Credential type "${r.type}" did not exist and was created; ` : ""}${r.replaced ? "Overwrote" : "Saved"} credential "${r.type}/${r.name}" (template ${r.template}).`,
        );
        return ok(head, r);
      }
      if (!a.type) return fail(t("缺少 type（或改用 template）。", "Missing type (or use template instead)."));
      const type = a.type;
      if (value && value_file) return fail(t("value 和 value_file 只能二选一。", "Pass either value or value_file, not both."));
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
        secret =
          (await promptSecret(
            t(
              `请输入要保存的凭证值：\n\n${label}\n\n注意：保存后，解锁凭证库的 AI 会话可以读取它。`,
              `Enter the credential value to save:\n\n${label}\n\nNote: once saved, AI sessions that unlock the vault can read it.`,
            ),
          )) ?? undefined;
        if (!secret) return fail(t("用户取消了输入，未保存。", "The user cancelled input; nothing was saved."));
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
      if (r.typeCreated) steps.push(t(`凭证类型 "${r.type}" 不存在，已先创建`, `Credential type "${r.type}" did not exist and was created`));
      steps.push(
        r.replaced
          ? t(`已覆盖凭证 "${r.type}/${r.name}"`, `Overwrote credential "${r.type}/${r.name}"`)
          : t(`已保存凭证 "${r.type}/${r.name}"`, `Saved credential "${r.type}/${r.name}"`),
      );
      if (source && delete_source_file) {
        const deleted = await confirmDeleteSourceFile(source);
        steps.push(
          deleted
            ? t(`内容来自 ${source}，原文件已删除`, `Content read from ${source}; the original file was deleted`)
            : t(`内容来自 ${source}（用户拒绝删除原文件，或删除失败，请自行处理）`, `Content read from ${source} (the user declined to delete the original file, or deletion failed; handle it yourself)`),
        );
      } else if (source) {
        steps.push(t(`内容来自 ${source}（如不再需要，建议删除原文件，可传 delete_source_file: true 让我代为确认删除）`, `Content read from ${source} (consider deleting the original file if no longer needed; pass delete_source_file: true to have me confirm and delete it)`));
      }
      return ok(steps.join(t("；", "; ")) + t("。", "."));
    }),
  );

  server.registerTool(
    "credential_delete",
    {
      description: t("删除一个凭证（会弹窗请用户确认）", "Delete a credential (the user is asked to confirm)"),
      inputSchema: { type: typeField, name: nameField, purpose: purposeField },
    },
    wrap(async ({ type, name, purpose }) => {
      const s = session.scoped(purpose);
      const exists = await s.request<boolean>("exists", { type, name });
      const label = `${norm(type)}/${norm(name)}`;
      if (!exists) return fail(t(`凭证 "${label}" 不存在。`, `Credential "${label}" not found.`));
      await s.request("delete", { type, name }); // 由 root helper 弹窗确认
      return ok(t(`已删除凭证 "${label}"。`, `Deleted credential "${label}".`));
    }),
  );

  server.registerTool(
    "credential_delete_type",
    {
      description: t(
        "删除一个空的凭证类型（类型下还有凭证时会失败；会弹窗请用户确认）",
        "Delete an empty credential type (fails if it still contains credentials; the user is asked to confirm)",
      ),
      inputSchema: { name: typeField, purpose: purposeField },
    },
    wrap(async ({ name, purpose }) => {
      const s = session.scoped(purpose);
      const label = norm(name);
      const types = await s.request<Array<{ name: string; count: number }>>("listTypes", {});
      const entry = types.find((x) => x.name === label);
      if (!entry) return fail(t(`凭证类型 "${label}" 不存在。`, `Credential type "${label}" not found.`));
      if (entry.count > 0)
        return fail(
          t(
            `凭证类型 "${label}" 下还有 ${entry.count} 个凭证，请先删除它们。`,
            `Credential type "${label}" still contains ${entry.count} credential(s); delete them first.`,
          ),
        );
      if (!(await confirm(t(`AI agent 请求删除凭证类型：\n\n${label}`, `An AI agent wants to delete the credential type:\n\n${label}`), t("确认删除", "Delete")))) {
        return fail(t("用户拒绝了删除操作。", "The user declined the deletion."));
      }
      await s.request("deleteType", { name });
      return ok(t(`已删除凭证类型 "${label}"。`, `Deleted credential type "${label}".`));
    }),
  );

  server.registerTool(
    "credential_audit_log",
    {
      description: t(
        "查询凭证库的操作记录（最新的在前）：解锁、读取凭证、获取 token、修改/删除等，每条含时间、会话、操作、凭证、目的和结果。" +
          "不含任何凭证值。可按本会话、凭证、操作、时间过滤。",
        "Query the vault's audit log (newest first): unlocks, credential reads, token requests, changes/deletions, etc. Each entry has time, session, operation, credential, purpose and result. " +
          "Contains no credential values. Filter by this session, credential, operation or time.",
      ),
      inputSchema: {
        this_session_only: z.boolean().optional().describe(t("只看本会话的记录", "Only entries from this session")),
        session: z.string().optional().describe(t("指定会话 ID", "Filter by session ID")),
        type: z.string().optional().describe(t("凭证类型", "Credential type")),
        name: z.string().optional().describe(t("凭证名", "Credential name")),
        op: z.string().optional().describe(t("操作，如 unlock、get、accessToken、set、delete", "Operation, e.g. unlock, get, accessToken, set, delete")),
        since: z.string().optional().describe(t("起始时间（ISO 8601），如 2026-10-06T00:00:00Z", "Start time (ISO 8601), e.g. 2026-10-06T00:00:00Z")),
        limit: z.number().int().optional().describe(t("最多返回条数，默认 50，最多 500", "Maximum entries to return (default 50, max 500)")),
        purpose: optionalPurposeField,
      },
    },
    wrap(async (a) => {
      const r = await session.request(
        "auditQuery",
        { this_session: a.this_session_only === true, session: a.session, type: a.type, name: a.name, op: a.op, since: a.since, limit: a.limit },
        a.purpose ?? t("查询凭证操作记录", "Query the credential audit log"),
      );
      return ok(t("操作记录：", "Audit log:"), r);
    }),
  );

  server.registerTool(
    "credential_settings",
    {
      description: t(
        "查看或修改 KeyValet 的授权模式。grant_mode：per_use（每次使用凭证都按 Touch ID）、per_credential（默认，每个会话中每个凭证按一次）、" +
          "per_session（每个会话按一次）、remember（按一次后，remember_hours 小时内所有会话都不用再按；0 表示永久）。" +
          "放宽（更宽松的模式或更长的记住时长）需要用户按 Touch ID；收紧立即生效。修改对当前会话也立即生效。forget=true 清除“记住”状态。" +
          "只在用户明确要求时修改设置。",
        "View or change KeyValet's authorization mode. grant_mode: per_use (Touch ID for every use), per_credential (default; Touch ID once per credential per session), " +
          "per_session (Touch ID once per session), remember (Touch ID once, then no prompts for any session for remember_hours hours; 0 = forever). " +
          "Loosening (a more permissive mode or a longer remember window) requires the user's Touch ID; tightening applies immediately. Changes take effect in the current session too. forget=true clears the remembered authorization. " +
          "Only change settings when the user explicitly asks.",
      ),
      inputSchema: {
        grant_mode: z.enum(["per_use", "per_credential", "per_session", "remember", "all"]).optional().describe(t("省略则只查看（all 等同 per_session）", "Omit to only view (all = per_session)")),
        remember_hours: z.number().min(0).max(8760).optional().describe(t("remember 模式的时长（小时），0 表示永久", "Duration for remember mode in hours; 0 = forever")),
        forget: z.boolean().optional().describe(t("清除当前的“记住”状态", "Clear the current remembered authorization")),
        purpose: optionalPurposeField,
      },
    },
    wrap(async (a) => {
      const changing = a.grant_mode !== undefined || a.remember_hours !== undefined || a.forget === true;
      if (changing && !a.purpose) return fail(t("修改设置需要说明目的（purpose）。", "Changing settings requires a purpose."));
      const r = await session.request(
        "settings",
        { grant_mode: a.grant_mode, remember_hours: a.remember_hours, forget: a.forget, purpose: a.purpose },
        a.purpose ?? t("查看凭证库设置", "View vault settings"),
      );
      return ok(changing ? t("设置已更新：", "Settings updated:") : t("当前设置：", "Current settings:"), r);
    }),
  );
}

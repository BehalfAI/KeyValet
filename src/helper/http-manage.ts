// 修改已有凭证的代理配置。扩大暴露面的改动（新增域名、修改注入规则、关闭「只能代理调用」、删除配置）
// 由 helper 自己以用户身份弹窗确认——不依赖 MCP server 的确认，绕过 server 直接驱动 helper 也无效。

import { cleanPurpose } from "../shared/protocol.js";
import { validateHttpConfig } from "./http-config.js";
import { confirmAsUser } from "./user-dialog.js";
import { Vault, VaultError, type HttpConfig } from "./vault.js";
import { t } from "../shared/i18n.js";

const summarizeInject = (c?: HttpConfig) => {
  const r = c?.inject;
  if (!r) return t("（自动注入 access token）", "(access token injected automatically)");
  const parts = [
    ...Object.keys(r.headers ?? {}).map((h) => t(`请求头 ${h}`, `header ${h}`)),
    ...Object.keys(r.query ?? {}).map((q) => t(`查询参数 ${q}`, `query parameter ${q}`)),
    ...(r.basic ? [t("Basic 认证", "Basic auth")] : []),
  ];
  return parts.join(t("、", ", "));
};

export async function configureHttp(vault: Vault, p: Record<string, unknown>) {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  const prev = record.http;
  const label = `${type}/${name}`;
  const purpose = cleanPurpose(p.purpose) ?? "";

  if (p.remove === true) {
    if (!prev) return { type, name, http: null };
    const message = t(
      `AI 会话请求删除凭证 ${label} 的代理调用配置${prev.proxy_only ? "（之后可以读出原始秘密）" : ""}。\n\n目的：${purpose.slice(0, 200)}`,
      `An AI session is requesting to remove the proxy configuration of credential ${label}${prev.proxy_only ? " (the raw secret will then be readable)" : ""}.\n\nPurpose: ${purpose.slice(0, 200)}`,
    );
    if (!(await confirmAsUser(message, t("允许删除", "Allow Removal")))) {
      throw new VaultError(t("用户拒绝了该修改", "The user denied this change"));
    }
    vault.updateHttp(type, name, (rec) => {
      if (JSON.stringify(rec.http ?? null) !== JSON.stringify(prev)) throw new VaultError(t("配置在确认期间被修改，请重试", "The configuration was modified during confirmation; please retry"));
      return undefined;
    });
    return { type, name, http: null };
  }

  const next = validateHttpConfig(
    {
      inject: p.inject !== undefined ? p.inject : prev?.inject,
      allowed_hosts: p.allowed_hosts !== undefined ? p.allowed_hosts : prev?.allowed_hosts,
      proxy_only: p.proxy_only !== undefined ? p.proxy_only : (prev?.proxy_only ?? false),
      test: p.test !== undefined ? p.test : prev?.test,
    },
    record,
    { allowSecretsInTest: false, prevTest: prev?.test },
  );

  const newHosts = next.allowed_hosts.filter((h) => !(prev?.allowed_hosts ?? []).includes(h));
  const injectChanged = JSON.stringify(next.inject ?? null) !== JSON.stringify(prev?.inject ?? null);
  const unlocking = !!prev?.proxy_only && !next.proxy_only;
  if (newHosts.length || injectChanged || unlocking) {
    const lines = [t(`AI 会话请求修改凭证 ${label} 的代理调用配置：`, `An AI session is requesting to change the proxy configuration of credential ${label}:`), ""];
    if (newHosts.length) lines.push(t(`• 新增允许发往的域名：${newHosts.join("、")}`, `• New allowed hosts: ${newHosts.join(", ")}`));
    if (injectChanged) lines.push(t(`• 注入方式：${summarizeInject(next)}`, `• Injection: ${summarizeInject(next)}`));
    if (unlocking) lines.push(t("• 关闭「只能代理调用」：之后可以读出原始秘密", `• Turn off "proxy only": the raw secret will then be readable`));
    lines.push("", t(`目的：${purpose.slice(0, 200)}`, `Purpose: ${purpose.slice(0, 200)}`));
    if (!(await confirmAsUser(lines.join("\n"), t("允许", "Allow")))) throw new VaultError(t("用户拒绝了该修改", "The user denied this change"));
  }
  vault.updateHttp(type, name, (rec) => {
    if (JSON.stringify(rec.http ?? null) !== JSON.stringify(prev ?? null)) throw new VaultError(t("配置在确认期间被修改，请重试", "The configuration was modified during confirmation; please retry"));
    return next;
  });
  return { type, name, http: { allowed_hosts: next.allowed_hosts, proxy_only: next.proxy_only, inject: summarizeInject(next), can_test: !!next.test } };
}

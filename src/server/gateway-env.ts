// 会话私有文件：写到仅用户可读的位置（~/.keyvalet/run，目录 0700、文件 0600），会话结束（MCP server 退出）时删除。
// - 网关环境变量文件：令牌写入文件，agent 用 `set -a; . <文件>; set +a; <命令>` 加载——
//   令牌不出现在命令行参数里（ps 对所有用户可见），也不出现在 agent 的上下文里。
// - 秘密文件（writeSecretFile）：某些程序必须从本地文件读取秘密本身（如 ssh -i 私钥），
//   没有网关那样“只转发、真值永不离开 root”的代理方式——写文件这一步就是秘密离开 root helper 的地方；
//   这里能做到的是不让内容经过 agent 的上下文，只把路径还给 agent。
// - 已返回值的记录（recordSecrets）：credential_get / credential_totp_code / credential_access_token /
//   credential_aws_credentials 这类工具，设计上就是把原始秘密交给 agent（没有代理通道可用时别无选择）。
//   把交出去的值记一笔到 <session>.redact，供 Claude Code 的 PreToolUse hook 在 agent 真的把它
//   拼进 shell 命令或写进文件之前拦下来——不管这个值长得像不像“API key”，只要是 KeyValet 亲手交出来的，
//   出现在命令行/文件里就值得警惕。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const created = new Set<string>();

function runDir(): string {
  const dir = path.join(os.homedir(), ".keyvalet", "run");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(dir), 0o700);
  fs.chmodSync(dir, 0o700);
  return dir;
}

const quote = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`;

export function writeGatewayEnv(session: string, type: string, name: string, env: Record<string, string>): string {
  const file = path.join(runDir(), `${session}-${type}-${name}.env`.replace(/[^A-Za-z0-9_.@:-]/g, "_"));
  const body = Object.entries(env)
    .map(([k, v]) => `export ${k}=${quote(v)}`)
    .join("\n");
  fs.rmSync(file, { force: true });
  fs.writeFileSync(file, `${body}\n`, { mode: 0o600, flag: "wx" });
  created.add(file);
  return file;
}

/**
 * 把一个秘密的原始内容写入仅用户可读的文件（同一目录，同样 0600），供需要本地文件的程序使用
 * （如 ssh -i、证书）。内容本身不返回给 agent，只返回路径。会话结束时与网关环境变量文件一起删除。
 */
export function writeSecretFile(session: string, type: string, name: string, field: string | undefined, content: string): string {
  const file = path.join(runDir(), `${session}-${type}-${name}${field ? `-${field}` : ""}.key`.replace(/[^A-Za-z0-9_.@:-]/g, "_"));
  fs.rmSync(file, { force: true });
  fs.writeFileSync(file, content, { mode: 0o600, flag: "wx" });
  created.add(file);
  return file;
}

const MIN_REDACT_LENGTH = 12; // 太短的值（如 6 位 TOTP 验证码）误伤面大，又本来就该被随手使用，不值得记录

/**
 * 记录一次返回给 agent 的秘密值，供 PreToolUse hook 做精确匹配（见上）。
 * 追加写入同一会话专属的文件（而不是像 writeSecretFile 那样整体覆盖），因为一个会话里
 * 可能多次调用 credential_get / credential_access_token 等。会话结束时随其他会话文件一起删除。
 */
export function recordSecrets(session: string, values: Iterable<string | undefined>): void {
  const vals = [...new Set([...values].filter((v): v is string => typeof v === "string" && v.trim().length >= MIN_REDACT_LENGTH))];
  if (!vals.length) return;
  const file = path.join(runDir(), `${session}.redact`.replace(/[^A-Za-z0-9_.@:-]/g, "_"));
  created.add(file);
  fs.appendFileSync(file, vals.map((v) => `${v}\n`).join(""));
  fs.chmodSync(file, 0o600);
}

/** 会话结束时删除本会话写过的环境变量文件 */
export function cleanupGatewayEnv(): void {
  for (const f of created) {
    try {
      fs.rmSync(f, { force: true });
    } catch {
      /* ignore */
    }
  }
  created.clear();
}

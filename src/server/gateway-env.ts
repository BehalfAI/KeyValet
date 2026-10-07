// 会话私有文件：写到仅用户可读的位置（~/.keyvalet/run，目录 0700、文件 0600），会话结束（MCP server 退出）时删除。
// - 网关环境变量文件：令牌写入文件，agent 用 `set -a; . <文件>; set +a; <命令>` 加载——
//   令牌不出现在命令行参数里（ps 对所有用户可见），也不出现在 agent 的上下文里。
// - 秘密文件（writeSecretFile）：某些程序必须从本地文件读取秘密本身（如 ssh -i 私钥），
//   没有网关那样“只转发、真值永不离开 root”的代理方式——写文件这一步就是秘密离开 root helper 的地方；
//   这里能做到的是不让内容经过 agent 的上下文，只把路径还给 agent。

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

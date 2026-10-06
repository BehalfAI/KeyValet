// 网关环境变量文件：令牌写入仅用户可读的文件（~/.keyvalet/run，目录 0700、文件 0600），
// agent 用 `set -a; . <文件>; set +a; <命令>` 加载——令牌不出现在命令行参数里（ps 对所有用户可见），
// 也不出现在 agent 的上下文里。会话结束（MCP server 退出）时删除。

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

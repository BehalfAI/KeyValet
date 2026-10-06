// 从文件导入秘密（私钥、服务账号 JSON 等），内容直接交给 root helper，不进入 AI 上下文。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MAX_FILE_BYTES = 64 * 1024;

/** 解析路径并检查（不读取内容）：必须是不超过 64KB 的普通文件 */
export function resolveSecretFile(p: string): string {
  const abs = path.resolve(p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p);
  let st: fs.Stats;
  try {
    st = fs.statSync(abs);
  } catch {
    throw new Error(`文件不存在：${abs}`);
  }
  if (!st.isFile()) throw new Error(`不是普通文件：${abs}`);
  if (st.size > MAX_FILE_BYTES) throw new Error(`文件过大（超过 64KB）：${abs}`);
  return abs;
}

export function readSecretFile(abs: string): string {
  const buf = fs.readFileSync(abs);
  if (buf.length > MAX_FILE_BYTES) throw new Error(`文件过大（超过 64KB）：${abs}`);
  return buf.toString("utf8");
}

// Import secrets from a file (private keys, service account JSON, etc.); the content goes straight to the root helper and never enters the AI's context.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { t } from "../shared/i18n.js";

const MAX_FILE_BYTES = 64 * 1024;

/** Resolve the path and check it (without reading the content): must be a regular file no larger than 64KB */
export function resolveSecretFile(p: string): string {
  const abs = path.resolve(p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p);
  let st: fs.Stats;
  try {
    st = fs.statSync(abs);
  } catch {
    throw new Error(t(`文件不存在：${abs}`, `File not found: ${abs}`));
  }
  if (!st.isFile()) throw new Error(t(`不是普通文件：${abs}`, `Not a regular file: ${abs}`));
  if (st.size > MAX_FILE_BYTES) throw new Error(t(`文件过大（超过 64KB）：${abs}`, `File too large (over 64KB): ${abs}`));
  return abs;
}

export function readSecretFile(abs: string): string {
  const buf = fs.readFileSync(abs);
  if (buf.length > MAX_FILE_BYTES) throw new Error(t(`文件过大（超过 64KB）：${abs}`, `File too large (over 64KB): ${abs}`));
  return buf.toString("utf8");
}

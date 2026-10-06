import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { t } from "../shared/i18n.js";
import { INSTALL_DIR } from "../shared/paths.js";

export function fatal(prefix: string, msg: string): never {
  process.stderr.write(`${prefix}: ${msg}\n`);
  process.exit(1);
}

/** 文件及其所有上级目录都必须 root 所有、不可被 group/other 写、且不是符号链接 */
export function untrustedReason(p: string): string | null {
  let cur = p;
  for (;;) {
    const st = fs.lstatSync(cur);
    if (st.isSymbolicLink()) return t(`${cur} 是符号链接`, `${cur} is a symbolic link`);
    if (st.uid !== 0) return t(`${cur} 不属于 root`, `${cur} is not owned by root`);
    if ((st.mode & 0o022) !== 0) return t(`${cur} 可被 group/other 写入`, `${cur} is writable by group/other`);
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

/**
 * 以 root 运行前的自检：必须是 root、必须从安装目录运行、
 * 所有会被加载的代码和 node 本身都不能被普通用户（包括 AI agent）篡改。
 */
export function verifyRootEnvironment(prefix: string, moduleUrl: string, expectedPath: string): void {
  if (process.getuid!() !== 0) fatal(prefix, t("必须以 root 运行（通过 sudo）", "must run as root (via sudo)"));
  const self = fileURLToPath(moduleUrl);
  if (self !== expectedPath) fatal(prefix, t(`必须从安装目录运行：${expectedPath}`, `must run from the install location: ${expectedPath}`));
  const distDir = path.join(INSTALL_DIR, "app", "dist");
  const files = [process.execPath, distDir, ...(fs.readdirSync(distDir, { recursive: true }) as string[]).map((f) => path.join(distDir, f))];
  for (const f of files) {
    const reason = untrustedReason(f);
    if (reason) fatal(prefix, t(`${reason}，拒绝以 root 运行`, `${reason}; refusing to run as root`));
  }
}

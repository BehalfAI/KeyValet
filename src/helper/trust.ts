import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { t } from "../shared/i18n.js";
import { INSTALL_DIR } from "../shared/paths.js";

export function fatal(prefix: string, msg: string): never {
  process.stderr.write(`${prefix}: ${msg}\n`);
  process.exit(1);
}

/** The file and every parent directory must be owned by root, not writable by group/other, and not a symbolic link */
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
 * Self-check before running as root: must be root, must run from the install directory,
 * and all code that will be loaded, along with node itself, must not be tamperable by a regular user (including an AI agent).
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

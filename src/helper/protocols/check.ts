// Field validation for protocol config. Input comes from the MCP server (indirectly from the agent), so it is always treated as untrusted.

import { VaultError } from "../vault.js";
import { t } from "../../shared/i18n.js";

export function str(v: unknown, what: string, max = 1000): string {
  if (typeof v !== "string" || v.length === 0 || v.length > max) throw new VaultError(t(`${what} 必须是 1~${max} 字符的字符串`, `${what} must be a string of 1-${max} characters`));
  return v;
}

export function optStr(v: unknown, what: string, max = 1000): string | undefined {
  return v === undefined || v === null || v === "" ? undefined : str(v, what, max);
}

export function int(v: unknown, what: string, min: number, max: number, dflt: number): number {
  if (v === undefined || v === null) return dflt;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw new VaultError(t(`${what} 必须是 ${min}~${max} 之间的整数`, `${what} must be an integer between ${min} and ${max}`));
  return v;
}

export function oneOf<T extends string>(v: unknown, what: string, allowed: readonly T[], dflt: T): T {
  if (v === undefined || v === null) return dflt;
  if (typeof v !== "string" || !allowed.includes(v as T)) throw new VaultError(t(`${what} 必须是 ${allowed.join(" / ")} 之一`, `${what} must be one of ${allowed.join(" / ")}`));
  return v as T;
}

export function strList(v: unknown, what: string, maxItems = 50): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > maxItems) throw new VaultError(t(`${what} 必须是最多 ${maxItems} 项的字符串数组`, `${what} must be an array of at most ${maxItems} strings`));
  return v.map((x, i) => {
    const s = str(x, `${what}[${i}]`, 500);
    if (/\s/.test(s)) throw new VaultError(t(`${what}[${i}] 不能包含空白字符`, `${what}[${i}] must not contain whitespace`));
    return s;
  });
}

export function strRecord(v: unknown, what: string, maxItems = 20): Record<string, string> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(t(`${what} 必须是对象`, `${what} must be an object`));
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > maxItems) throw new VaultError(t(`${what} 最多 ${maxItems} 项`, `${what} may have at most ${maxItems} entries`));
  const out: Record<string, string> = {};
  for (const [k, x] of entries) {
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(k)) throw new VaultError(t(`${what} 的键 "${k}" 非法`, `${what} has an invalid key "${k}"`));
    out[k] = str(x, `${what}.${k}`, 1000);
  }
  return out;
}

export function jsonRecord(v: unknown, what: string, maxBytes = 8192): Record<string, unknown> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(t(`${what} 必须是对象`, `${what} must be an object`));
  if (JSON.stringify(v).length > maxBytes) throw new VaultError(t(`${what} 过大`, `${what} is too large`));
  return structuredClone(v as Record<string, unknown>);
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

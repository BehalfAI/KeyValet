// 协议配置的字段校验。输入来自 MCP server（间接来自 agent），一律当作不可信。

import { VaultError } from "../vault.js";

export function str(v: unknown, what: string, max = 1000): string {
  if (typeof v !== "string" || v.length === 0 || v.length > max) throw new VaultError(`${what} 必须是 1~${max} 字符的字符串`);
  return v;
}

export function optStr(v: unknown, what: string, max = 1000): string | undefined {
  return v === undefined || v === null || v === "" ? undefined : str(v, what, max);
}

export function int(v: unknown, what: string, min: number, max: number, dflt: number): number {
  if (v === undefined || v === null) return dflt;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw new VaultError(`${what} 必须是 ${min}~${max} 之间的整数`);
  return v;
}

export function oneOf<T extends string>(v: unknown, what: string, allowed: readonly T[], dflt: T): T {
  if (v === undefined || v === null) return dflt;
  if (typeof v !== "string" || !allowed.includes(v as T)) throw new VaultError(`${what} 必须是 ${allowed.join(" / ")} 之一`);
  return v as T;
}

export function strList(v: unknown, what: string, maxItems = 50): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > maxItems) throw new VaultError(`${what} 必须是最多 ${maxItems} 项的字符串数组`);
  return v.map((x, i) => {
    const s = str(x, `${what}[${i}]`, 500);
    if (/\s/.test(s)) throw new VaultError(`${what}[${i}] 不能包含空白字符`);
    return s;
  });
}

export function strRecord(v: unknown, what: string, maxItems = 20): Record<string, string> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(`${what} 必须是对象`);
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > maxItems) throw new VaultError(`${what} 最多 ${maxItems} 项`);
  const out: Record<string, string> = {};
  for (const [k, x] of entries) {
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(k)) throw new VaultError(`${what} 的键 "${k}" 非法`);
    out[k] = str(x, `${what}.${k}`, 1000);
  }
  return out;
}

export function jsonRecord(v: unknown, what: string, maxBytes = 8192): Record<string, unknown> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(`${what} 必须是对象`);
  if (JSON.stringify(v).length > maxBytes) throw new VaultError(`${what} 过大`);
  return structuredClone(v as Record<string, unknown>);
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

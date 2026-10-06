// TOTP（RFC 6238）两步验证码。agent 只能拿到当前验证码，拿不到种子。

import crypto from "node:crypto";
import { Vault, VaultError } from "../vault.js";
import { int, oneOf, optStr, str } from "./check.js";

const ALGS = ["SHA1", "SHA256", "SHA512"] as const;
type TotpAlg = (typeof ALGS)[number];

interface TotpConfig {
  issuer?: string;
  account?: string;
  digits: number;
  period: number;
  algorithm: TotpAlg;
}

export function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new VaultError("TOTP 密钥不是合法的 Base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totpAt(key: Buffer, unixSeconds: number, digits: number, period: number, alg: TotpAlg): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / period)));
  const mac = crypto.createHmac(alg.toLowerCase(), key).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(bin).padStart(digits, "0");
}

/** secret 可以是 Base32 种子，也可以是二维码里的 otpauth://totp/... URI */
export function validateTotpSetup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  const raw = str(secrets.secret, "TOTP 密钥", 2000).trim();
  let seed = raw;
  const fromUri: Record<string, unknown> = {};
  if (raw.toLowerCase().startsWith("otpauth://")) {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw new VaultError("otpauth URI 格式错误");
    }
    if (u.host.toLowerCase() !== "totp") throw new VaultError("只支持 otpauth://totp（不支持 hotp）");
    seed = str(u.searchParams.get("secret") ?? "", "otpauth URI 中的 secret", 500);
    const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
    const [labelIssuer, labelAccount] = label.includes(":") ? label.split(":", 2) : [undefined, label];
    fromUri.issuer = u.searchParams.get("issuer") ?? labelIssuer;
    fromUri.account = labelAccount?.trim();
    if (u.searchParams.get("digits")) fromUri.digits = Number(u.searchParams.get("digits"));
    if (u.searchParams.get("period")) fromUri.period = Number(u.searchParams.get("period"));
    if (u.searchParams.get("algorithm")) fromUri.algorithm = u.searchParams.get("algorithm")!.toUpperCase();
  }
  const key = base32Decode(seed);
  if (key.length < 10) throw new VaultError("TOTP 密钥太短（至少 80 位）");
  const cfg: TotpConfig = {
    issuer: optStr(config.issuer ?? fromUri.issuer, "issuer", 200),
    account: optStr(config.account ?? fromUri.account, "account", 200),
    digits: int(config.digits ?? fromUri.digits, "digits", 6, 8, 6),
    period: int(config.period ?? fromUri.period, "period", 15, 300, 30),
    algorithm: oneOf(config.algorithm ?? fromUri.algorithm, "algorithm", ALGS, "SHA1"),
  };
  return { config: cfg as unknown as Record<string, unknown>, secrets: { secret: seed.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "") } };
}

export function totpCode(vault: Vault, p: { type: unknown; name: unknown }) {
  const { type: t, name: n, record } = vault.getRecord(p.type, p.name);
  if (record.kind !== "totp") throw new VaultError(`"${t}/${n}" 不是 TOTP 凭证`);
  const cfg = record.config as unknown as TotpConfig;
  const key = base32Decode(record.secrets!.secret!);
  const now = Date.now() / 1000;
  const remaining = cfg.period - (Math.floor(now) % cfg.period);
  return {
    code: totpAt(key, now, cfg.digits, cfg.period, cfg.algorithm),
    remaining_seconds: remaining,
    // 剩余时间很短时附上下一个码，方便调用方直接使用
    next_code: remaining <= 5 ? totpAt(key, now + cfg.period, cfg.digits, cfg.period, cfg.algorithm) : undefined,
    issuer: cfg.issuer ?? null,
    account: cfg.account ?? null,
  };
}

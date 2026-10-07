// TOTP (RFC 6238) two-factor codes. The agent can only get the current code, never the seed.

import crypto from "node:crypto";
import { t } from "../../shared/i18n.js";
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
    if (idx < 0) throw new VaultError(t("TOTP 密钥不是合法的 Base32", "TOTP secret is not valid Base32"));
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

/** secret can be either a Base32 seed or an otpauth://totp/... URI from a QR code */
export function validateTotpSetup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  const raw = str(secrets.secret, t("TOTP 密钥", "TOTP secret"), 2000).trim();
  let seed = raw;
  const fromUri: Record<string, unknown> = {};
  if (raw.toLowerCase().startsWith("otpauth://")) {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw new VaultError(t("otpauth URI 格式错误", "Malformed otpauth URI"));
    }
    if (u.host.toLowerCase() !== "totp") throw new VaultError(t("只支持 otpauth://totp（不支持 hotp）", "Only otpauth://totp is supported (hotp is not)"));
    seed = str(u.searchParams.get("secret") ?? "", t("otpauth URI 中的 secret", "secret in the otpauth URI"), 500);
    const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
    const [labelIssuer, labelAccount] = label.includes(":") ? label.split(":", 2) : [undefined, label];
    fromUri.issuer = u.searchParams.get("issuer") ?? labelIssuer;
    fromUri.account = labelAccount?.trim();
    if (u.searchParams.get("digits")) fromUri.digits = Number(u.searchParams.get("digits"));
    if (u.searchParams.get("period")) fromUri.period = Number(u.searchParams.get("period"));
    if (u.searchParams.get("algorithm")) fromUri.algorithm = u.searchParams.get("algorithm")!.toUpperCase();
  }
  const key = base32Decode(seed);
  if (key.length < 10) throw new VaultError(t("TOTP 密钥太短（至少 80 位）", "TOTP secret is too short (at least 80 bits)"));
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
  const { type: ty, name: n, record } = vault.getRecord(p.type, p.name);
  if (record.kind !== "totp") throw new VaultError(t(`"${ty}/${n}" 不是 TOTP 凭证`, `"${ty}/${n}" is not a TOTP credential`));
  const cfg = record.config as unknown as TotpConfig;
  const key = base32Decode(record.secrets!.secret!);
  const now = Date.now() / 1000;
  const remaining = cfg.period - (Math.floor(now) % cfg.period);
  return {
    code: totpAt(key, now, cfg.digits, cfg.period, cfg.algorithm),
    remaining_seconds: remaining,
    // Include the next code when very little time remains, so the caller can use it directly
    next_code: remaining <= 5 ? totpAt(key, now + cfg.period, cfg.digits, cfg.period, cfg.algorithm) : undefined,
    issuer: cfg.issuer ?? null,
    account: cfg.account ?? null,
  };
}

import crypto from "node:crypto";
import { VaultError } from "../vault.js";
import { t } from "../../shared/i18n.js";

export const JWT_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512"] as const;
export type JwtAlgorithm = (typeof JWT_ALGORITHMS)[number];

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");

/** 校验密钥能否用于该算法，返回规范化后的密钥（PEM 或 HMAC 秘密） */
export function checkJwtKey(alg: JwtAlgorithm, key: string): string {
  if (alg.startsWith("HS")) {
    if (key.length < 16) throw new VaultError(t("HMAC 密钥太短（至少 16 字符）", "HMAC key is too short (at least 16 characters)"));
    return key;
  }
  let k: crypto.KeyObject;
  try {
    k = crypto.createPrivateKey(key);
  } catch {
    throw new VaultError(t("无法解析私钥（需要 PEM 格式）", "Unable to parse private key (PEM format required)"));
  }
  const kt = k.asymmetricKeyType;
  const ok =
    (alg.startsWith("RS") || alg.startsWith("PS") ? kt === "rsa" || kt === "rsa-pss" : false) ||
    (alg === "ES256" && kt === "ec" && k.asymmetricKeyDetails?.namedCurve === "prime256v1") ||
    (alg === "ES384" && kt === "ec" && k.asymmetricKeyDetails?.namedCurve === "secp384r1") ||
    (alg === "EdDSA" && kt === "ed25519");
  if (!ok) throw new VaultError(t(`私钥类型（${kt}）与算法 ${alg} 不匹配`, `Private key type (${kt}) does not match algorithm ${alg}`));
  return key;
}

export function signJwt(alg: JwtAlgorithm, key: string, claims: Record<string, unknown>, extraHeader: Record<string, unknown> = {}): string {
  const header = { ...extraHeader, alg, typ: "JWT" };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const bits = alg.slice(2);
  let sig: Buffer;
  if (alg.startsWith("HS")) {
    sig = crypto.createHmac(`sha${bits}`, key).update(input).digest();
  } else if (alg === "EdDSA") {
    sig = crypto.sign(null, Buffer.from(input), key);
  } else if (alg.startsWith("ES")) {
    // JWS 要求 ECDSA 签名为 r||s 定长格式，而不是 DER
    sig = crypto.sign(`sha${bits}`, Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
  } else if (alg.startsWith("PS")) {
    sig = crypto.sign(`sha${bits}`, Buffer.from(input), {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
  } else {
    sig = crypto.sign(`sha${bits}`, Buffer.from(input), key);
  }
  return `${input}.${b64url(sig)}`;
}

/** 解出 JWT payload（不验签，只用于展示 token 端点直接返回的 id_token 里的账号信息） */
export function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const part = jwt.split(".")[1];
    return part ? (JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

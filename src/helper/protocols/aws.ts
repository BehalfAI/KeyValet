// AWS：用长期 access key 通过 STS 换取临时凭证（GetSessionToken 或 AssumeRole）。
// 长期 secret key 永不离开 root helper；agent 只拿到最长数小时有效的临时凭证。

import crypto from "node:crypto";
import { Vault, VaultError, type CredentialRecord } from "../vault.js";
import { int, optStr, str } from "./check.js";
import { httpRequest } from "./http.js";
import { totpCode } from "./totp.js";

interface AwsConfig {
  access_key_id: string;
  region: string;
  role_arn?: string;
  external_id?: string;
  role_session_name: string;
  duration_seconds: number;
  /** MFA 设备 ARN；配合 mfa_totp 引用的 TOTP 凭证自动生成验证码 */
  mfa_serial?: string;
  mfa_totp?: { type: string; name: string };
}

interface SessionCreds {
  access_key_id: string;
  secret_access_key: string;
  session_token: string;
  expiration: number;
}

let stsEndpointOverride: string | null = null;
/** 仅供测试：把 STS 请求发到本地模拟服务 */
export function setStsEndpointForTests(url: string | null): void {
  stsEndpointOverride = url;
}

const sha256 = (s: string | Buffer) => crypto.createHash("sha256").update(s).digest("hex");
const hmac = (k: Buffer | string, s: string) => crypto.createHmac("sha256", k).update(s).digest();

/** AWS Signature Version 4，返回 Authorization 头 */
export function sigv4(p: {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  amzDate: string;
}): string {
  const names = Object.keys(p.headers).map((h) => h.toLowerCase()).sort();
  const lower = Object.fromEntries(Object.entries(p.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const canonicalHeaders = names.map((h) => `${h}:${lower[h]!.trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalRequest = [p.method, p.path, p.query, canonicalHeaders, signedHeaders, sha256(p.body)].join("\n");
  const date = p.amzDate.slice(0, 8);
  const scope = `${date}/${p.region}/${p.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", p.amzDate, scope, sha256(canonicalRequest)].join("\n");
  const kSigning = hmac(hmac(hmac(hmac(`AWS4${p.secretAccessKey}`, date), p.region), p.service), "aws4_request");
  const signature = crypto.createHmac("sha256", kSigning).update(stringToSign).digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${p.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

export function validateAwsSetup(config: Record<string, unknown>, secrets: Record<string, unknown>) {
  const akid = str(config.access_key_id, "access_key_id", 128);
  if (!/^AKIA[A-Z0-9]{12,124}$/.test(akid)) throw new VaultError("access_key_id 应为长期密钥（AKIA 开头）");
  const secret = str(secrets.secret_access_key, "secret_access_key", 256);
  if (!/^[A-Za-z0-9/+=]{20,256}$/.test(secret)) throw new VaultError("secret_access_key 格式不对");
  const region = str(config.region ?? "us-east-1", "region", 50);
  if (!/^[a-z]{2}(-gov)?-[a-z]+-\d$/.test(region)) throw new VaultError(`非法或不支持的 region：${region}`);
  const roleArn = optStr(config.role_arn, "role_arn", 2048);
  if (roleArn && !/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(roleArn)) throw new VaultError("role_arn 格式不对");
  const mfaSerial = optStr(config.mfa_serial, "mfa_serial", 256);
  if (mfaSerial && !/^(arn:aws[a-z-]*:iam::\d{12}:mfa\/[\w+=,.@/-]+|GAHT[A-Z0-9]+)$/.test(mfaSerial)) throw new VaultError("mfa_serial 格式不对");
  let mfaTotp: AwsConfig["mfa_totp"];
  if (config.mfa_totp) {
    const m = config.mfa_totp as Record<string, unknown>;
    mfaTotp = { type: str(m.type, "mfa_totp.type", 64), name: str(m.name, "mfa_totp.name", 128) };
    if (!mfaSerial) throw new VaultError("设置 mfa_totp 时必须同时设置 mfa_serial");
  }
  const sessionName = str(config.role_session_name ?? "keyvalet", "role_session_name", 64);
  if (!/^[\w+=,.@-]{2,64}$/.test(sessionName)) throw new VaultError("role_session_name 格式不对");
  const cfg: AwsConfig = {
    access_key_id: akid,
    region,
    role_arn: roleArn,
    external_id: optStr(config.external_id, "external_id", 1224),
    role_session_name: sessionName,
    duration_seconds: int(config.duration_seconds, "duration_seconds", 900, roleArn ? 43_200 : 129_600, 3600),
    mfa_serial: mfaSerial,
    mfa_totp: mfaTotp,
  };
  return { config: cfg as unknown as Record<string, unknown>, secrets: { secret_access_key: secret } };
}

function xmlTag(xml: string, tag: string): string | undefined {
  return new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(xml)?.[1];
}

export async function awsCredentials(vault: Vault, p: { type: unknown; name: unknown; duration_seconds?: unknown; force?: unknown }) {
  const { type: t, name: n, record } = vault.getRecord(p.type, p.name);
  if (record.kind !== "aws") throw new VaultError(`"${t}/${n}" 不是 AWS 凭证`);
  const cfg = record.config as unknown as AwsConfig;
  const duration = int(p.duration_seconds, "duration_seconds", 900, cfg.role_arn ? 43_200 : 129_600, cfg.duration_seconds);

  const cached = (record.state ?? {}).session as SessionCreds | undefined;
  if (cached && p.force !== true && p.duration_seconds == null && cached.expiration - 5 * 60_000 > Date.now()) return out(cached, cfg);

  const form: Record<string, string> = { Version: "2011-06-15", DurationSeconds: String(duration) };
  if (cfg.role_arn) {
    form.Action = "AssumeRole";
    form.RoleArn = cfg.role_arn;
    form.RoleSessionName = cfg.role_session_name;
    if (cfg.external_id) form.ExternalId = cfg.external_id;
  } else {
    form.Action = "GetSessionToken";
  }
  if (cfg.mfa_serial) {
    if (!cfg.mfa_totp) throw new VaultError("配置了 mfa_serial 但没有关联 TOTP 凭证（mfa_totp）");
    form.SerialNumber = cfg.mfa_serial;
    let mfa = totpCode(vault, cfg.mfa_totp);
    // AWS 拒绝重复使用同一个验证码：与上次相同则等到下一个周期
    if (mfa.code === (record.state ?? {}).last_mfa_code) {
      await new Promise((r) => setTimeout(r, (mfa.remaining_seconds + 1) * 1000));
      mfa = totpCode(vault, cfg.mfa_totp);
    }
    form.TokenCode = mfa.code;
  }

  const host = `sts.${cfg.region}.amazonaws.com${cfg.region.startsWith("cn-") ? ".cn" : ""}`;
  const body = new URLSearchParams(form).toString();
  const amzDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded; charset=utf-8",
    host,
    "x-amz-date": amzDate,
  };
  const authorization = sigv4({
    method: "POST",
    path: "/",
    query: "",
    headers,
    body,
    region: cfg.region,
    service: "sts",
    accessKeyId: cfg.access_key_id,
    secretAccessKey: record.secrets!.secret_access_key!,
    amzDate,
  });
  const { host: _h, ...sendHeaders } = headers; // host 头由 fetch 自动设置
  const r = await httpRequest(stsEndpointOverride ?? `https://${host}/`, {
    method: "POST",
    headers: { ...sendHeaders, Authorization: authorization, Accept: "application/xml" },
    body,
  });
  if (r.status >= 300) {
    throw new VaultError(`AWS STS 返回错误（HTTP ${r.status}）：${xmlTag(r.text, "Code") ?? ""} ${xmlTag(r.text, "Message") ?? r.text.slice(0, 200)}`);
  }
  const creds: SessionCreds = {
    access_key_id: xmlTag(r.text, "AccessKeyId") ?? "",
    secret_access_key: xmlTag(r.text, "SecretAccessKey") ?? "",
    session_token: xmlTag(r.text, "SessionToken") ?? "",
    expiration: Date.parse(xmlTag(r.text, "Expiration") ?? ""),
  };
  if (!creds.access_key_id || !creds.secret_access_key || !creds.session_token || !creds.expiration) {
    throw new VaultError("AWS STS 响应缺少凭证字段");
  }
  vault.patchRecord(t, n, "aws", record.generation, (rec: CredentialRecord) => {
    rec.state = {
      ...rec.state,
      ...(p.duration_seconds == null ? { session: creds } : {}),
      ...(form.TokenCode ? { last_mfa_code: form.TokenCode } : {}),
    };
  });
  return out(creds, cfg);
}

function out(c: SessionCreds, cfg: AwsConfig) {
  return {
    access_key_id: c.access_key_id,
    secret_access_key: c.secret_access_key,
    session_token: c.session_token,
    expiration: new Date(c.expiration).toISOString(),
    region: cfg.region,
    role_arn: cfg.role_arn ?? null,
  };
}

// 终端管理工具，供用户本人使用：keyvalet <command>
// 由 /usr/local/bin/keyvalet 通过 `sudo -k` 启动，直接以 root 读写凭证库。

import fs from "node:fs";
import { CLI_JS, VAULT_DIR } from "../shared/paths.js";
import { fatal as fatalWith, verifyRootEnvironment } from "../helper/trust.js";
import { readSettings, writeSettings } from "../helper/settings.js";
import { MAX_VALUE_LENGTH, Vault } from "../helper/vault.js";

function fatal(msg: string): never {
  return fatalWith("keyvalet", msg);
}

const USAGE = `用法：keyvalet <命令>

  types                              列出凭证类型
  list [type]                        列出凭证（不含值）
  get <type> <name>                  输出凭证值（协议凭证输出完整配置和秘密）
  set <type> <name> [选项]           保存凭证（值从隐藏输入或管道读取；类型不存在会先创建）
      --desc <text>                  凭证说明
      --type-desc <text>             新建类型时的类型说明
      --attr key=value               非敏感属性，可重复
      --overwrite                    覆盖已有凭证
  delete <type> <name>               删除凭证
  delete-type <type>                 删除空的凭证类型
  audit [行数]                       查看审计日志（默认 50 行）
  grant-mode [per-credential|all]    查看/设置授权范围：每个凭证单独授权，或每个会话一次授权全部`;

function readHidden(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let value = "";
    const done = (err?: Error) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      process.stderr.write("\n");
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done();
        if (ch === "\u0003") return done(new Error("已取消"));
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function readValue(label: string): Promise<string> {
  if (process.stdin.isTTY) {
    const a = await readHidden(`输入 ${label} 的值（不回显）：`);
    const b = await readHidden("再输入一次确认：");
    if (a !== b) fatal("两次输入不一致");
    return a;
  }
  // 管道输入：如 `pbpaste | keyvalet set api_key openai`
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

function parseOptions(args: string[]) {
  const opts: { desc?: string; typeDesc?: string; attrs: Record<string, string>; overwrite: boolean; rest: string[] } = {
    attrs: {},
    overwrite: false,
    rest: [],
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const next = () => args[++i] ?? fatal(`${a} 缺少参数`);
    if (a === "--desc") opts.desc = next();
    else if (a === "--type-desc") opts.typeDesc = next();
    else if (a === "--overwrite") opts.overwrite = true;
    else if (a === "--attr") {
      const kv = next();
      const eq = kv.indexOf("=");
      if (eq <= 0) fatal(`--attr 格式应为 key=value：${kv}`);
      opts.attrs[kv.slice(0, eq)] = kv.slice(eq + 1);
    } else opts.rest.push(a);
  }
  return opts;
}

async function main(): Promise<void> {
  process.umask(0o077);
  verifyRootEnvironment("keyvalet", import.meta.url, CLI_JS);
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log(USAGE);
    return;
  }

  const vault = new Vault(VAULT_DIR);
  vault.init();
  const client = { client: "keyvalet-cli", user: process.env.SUDO_USER };
  const audited = <T>(op: string, target: Record<string, unknown>, fn: () => T): T => {
    try {
      const r = fn();
      vault.audit({ op, ...target, ok: true, client });
      return r;
    } catch (e) {
      vault.audit({ op, ...target, ok: false, error: (e as Error).message, client });
      throw e;
    }
  };

  switch (cmd) {
    case "types": {
      const types = audited("listTypes", {}, () => vault.listTypes());
      if (!types.length) console.log("（暂无凭证类型）");
      for (const t of types) console.log(`${t.name}\t${t.count} 个\t${t.description}`);
      break;
    }
    case "list": {
      const items = audited("list", { type: args[0] }, () => vault.list(args[0]));
      if (!items.length) console.log("（暂无凭证）");
      for (const c of items) {
        const attrs = Object.entries(c.attributes).map(([k, v]) => `${k}=${v}`).join(" ");
        const kind = c.kind === "static" ? "" : ` [${c.kind}]`;
        console.log(`${c.type}/${c.name}${kind}\t${c.description}${attrs ? `\t${attrs}` : ""}`);
      }
      break;
    }
    case "get": {
      const [type, name] = args;
      if (!type || !name) fatal("用法：get <type> <name>");
      const { record } = audited("get", { type, name }, () => vault.getRecord(type, name));
      if ((record.kind ?? "static") === "static") {
        process.stdout.write(record.value + (process.stdout.isTTY ? "\n" : ""));
      } else {
        // 协议凭证：输出完整配置和秘密（仅限终端中以 root 身份执行，供备份/迁移）
        console.log(JSON.stringify({ kind: record.kind, config: record.config, secrets: record.secrets }, null, 2));
      }
      break;
    }
    case "set": {
      const opts = parseOptions(args);
      const [type, name] = opts.rest;
      if (!type || !name) fatal("用法：set <type> <name> [选项]");
      if (!opts.overwrite && vault.exists(type, name)) fatal(`凭证 ${type}/${name} 已存在，如需替换请加 --overwrite`);
      const value = await readValue(`${type}/${name}`);
      if (!value) fatal("值不能为空");
      if (value.length > MAX_VALUE_LENGTH) fatal("值过长");
      const r = audited("set", { type, name }, () =>
        vault.set({ type, name, value, description: opts.desc, attributes: opts.attrs, typeDescription: opts.typeDesc, overwrite: opts.overwrite }),
      );
      if (r.typeCreated) console.log(`凭证类型 "${r.type}" 不存在，已先创建`);
      console.log(r.replaced ? `已覆盖 ${r.type}/${r.name}` : `已保存 ${r.type}/${r.name}`);
      break;
    }
    case "delete": {
      const [type, name] = args;
      if (!type || !name) fatal("用法：delete <type> <name>");
      const r = audited("delete", { type, name }, () => vault.delete(type, name));
      console.log(`已删除 ${r.type}/${r.name}`);
      break;
    }
    case "delete-type": {
      const [type] = args;
      if (!type) fatal("用法：delete-type <type>");
      const r = audited("deleteType", { type }, () => vault.deleteType(type));
      console.log(`已删除凭证类型 ${r.name}`);
      break;
    }
    case "grant-mode": {
      const [m] = args;
      if (!m) {
        console.log(readSettings(VAULT_DIR).grant_mode);
        break;
      }
      const mode = m.replace("-", "_");
      if (mode !== "per_credential" && mode !== "all") fatal("用法：grant-mode [per-credential|all]");
      writeSettings(VAULT_DIR, { ...readSettings(VAULT_DIR), grant_mode: mode });
      vault.audit({ op: "settings", grant_mode: mode, ok: true, client });
      console.log(`授权范围已设为 ${mode}（对新的会话生效）`);
      break;
    }
    case "audit": {
      const n = Number(args[0] ?? 50);
      const lines = fs.existsSync(vault.auditPath) ? fs.readFileSync(vault.auditPath, "utf8").trimEnd().split("\n") : [];
      console.log(lines.slice(-n).join("\n"));
      break;
    }
    default:
      fatal(`未知命令 ${cmd}\n\n${USAGE}`);
  }
}

main().catch((e: Error) => fatal(e.message));

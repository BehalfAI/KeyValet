// Session-private files: written to a location only the user can read (~/.keyvalet/run, directory 0700, files 0600), deleted when the session (MCP server) exits.
// - Gateway environment variable file: the token is written to a file, and the agent loads it with
//   `set -a; . <file>; set +a; <command>` — the token never appears in command-line arguments (ps is visible to all users),
//   nor does it appear in the agent's context.
// - Secret file (writeSecretFile): some programs must read the secret itself from a local file (e.g. an ssh -i private key).
//   There's no proxy-style approach here like the gateway's "only forward, the real value never leaves root" —
//   writing the file is the point where the secret leaves the root helper; the best we can do here is keep the
//   content out of the agent's context and hand back only the path.
// - Record of returned values (recordSecrets): tools like credential_get / credential_totp_code / credential_access_token /
//   credential_aws_credentials are, by design, meant to hand the raw secret to the agent (there's no choice when no
//   proxy channel is available). We log each value handed out to <session>.redact, so Claude Code's PreToolUse hook can
//   intercept it before the agent actually splices it into a shell command or writes it to a file — regardless of
//   whether the value looks like an "API key," anything KeyValet itself handed out is worth flagging if it shows up
//   in a command line or file.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const created = new Set<string>();

function runDir(): string {
  const dir = path.join(os.homedir(), ".keyvalet", "run");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(dir), 0o700);
  fs.chmodSync(dir, 0o700);
  return dir;
}

const quote = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`;

export function writeGatewayEnv(session: string, type: string, name: string, env: Record<string, string>): string {
  const file = path.join(runDir(), `${session}-${type}-${name}.env`.replace(/[^A-Za-z0-9_.@:-]/g, "_"));
  const body = Object.entries(env)
    .map(([k, v]) => `export ${k}=${quote(v)}`)
    .join("\n");
  fs.rmSync(file, { force: true });
  fs.writeFileSync(file, `${body}\n`, { mode: 0o600, flag: "wx" });
  created.add(file);
  return file;
}

/**
 * Write a secret's raw content to a file only the user can read (same directory, also 0600), for programs
 * that need a local file (e.g. ssh -i, certificates). The content itself is never returned to the agent, only
 * the path is. Deleted along with the gateway environment variable files when the session ends.
 */
export function writeSecretFile(session: string, type: string, name: string, field: string | undefined, content: string): string {
  const file = path.join(runDir(), `${session}-${type}-${name}${field ? `-${field}` : ""}.key`.replace(/[^A-Za-z0-9_.@:-]/g, "_"));
  fs.rmSync(file, { force: true });
  fs.writeFileSync(file, content, { mode: 0o600, flag: "wx" });
  created.add(file);
  return file;
}

const MIN_REDACT_LENGTH = 12; // Values this short (e.g. a 6-digit TOTP code) cause too many false positives and are meant to be used freely anyway, so they're not worth recording

/**
 * Record one secret value returned to the agent, for the PreToolUse hook to match exactly (see above).
 * Appends to a file dedicated to this session (rather than overwriting it wholesale like writeSecretFile),
 * since a single session may call credential_get / credential_access_token etc. multiple times. Deleted
 * along with the other session files when the session ends.
 */
export function recordSecrets(session: string, values: Iterable<string | undefined>): void {
  const vals = [...new Set([...values].filter((v): v is string => typeof v === "string" && v.trim().length >= MIN_REDACT_LENGTH))];
  if (!vals.length) return;
  const file = path.join(runDir(), `${session}.redact`.replace(/[^A-Za-z0-9_.@:-]/g, "_"));
  created.add(file);
  fs.appendFileSync(file, vals.map((v) => `${v}\n`).join(""));
  fs.chmodSync(file, 0o600);
}

/** Delete the environment variable files this session wrote, when the session ends */
export function cleanupGatewayEnv(): void {
  for (const f of created) {
    try {
      fs.rmSync(f, { force: true });
    } catch {
      /* ignore */
    }
  }
  created.clear();
}

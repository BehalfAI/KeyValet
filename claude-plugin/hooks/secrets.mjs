#!/usr/bin/env node
// KeyValet hook for Claude Code: notices secrets so they end up in KeyValet instead of the chat, files or shell.
//
//   secrets.mjs prompt   UserPromptSubmit: the user pasted a key → tell Claude to store it in KeyValet
//   secrets.mjs tool     PreToolUse (Write/Edit/MultiEdit/NotebookEdit/Bash): a literal key is about to be
//                        written to a file or a command → ask the user first and point Claude to KeyValet
//
// The "tool" mode also catches secrets Claude already pulled OUT of KeyValet this session
// (credential_get / credential_totp_code / credential_access_token / credential_aws_credentials record
// what they returned in ~/.keyvalet/run/*.redact) by exact match — this does not rely on the value
// looking like a known key format, unlike the PATTERNS below.
//
// Never prints the secret itself (only a masked preview). Set KEYVALET_HOOKS=off to disable.
// No dependencies: runs with whatever node is available.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Known key formats → KeyValet template. Order matters: more specific prefixes first. */
export const PATTERNS = [
  { id: "anthropic", label: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_-]{32,}/g },
  { id: "openrouter", label: "OpenRouter API key", re: /sk-or-v1-[A-Za-z0-9]{40,}/g },
  { id: "openai", label: "OpenAI API key", re: /sk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_-]{20,}/g },
  { id: "openai", label: "OpenAI-style API key (OpenAI, DeepSeek, …)", re: /\bsk-[A-Za-z0-9]{32,}/g, ambiguous: true },
  { id: "github", label: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g },
  { id: "gitlab", label: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { id: "slack", label: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{20,}/g },
  { id: "stripe", label: "Stripe secret key", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}/g },
  { id: "google_gemini", label: "Google API key (Gemini or another Google API)", re: /\bAIza[0-9A-Za-z_-]{35}/g, ambiguous: true },
  { id: "groq", label: "Groq API key", re: /\bgsk_[A-Za-z0-9]{40,}/g },
  { id: "xai", label: "xAI API key", re: /\bxai-[A-Za-z0-9]{40,}/g },
  { id: "huggingface", label: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}/g },
  { id: "replicate", label: "Replicate token", re: /\br8_[A-Za-z0-9]{30,}/g },
  { id: "perplexity", label: "Perplexity API key", re: /\bpplx-[A-Za-z0-9]{40,}/g },
  { id: "tavily", label: "Tavily API key", re: /\btvly-[A-Za-z0-9-]{20,}/g },
  { id: "firecrawl", label: "Firecrawl API key", re: /\bfc-[a-f0-9]{32}\b/g },
  { id: "pinecone", label: "Pinecone API key", re: /\bpcsk_[A-Za-z0-9_]{40,}/g },
  { id: "npm", label: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "sendgrid", label: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
  { id: "resend", label: "Resend API key", re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g },
  { id: "notion", label: "Notion token", re: /\b(?:ntn_|secret_)[A-Za-z0-9]{40,}/g },
  { id: "linear", label: "Linear API key", re: /\blin_api_[A-Za-z0-9]{40,}/g },
  { id: "digitalocean", label: "DigitalOcean token", re: /\bdo[opr]_v1_[a-f0-9]{64}/g },
  { id: "sentry", label: "Sentry token", re: /\bsntr[yu]s?_[A-Za-z0-9+/=_]{40,}/g },
  { id: "aws", label: "AWS access key ID", re: /\bAKIA[0-9A-Z]{16}\b/g, tool: "credential_setup_aws" },
  { id: "private_key", label: "private key (PEM)", re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g, tool: "credential_set (value_file if it is in a file)", noEntropy: true },
  { id: "bearer", label: "JWT / bearer token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
];

/** "api_key = …", "password: …" in prose, including their Chinese equivalents (prompts only — too noisy for code). */
const GENERIC =
  /(?:api[_ -]?key|secret|token|password|passwd|pwd|密钥|密码|口令|令牌)["'\s]*(?:[:=：]|is|是|为)\s*["'`]?([^\s"'`,，;；]{12,})/gi;

/** Fake / placeholder values (sk-xxxxxxxx, your-api-key-here, ${OPENAI_API_KEY}) don't count. */
function looksRandom(s) {
  if (/(x{6,}|\*{3,}|\.{3}|…|your|example|placeholder|dummy|redacted|\$\{|<.*>|process\.env|os\.environ)/i.test(s)) return false;
  if (!/[0-9]/.test(s) || !/[A-Za-z]/.test(s)) return false;
  return new Set(s).size >= 10;
}

export function mask(s) {
  return s.length <= 12 ? `${s.slice(0, 3)}…` : `${s.slice(0, 6)}…${s.slice(-4)}`;
}

/** Find secrets in text. Each hit: { id, label, preview, tool?, ambiguous? }. */
export function detect(text, { generic = false } = {}) {
  if (typeof text !== "string" || text.length < 16) return [];
  const hits = [];
  const seen = new Set();
  let rest = text;
  for (const p of PATTERNS) {
    for (const m of rest.matchAll(p.re)) {
      const v = m[0];
      if (!p.noEntropy && !looksRandom(v)) continue;
      if (seen.has(v)) continue;
      seen.add(v);
      hits.push({ id: p.id, label: p.label, preview: p.noEntropy ? v : mask(v), ...(p.tool ? { tool: p.tool } : {}), ...(p.ambiguous ? { ambiguous: true } : {}) });
    }
    rest = rest.replace(p.re, " "); // a specific match must not be re-reported by a broader pattern
  }
  if (generic) {
    for (const m of rest.matchAll(GENERIC)) {
      const v = m[1];
      if (!looksRandom(v) || seen.has(v)) continue;
      seen.add(v);
      hits.push({ id: null, label: "secret (password / token)", preview: mask(v) });
    }
  }
  return hits;
}

function describe(hits) {
  return hits
    .map((h) => {
      const how = h.tool ? `store with ${h.tool}` : h.id ? `template \`${h.id}\`${h.ambiguous ? " (confirm the service with the user if unclear)" : ""}` : "no known template — ask the user which service it is for, then search credential_templates";
      return `- ${h.label} (${h.preview}) → ${how}`;
    })
    .join("\n");
}

export function promptContext(hits) {
  return [
    "KeyValet: the user's message contains what looks like a secret:",
    describe(hits),
    "",
    "Unless the user said not to store it, proactively save it in KeyValet now, before doing anything else with it:",
    "1. credential_list — if a credential for the same service already exists, ask the user whether to replace it (overwrite: true) or save under a new name.",
    "2. credential_set with the template, a short name (e.g. \"default\", or the project/account it belongs to), value = the exact secret from the message, and a purpose. " +
      "For an AWS key pair use credential_setup_aws (access_key_id + secret_access_key). If the template needs several secret fields, omit value and let the user fill them in the dialog.",
    "3. From then on use it through credential_http_request or credential_gateway. Do not write it to .env or other files, shell commands, code, memory or notes, and do not repeat it in your reply.",
    "Tell the user in one line that it is stored in KeyValet. Mention once that /keyvalet:add lets them enter keys in a private dialog so they never pass through the chat.",
  ].join("\n");
}

export function toolText(toolName, input) {
  if (!input || typeof input !== "object") return "";
  switch (toolName) {
    case "Write":
      return String(input.content ?? "");
    case "Edit":
      return String(input.new_string ?? "");
    case "MultiEdit":
      return (Array.isArray(input.edits) ? input.edits : []).map((e) => String(e?.new_string ?? "")).join("\n");
    case "NotebookEdit":
      return String(input.new_source ?? "");
    case "Bash":
      return String(input.command ?? "");
    default:
      return "";
  }
}

/**
 * Secrets that a KeyValet tool already returned to Claude in a still-live session, read from
 * ~/.keyvalet/run/*.redact (one file per session, written by recordSecrets in src/server/gateway-env.ts,
 * deleted when that session ends). Ignores files older than a day so a crashed session that skipped
 * cleanup doesn't keep flagging long-dead values forever.
 */
function loadReturnedSecrets() {
  const dir = path.join(os.homedir(), ".keyvalet", "run");
  const out = new Set();
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let names;
  try {
    names = fs.readdirSync(dir).filter((f) => f.endsWith(".redact"));
  } catch {
    return out;
  }
  for (const name of names) {
    const p = path.join(dir, name);
    try {
      if (fs.statSync(p).mtimeMs < cutoff) continue;
      for (const line of fs.readFileSync(p, "utf8").split("\n")) {
        const v = line.trim();
        if (v) out.add(v);
      }
    } catch {
      /* ignore */
    }
  }
  return out;
}

/** Exact-match hits (unlike detect(), not a format guess — these are values KeyValet itself handed out). */
export function detectReturnedSecrets(text) {
  if (typeof text !== "string" || !text) return [];
  const hits = [];
  for (const v of loadReturnedSecrets()) {
    if (text.includes(v)) hits.push({ preview: mask(v) });
  }
  return hits;
}

export function toolReason(toolName, hits, returnedHits = []) {
  const where = toolName === "Bash" ? "this shell command" : "this file";
  const parts = [];
  if (hits.length) {
    parts.push(
      `${where} contains a literal secret — ${hits.map((h) => `${h.label} (${h.preview})`).join(", ")}. ` +
        "Keep secrets in KeyValet: call APIs with credential_http_request, run SDKs/scripts with credential_gateway (env file with a local base URL and a gateway token), " +
        "and read env vars in code instead of hard-coding keys.",
    );
  }
  if (returnedHits.length) {
    parts.push(
      `${where} contains a value KeyValet already returned this session (${returnedHits.map((h) => h.preview).join(", ")}). ` +
        "A secret KeyValet handed you should not go into a shell command or env-var prefix (ps shows it to every local user) or into a plain file — " +
        "use credential_export_file instead and have the program read it from the private file it returns.",
    );
  }
  return parts.join(" ") + " Approve only if you really want this.";
}

/** Hook entry: returns the JSON to print, or null for no output. */
export function handle(mode, input) {
  if (mode === "prompt") {
    const hits = detect(String(input?.prompt ?? ""), { generic: true });
    if (!hits.length) return null;
    return { hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: promptContext(hits) } };
  }
  if (mode === "tool") {
    const name = String(input?.tool_name ?? "");
    const text = toolText(name, input?.tool_input);
    const hits = detect(text);
    const returnedHits = detectReturnedSecrets(text);
    if (!hits.length && !returnedHits.length) return null;
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: toolReason(name, hits, returnedHits),
        additionalContext:
          "KeyValet flagged a secret in this tool call. " +
          (hits.length ? "If the user hasn't stored it yet, store it with credential_set (template + value), then use credential_http_request / credential_gateway or read it from env vars instead of hard-coding it. " : "") +
          (returnedHits.length ? "A value returned by a KeyValet tool this session is present verbatim — use credential_export_file so the program reads it from a private file instead." : ""),
      },
    };
  }
  return null;
}

async function main() {
  if (/^(off|0|false|no)$/i.test(process.env.KEYVALET_HOOKS ?? "")) return;
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    return;
  }
  const out = handle(process.argv[2], input);
  if (out) process.stdout.write(JSON.stringify(out));
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {}); // a hook must never break the session
}

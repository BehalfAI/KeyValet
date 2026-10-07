// Bilingual UI text (English / Simplified Chinese).
//
// Usage: t("Chinese copy", "English text") — both variants live side by side at the call site.
// Language resolution (first match wins):
//   1. setLang() — the root helper receives the language from the MCP server in the handshake;
//      the CLI receives it via --lang from its wrapper script
//   2. KEYVALET_LANG=en|zh
//   3. macOS UI language (AppleLanguages)
//   4. LC_ALL / LC_MESSAGES / LANG
//   5. English

import { execFileSync } from "node:child_process";

export type Lang = "en" | "zh";

let current: Lang | null = null;

function fromString(v: string | undefined): Lang | null {
  if (!v) return null;
  const s = v.trim().toLowerCase();
  if (s.startsWith("zh")) return "zh";
  if (s.startsWith("en")) return "en";
  return null;
}

function macLanguage(): Lang | null {
  if (process.platform !== "darwin" || process.getuid?.() === 0) return null; // running as root would read root's own preference, not the user's
  try {
    const out = execFileSync("/usr/bin/defaults", ["read", "-g", "AppleLanguages"], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] });
    const first = /"?([A-Za-z]{2}[-_A-Za-z]*)"?/.exec(out.replace(/[()\s,]/g, " "));
    return first ? (fromString(first[1]) ?? "en") : null;
  } catch {
    return null;
  }
}

export function detectLang(): Lang {
  return (
    fromString(process.env.KEYVALET_LANG) ??
    macLanguage() ??
    fromString(process.env.LC_ALL) ??
    fromString(process.env.LC_MESSAGES) ??
    fromString(process.env.LANG) ??
    "en"
  );
}

export function lang(): Lang {
  if (!current) current = detectLang();
  return current;
}

export function setLang(l: unknown): void {
  const v = fromString(typeof l === "string" ? l : undefined);
  if (v) current = v;
}

/** Pick the text for the current language. */
export function t(zh: string, en: string): string {
  return lang() === "zh" ? zh : en;
}

#!/usr/bin/env node
// Generates KeyValet's bundled template catalog templates/catalog.json (Apache-2.0, distributed with the project).
// Compiled from each service's official API docs: auth method (injection rule), verification endpoint, API host.
// To change templates, edit this file and run: npm run templates:build

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const key = (label = "API Key") => ({ name: "apiKey", label, secret: true, required: true });
const tok = (label = "Token") => ({ name: "token", label, secret: true, required: true });
const url = (def, label = "API Base URL") => ({ name: "apiUrl", label, secret: false, required: true, default: def });
const bearer = (field = "apiKey") => ({ headers: { Authorization: `Bearer {{${field}}}` } });
const get = (u, extra = {}) => ({ method: "GET", url: u, ...extra });

/** @type {Array<Record<string, unknown>>} */
const T = [
  // ---------- AI / LLMs ----------
  { id: "openai", name: "OpenAI", fields: [key()], inject: bearer(), test: get("https://api.openai.com/v1/models") },
  {
    id: "anthropic",
    name: "Anthropic (Claude)",
    fields: [key()],
    inject: { headers: { "x-api-key": "{{apiKey}}", "anthropic-version": "2023-06-01" } },
    test: get("https://api.anthropic.com/v1/models"),
  },
  {
    id: "google_gemini",
    name: "Google Gemini API (AI Studio)",
    fields: [key()],
    inject: { headers: { "x-goog-api-key": "{{apiKey}}" } },
    test: get("https://generativelanguage.googleapis.com/v1beta/models"),
  },
  { id: "mistral", name: "Mistral AI", fields: [key()], inject: bearer(), test: get("https://api.mistral.ai/v1/models") },
  { id: "groq", name: "Groq", fields: [key()], inject: bearer(), test: get("https://api.groq.com/openai/v1/models") },
  { id: "deepseek", name: "DeepSeek", fields: [key()], inject: bearer(), test: get("https://api.deepseek.com/models") },
  { id: "xai", name: "xAI (Grok)", fields: [key()], inject: bearer(), test: get("https://api.x.ai/v1/models") },
  { id: "openrouter", name: "OpenRouter", fields: [key()], inject: bearer(), test: get("https://openrouter.ai/api/v1/key") },
  { id: "together", name: "Together AI", fields: [key()], inject: bearer(), test: get("https://api.together.xyz/v1/models") },
  { id: "cohere", name: "Cohere", fields: [key()], inject: bearer(), test: get("https://api.cohere.com/v1/models") },
  { id: "perplexity", name: "Perplexity", fields: [key()], inject: bearer(), hosts: ["api.perplexity.ai"] },
  { id: "huggingface", name: "Hugging Face", fields: [tok("Access Token")], inject: bearer("token"), test: get("https://huggingface.co/api/whoami-v2") },
  { id: "replicate", name: "Replicate", fields: [tok("API Token")], inject: bearer("token"), test: get("https://api.replicate.com/v1/account") },
  {
    id: "elevenlabs",
    name: "ElevenLabs",
    fields: [key()],
    inject: { headers: { "xi-api-key": "{{apiKey}}" } },
    test: get("https://api.elevenlabs.io/v1/user"),
  },
  { id: "pinecone", name: "Pinecone", fields: [key()], inject: { headers: { "Api-Key": "{{apiKey}}" } }, test: get("https://api.pinecone.io/indexes") },
  { id: "tavily", name: "Tavily", fields: [key()], inject: bearer(), hosts: ["api.tavily.com"] },
  { id: "firecrawl", name: "Firecrawl", fields: [key()], inject: bearer(), hosts: ["api.firecrawl.dev"] },

  // ---------- Developer platforms / cloud ----------
  {
    id: "github",
    name: "GitHub (Personal Access Token)",
    fields: [tok("Personal Access Token")],
    inject: { headers: { Authorization: "Bearer {{token}}", "X-GitHub-Api-Version": "2022-11-28" } },
    test: get("https://api.github.com/user"),
  },
  {
    id: "gitlab",
    name: "GitLab (Personal Access Token)",
    fields: [url("https://gitlab.com", "GitLab URL"), tok("Personal Access Token")],
    inject: { headers: { "PRIVATE-TOKEN": "{{token}}" } },
    test: get("{{apiUrl}}/api/v4/user"),
  },
  { id: "npm", name: "npm Registry", fields: [tok("Access Token")], inject: bearer("token"), test: get("https://registry.npmjs.org/-/whoami") },
  { id: "vercel", name: "Vercel", fields: [tok()], inject: bearer("token"), test: get("https://api.vercel.com/v2/user") },
  { id: "netlify", name: "Netlify", fields: [tok("Personal Access Token")], inject: bearer("token"), test: get("https://api.netlify.com/api/v1/user") },
  {
    id: "cloudflare",
    name: "Cloudflare (API Token)",
    fields: [tok("API Token")],
    inject: bearer("token"),
    test: get("https://api.cloudflare.com/client/v4/user/tokens/verify"),
  },
  { id: "digitalocean", name: "DigitalOcean", fields: [tok("Personal Access Token")], inject: bearer("token"), test: get("https://api.digitalocean.com/v2/account") },
  { id: "supabase", name: "Supabase Management API", fields: [tok("Access Token")], inject: bearer("token"), test: get("https://api.supabase.com/v1/projects") },
  { id: "sentry", name: "Sentry", fields: [tok("Auth Token")], inject: bearer("token"), test: get("https://sentry.io/api/0/") },
  {
    id: "datadog",
    name: "Datadog",
    fields: [url("https://api.datadoghq.com", "API URL (per site, e.g. https://api.datadoghq.eu)"), key(), { name: "appKey", label: "Application Key", secret: true, required: true }],
    inject: { headers: { "DD-API-KEY": "{{apiKey}}", "DD-APPLICATION-KEY": "{{appKey}}" } },
    test: get("{{apiUrl}}/api/v1/validate"),
  },
  {
    id: "pagerduty",
    name: "PagerDuty",
    fields: [key("REST API Key")],
    inject: { headers: { Authorization: "Token token={{apiKey}}" } },
    test: get("https://api.pagerduty.com/abilities"),
  },

  // ---------- Messaging / email ----------
  { id: "slack", name: "Slack (Bot / User Token)", fields: [tok("Token (xoxb- / xoxp-)")], inject: bearer("token"), test: get("https://slack.com/api/auth.test") },
  {
    id: "discord_bot",
    name: "Discord Bot",
    fields: [tok("Bot Token")],
    inject: { headers: { Authorization: "Bot {{token}}" } },
    test: get("https://discord.com/api/v10/users/@me"),
  },
  {
    id: "twilio",
    name: "Twilio",
    fields: [{ name: "accountSid", label: "Account SID", secret: false, required: true }, { name: "authToken", label: "Auth Token", secret: true, required: true }],
    inject: { basic: { username: "{{accountSid}}", password: "{{authToken}}" } },
    test: get("https://api.twilio.com/2010-04-01/Accounts/{{accountSid}}.json"),
  },
  { id: "sendgrid", name: "SendGrid", fields: [key()], inject: bearer(), test: get("https://api.sendgrid.com/v3/scopes") },
  { id: "resend", name: "Resend", fields: [key()], inject: bearer(), test: get("https://api.resend.com/domains") },
  {
    id: "mailgun",
    name: "Mailgun",
    fields: [url("https://api.mailgun.net", "API URL (EU region: https://api.eu.mailgun.net)"), key()],
    inject: { basic: { username: "api", password: "{{apiKey}}" } },
    test: get("{{apiUrl}}/v3/domains"),
  },
  {
    id: "postmark",
    name: "Postmark (Server Token)",
    fields: [tok("Server API Token")],
    inject: { headers: { "X-Postmark-Server-Token": "{{token}}" } },
    test: get("https://api.postmarkapp.com/server"),
  },

  // ---------- Payments / business ----------
  { id: "stripe", name: "Stripe", fields: [key("Secret Key")], inject: bearer(), test: get("https://api.stripe.com/v1/balance") },
  { id: "hubspot", name: "HubSpot (Private App Token)", fields: [tok("Access Token")], inject: bearer("token"), test: get("https://api.hubapi.com/account-info/v3/details") },

  // ---------- Collaboration / project management ----------
  {
    id: "notion",
    name: "Notion (Internal Integration)",
    fields: [tok("Integration Secret")],
    inject: { headers: { Authorization: "Bearer {{token}}", "Notion-Version": "2022-06-28" } },
    test: get("https://api.notion.com/v1/users/me"),
  },
  { id: "airtable", name: "Airtable (Personal Access Token)", fields: [tok("Personal Access Token")], inject: bearer("token"), test: get("https://api.airtable.com/v0/meta/whoami") },
  {
    id: "jira",
    name: "Jira Cloud / Atlassian (API Token)",
    fields: [
      { name: "domain", label: "Site subdomain (the xxx in xxx.atlassian.net)", secret: false, required: true },
      { name: "email", label: "Atlassian account email", secret: false, required: true },
      { name: "apiToken", label: "API Token", secret: true, required: true },
    ],
    inject: { basic: { username: "{{email}}", password: "{{apiToken}}" } },
    test: get("https://{{domain}}.atlassian.net/rest/api/3/myself"),
  },
  { id: "linear", name: "Linear (Personal API Key)", fields: [key()], inject: { headers: { Authorization: "{{apiKey}}" } }, hosts: ["api.linear.app"] },
  { id: "asana", name: "Asana (Personal Access Token)", fields: [tok("Personal Access Token")], inject: bearer("token"), test: get("https://app.asana.com/api/1.0/users/me") },
  {
    id: "clickup",
    name: "ClickUp (Personal API Token)",
    fields: [tok("API Token (pk_...)")],
    inject: { headers: { Authorization: "{{token}}" } },
    test: get("https://api.clickup.com/api/v2/user"),
  },
  {
    id: "trello",
    name: "Trello",
    fields: [key(), tok("Token")],
    inject: { query: { key: "{{apiKey}}", token: "{{token}}" } },
    test: get("https://api.trello.com/1/members/me"),
  },
  {
    id: "zendesk",
    name: "Zendesk (API Token)",
    fields: [
      { name: "subdomain", label: "Subdomain (the xxx in xxx.zendesk.com)", secret: false, required: true },
      { name: "email", label: "Agent email", secret: false, required: true },
      { name: "apiToken", label: "API Token", secret: true, required: true },
    ],
    inject: { basic: { username: "{{email}}/token", password: "{{apiToken}}" } },
    test: get("https://{{subdomain}}.zendesk.com/api/v2/users/me.json"),
  },
  { id: "figma", name: "Figma (Personal Access Token)", fields: [tok("Personal Access Token")], inject: { headers: { "X-Figma-Token": "{{token}}" } }, test: get("https://api.figma.com/v1/me") },

  // ---------- Search / data ----------
  {
    id: "brave_search",
    name: "Brave Search API",
    fields: [key("Subscription Token")],
    inject: { headers: { "X-Subscription-Token": "{{apiKey}}" } },
    test: get("https://api.search.brave.com/res/v1/web/search", { query: { q: "keyvalet" } }),
  },
  { id: "serpapi", name: "SerpApi", fields: [key()], inject: { query: { api_key: "{{apiKey}}" } }, test: get("https://serpapi.com/account.json") },
  {
    id: "openweathermap",
    name: "OpenWeatherMap",
    fields: [key()],
    inject: { query: { appid: "{{apiKey}}" } },
    test: get("https://api.openweathermap.org/data/2.5/weather", { query: { q: "London" } }),
  },
  {
    id: "deepl",
    name: "DeepL",
    fields: [url("https://api-free.deepl.com", "API URL (Pro accounts: https://api.deepl.com)"), key("Authentication Key")],
    inject: { headers: { Authorization: "DeepL-Auth-Key {{apiKey}}" } },
    test: get("{{apiUrl}}/v2/usage"),
  },
];

// Compute the fixed API host (when the host part of the URL contains no placeholders)
for (const t of T) {
  t.source = "catalog";
  t.kind = "static";
  if (!t.hosts && t.test) {
    const fields = t.fields;
    const rendered = t.test.url.replace(/\{\{(\w+)\}\}/g, (m, n) => fields.find((f) => f.name === n)?.default ?? "zzph");
    try {
      const h = new URL(rendered).hostname;
      if (!h.includes("zzph")) t.hosts = [h];
    } catch {
      /* contains placeholders */
    }
  }
}

const ids = new Set();
for (const t of T) {
  if (ids.has(t.id)) throw new Error(`Duplicate template id: ${t.id}`);
  ids.add(t.id);
}

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "templates", "catalog.json");
fs.writeFileSync(
  out,
  JSON.stringify({ source: "keyvalet", license: "Apache-2.0", note: "Compiled from official API docs of each service; generated by scripts/build-catalog.mjs", templates: T }, null, 1) + "\n",
);
console.log(`Wrote ${out}: ${T.length} templates (${T.filter((t) => t.test).length} verifiable)`);

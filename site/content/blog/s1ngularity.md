+++
title = "Your AI coding agent can read every secret on your machine. In August 2025, one did."
date = 2026-10-08
description = "The s1ngularity npm attack didn’t exploit a bug in any AI agent — it just asked nicely. The structural fix is to never let the agent hold the secret."
+++

On August 26, 2025, a compromised npm package turned thousands of developers' own AI coding assistants against them. The attack — later named **s1ngularity** — didn't exploit a vulnerability in Claude Code, Gemini CLI, or Amazon Q. It didn't need one. It just asked them, nicely, to hand over everything.

## What actually happened

A malicious update to the `nx` build tool (and several related packages) shipped a post-install script. That script's job was simple: look around the infected machine for an AI coding CLI — Claude Code, Gemini CLI, or Amazon Q — and, if one was installed, invoke it directly from the shell with a prompt instructing it to search the filesystem for secrets: SSH keys, `.env` files, npm and GitHub tokens, cloud credentials. Where it could, it added `--dangerously-skip-permissions` or the equivalent, so the agent wouldn't even pause to ask.

The agents did exactly what they were told. They're very good at exactly this kind of task — read files, pattern-match for anything that looks like a key, summarize it — which is precisely why it worked so well. The harvested secrets were exfiltrated to attacker-controlled GitHub repositories, created under the victims' own accounts using their own stolen tokens.

By the time it was over: **over 2,300 secrets** stolen across **225+ GitHub organizations**, and roughly **6,700 private repositories** flipped to public before anyone could stop it. Wiz's analysis of the blast radius found that AI CLI tools were installed on close to half of the affected machines — not a coincidence, a target list.

## The part that should worry you

Nothing about this attack was exotic. It wasn't a jailbreak, a prompt injection against a hosted model, or a zero-day in anyone's agent. It was a `postinstall` script — the oldest supply-chain trick in the npm ecosystem — paired with a local CLI that had one property the attackers needed: **it could read your secrets and had no idea it shouldn't.**

That's the structural problem. Claude Code, Gemini CLI, and Amazon Q (and basically every coding agent, including the ones we build on) are designed to read your filesystem, because that's the job. If your OpenAI key is sitting in `.env`, your AWS credentials in `~/.aws/credentials`, your GitHub token in `~/.netrc` — the agent can read them, because it has to be able to read *your code*, and nothing on disk tells it "this file is different, don't summarize this one for a stranger."

`--dangerously-skip-permissions` made this attack faster, but it wasn't the actual hole. The actual hole is that **the secrets were readable at all** — by the agent, by a malicious prompt that reaches the agent, by anything running as you. Removing the flag would have only meant someone had to click "approve" on the thing that had already decided to approve.

## This keeps happening, and it won't stop on its own

s1ngularity wasn't a one-off. The same underlying fact — agents hold the keys, in plaintext, in their own reachable context — is the common thread in essentially every agent-credential incident since:

- **Comment and Control** (April 2026): a PR title or issue comment, parsed by a CI agent, exfiltrated `GITHUB_TOKEN` and friends through the same "I can read it, so I will" logic.
- **GhostSplice** (August 2026): a malicious MCP server split its exfiltration instructions across multiple tool calls so no single one looked suspicious — same target, more patience.
- GitGuardian's 2026 scan of public GitHub found **24,008 secrets sitting in MCP configuration files alone**, 2,117 of them still live.

Different delivery mechanism each time. Same precondition every time: an agent that can see the plaintext.

## What actually breaks this

The fix isn't "write better prompts" or "add more permission dialogs" — s1ngularity's victims had permission dialogs; the attack just told the agent to skip them, and a sufficiently motivated prompt injection doesn't need your permission at all once it's inside the agent's own reasoning.

The fix is structural: **don't let the agent hold the secret in the first place.**

That's the entire design of KeyValet. Your OpenAI key, GitHub token, AWS credentials — they live in a local vault, encrypted, readable only by a root-owned helper process. When your agent needs to call an API, it doesn't ask for the key; it asks KeyValet to make the call on its behalf (`credential_http_request`), and gets back a response with the secret already stripped out, even if the upstream service echoes it back. If an agent — or a malicious script riding along in your dependencies — tries to *write* a key into a file, a shell command, or a chat prompt, a hook flags it before it lands. There is no `--dangerously-skip-permissions` equivalent, because there's no permission check sitting between a compromised process and a plaintext secret: the secret was never in a place that process could reach.

Could s1ngularity have worked against a KeyValet-protected machine? The malicious script could still have told the agent "go read `.env` and summarize anything that looks like a key" — but there wouldn't have been a key in `.env` to find. It would have found nothing usable — the key is in the vault, and the agent can only use it through proxied calls you approve.

That's the bar. Not "detect this specific attack" — detect nothing, need nothing to detect, because the thing the attack needs was never there.

## What we don't claim

KeyValet doesn't protect against misuse of a credential *within* an active grant — if your agent is authorized to call the OpenAI API right now and a prompt injection tells it to burn through your quota, that's a real limitation, and it's why `proxy_only`, narrowed `allowed_hosts`, and per-credential grant modes exist: to shrink what "authorized" means. It doesn't verify that an agent's stated purpose for using a credential is true — that's recorded in the audit log and never more than a claim; the Touch ID prompt shows the request itself, not the agent's reason. Full list, no marketing gloss, in [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md).

What it does guarantee is the one thing that would have stopped s1ngularity cold: your agent — compromised, confused, or just following a bad prompt — can tell you anything it wants about what it's doing. It still can't show you the key, because it never had it.

---

**Sources:** [GitGuardian — the Nx s1ngularity attack](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/) · [SecurityWeek — 6,700 private repositories made public](https://www.securityweek.com/over-6700-private-repositories-made-public-in-nx-supply-chain-attack/) · [GitGuardian — State of Secrets Sprawl 2026](https://www.gitguardian.com/state-of-secrets-sprawl-report-2026) · [SecurityWeek — Comment and Control](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/) · [The Hacker News — GhostSplice](https://thehackernews.com/2026/08/malicious-mcp-servers-can-split.html)

---

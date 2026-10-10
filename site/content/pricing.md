+++
title = "Pricing"
description = "KeyValet is free and open source. Team plans — shared credentials, org policy, audit export, CI identity — are planned, not available yet."
+++

<div class="plans wide">
  <div class="plan">
    <h3>Free</h3>
    <p class="price">$0</p>
    <p>Open source (Apache-2.0), forever. Everything the product does today:</p>
    <ul>
      <li>Local vault protected by Secure Enclave + device binding</li>
      <li>All credential kinds: API keys, OAuth 2.0, Google service accounts, GitHub Apps, JWT, TOTP, AWS STS</li>
      <li>~50 service templates + generic bearer/header/query/basic</li>
      <li>Proxied calls and the loopback SDK gateway</li>
      <li>Touch ID approval modes: per-use, per-credential, per-session, remember</li>
      <li>Hooks for Claude Code, Codex, Cursor, Grok Build and Devin CLI</li>
      <li><code>keyvalet scan</code> and the local, root-only audit log</li>
    </ul>
    <p>Planned for Free:</p>
    <ul>
      <li>Policy engine (risk tiers, policy.yaml)</li>
      <li>Linux helper</li>
      <li>Self-hosted relay</li>
      <li>iPhone approvals</li>
    </ul>
    <p class="cta-plan"><a class="btn primary" href="/#install">Install on macOS</a></p>
  </div>
  <div class="plan">
    <span class="badge">Planned — not available yet</span>
    <h3>Team</h3>
    <p class="price">$15 <small>per seat / month · $12 billed annually</small></p>
    <p>Machine identities unlimited (fair use).</p>
    <ul>
      <li>Shared credentials wrapped per member device</li>
      <li>Org policy as code — it can only tighten members’ local policy</li>
      <li>Audit export (JSONL / OTLP)</li>
      <li>CI identity: GitHub OIDC → short-lived capability token; no static secrets in repo settings</li>
      <li>Hosted relay without quotas</li>
      <li>Encrypted cross-device sync</li>
      <li>Member management</li>
    </ul>
    <p>14-day trial, no credit card, when it ships.</p>
    <p class="cta-plan"><a class="btn ghost" href="https://github.com/KeyValet/KeyValet/discussions">Get notified</a></p>
  </div>
  <div class="plan">
    <span class="badge">Planned — not available yet</span>
    <h3>Team + phone approvals</h3>
    <p class="price">$18 <small>per seat / month · $15 billed annually</small></p>
    <p>Everything in Team, plus:</p>
    <ul>
      <li>Approval routing to an owner’s phone</li>
      <li>N-of-M approvals for sensitive credentials</li>
      <li>Phone approvals for Linux/CI</li>
      <li>OIDC SSO (Okta, Entra, Google)</li>
      <li>90-day encrypted audit retention</li>
    </ul>
    <p class="cta-plan"><a class="btn ghost" href="https://github.com/KeyValet/KeyValet/discussions">Get notified</a></p>
  </div>
</div>

## FAQ

### Is Free really free?

Yes — no time limit, no watermark, no security downgrade. An upgrade prompt may appear once, at the moment you hit a Team-only need, and never again.

### Do you ever see my secrets?

No. Everything is local: secrets live in a root-only vault on your Mac, protected by Secure Enclave and device binding. Team plans sync only ciphertext wrapped to your devices.

### Why does Team cost money?

Shared keys, CI identity, policy distribution and audit export need a relay — and people to run it.

### Can I self-host the relay?

Planned, yes — and open source.

### What about Enterprise?

Later: self-hosted, SSO/SCIM, isolated CI execution. Not before 2027.

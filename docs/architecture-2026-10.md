# KeyValet Technical Architecture (Phase 0 to Phase 3)

- Date: 2026-10-08
- Decision update: 2026-10-09 — platform support and secret protection follow [Product §1.4](product-2026-10.zh-CN.md#14-平台支持与密钥保护); the first macOS release and the real-vault migration are done (§8.0); the other new capabilities are still design — the current threat model lives in `SECURITY.md`.
- Scope: from the existing v0.1 to Phase 3 "iPhone approval and full Team" (~14 months). Phase 4 items — enclave offline execution, the remote MCP endpoint, Enterprise self-hosting, SCIM, Android — keep their design sections but are marked with their phase and are not part of the first-14-month implementation plan. Native Windows support is scheduled against concrete demand; see §8.0.
- Version: second edition (2026-10-08), revised after an overall review: phase ordering for the solo-developer edition; client authentication and CA ownership for the transparent proxy; moving the relay client out of the privileged helper; trust statements for the KMS path and BYO-KMS; precise grant scope and template `summarize`; Ory Hydra instead of a self-built authorization server; runtime adaptation changed to a Rust trait + a manifest that only carries install metadata.
- First-wave runtimes: Claude Code, Codex, Cursor, Grok
- Companion documents: `docs/strategy-2026-10.zh-CN.md` (market, pricing, roadmap), `docs/product-2026-10.zh-CN.md` (product plan, user journeys, UX spec), `SECURITY.md` (current threat model)
- Note: `docs/` holds internal planning; the public site only publishes `site/` — this document is not published to the website.

## Contents

1. Design principles
2. Current baseline and scope of changes
3. Overall architecture
4. Core pipeline and plugin system
5. Runtime adaptation layer
6. Policy engine
7. Approval subsystem
8. Keys, identity, and vault format
9. Executors and routing
10. Server side: relay, remote MCP endpoint, team, and billing
11. Nitro enclave executor
12. Audit
13. Storage backends and import
14. Team features
15. Official relay quota and the CI offline-execution add-on
16. Security design highlights
17. Observability and operations
18. Engineering plan: repo layout, migration, testing, release
19. Phase-deliverable mapping
20. Open questions
- Appendix A: `keyvalet.toml` example
- Appendix B: `policy.yaml` example
- Appendix C: runtime manifest example
- Appendix D: approval request and capability token examples
- Appendix E: server API summary
- Appendix F: new IPC v4 operations

---

## 1. Design principles

1. **The agent never holds secrets.** The default delivery mode is proxy execution; new credentials default to `proxy_only = true` (Product §6.3); file paths come second; plaintext must be explicitly allowed and is always audited.
2. **Approvals bind to the real request.** What gets approved is the normalized request digest, not a sentence the agent wrote; one approval executes exactly once.
3. **Local-first.** Every on-device feature works without the server; the server only participates for remote approval, remote agents, and offline execution.
4. **The server only ever sees ciphertext.** Everything through the relay is end-to-end encrypted; a compromised server leaks only ciphertext and metadata.
5. **Everything is a plugin.** Ten extension points — runtime, identity, policy, approval, issuing, delivery, guard, storage, audit, template — and the core depends only on traits.
6. **One core, three targets.** The same Rust crates compile to the Mac/Linux helper, the iPhone app (UniFFI), and the Nitro enclave.
7. **Declarative runtime adaptation.** Adding a runtime mostly means writing a manifest, not code.
8. **No silent downgrades.** The default grant mode stays per-credential; T2 sensitive operations always require a fresh Strong approval; the transparent proxy is opt-in.
9. **Auditable and reproducible.** A hash-chained audit log; enclave images are reproducible with published PCRs; releases are signed.
10. **Backward compatible.** The IPC protocol moves smoothly from v3 to v4; the existing TS MCP frontend keeps working during migration.
11. **Shortest path to revenue first.** Phases are ordered by revenue prerequisites: policy and Linux → relay and Team v1 → phone → enclave. Components not on the current revenue path only get interface reservations.

---

## 2. Current baseline and scope of changes

### 2.1 Existing components (v0.1)

| Component | Location | Notes |
| --- | --- | --- |
| MCP server (TypeScript) | `src/server/` | stdio MCP, ~30 `credential_*` tools, templates, OAuth browser flows, native dialogs |
| Privileged helper | `src/helper/` (TS) and `rust/crates/kv-helper` (Rust rewrite) | Spawned by `sudo`, runs as root, talks to the MCP server over stdin/stdout only, exits when stdin closes; `verify_root_environment` validates its own path and environment |
| IPC protocol v3 | `src/shared/protocol.ts`, `rust/crates/kv-ipc` | 24 operations: ListTypes, CreateType, DeleteType, List, Exists, Info, Get, Set, Delete, SetupProtocol, OauthExchange, OauthDeviceStart, OauthDevicePoll, AccessToken, Totp, Aws, AuditQuery, HttpConfigure, HttpRequest, HttpTest, Grant, Settings, SessionInfo, GatewayOpen; one JSON object per line, 1 MiB cap; `[GRANT_REQUIRED]` prefix means authorization is needed |
| Authorization gate | `kv-core/auth_gate.rs`, `dispatch.rs` | `AuthorizeGate` trait; `TouchIdSessionGate` wraps Touch ID with failure cooldown and locking; `SessionAuth` implements the four grant modes PerUse / PerCredential / PerSession / Remember |
| vault | `kv-vault` | Encrypted file; `CredentialRecord { kind, value, config, secrets, state, generation, http, template, description, attributes }`; `Kind`: Static, Oauth2, GoogleServiceAccount, GithubApp, Jwt, Totp, Aws; audit writes go through `audit()` |
| Protocol issuers | `kv-protocols` | oauth2, jwt, github_app, google_sa, aws (STS), totp, http; `setup_protocol` / `access_token` |
| Proxy and gateway | `kv-proxy` | `HttpConfig { inject, allowed_hosts, proxy_only, test }`; `InjectRule { headers, query, basic }`; placeholder rendering; local gateway (`OPENAI_BASE_URL` style, peer-uid check); response redaction `redact.rs` |
| Platform layer | `kv-platform` | `Authenticator` (Touch ID), `Confirmer` (native confirmation dialog), path and trust validation |
| Claude Code plugin | `claude-plugin/` | hooks: `UserPromptSubmit` (user pasted a secret → suggest storing it), `PreToolUse` (Write/Edit/MultiEdit/NotebookEdit/Bash hit a secret → `permissionDecision: ask`); skills and `/keyvalet:*` commands |
| Templates | `templates/catalog.json`, `n8n-catalog.json` | `CredentialTemplate { id, name, source, kind, fields, inject, test, oauth }` |
| Website and docs | `site/index.html`, `site/guide.md`, `site/install.sh` (GitHub Pages) | Static landing page, guide, install script; migrated out of `docs/` on 2026-10-09 — `docs/` used to be both the Pages publishing root and the home of all internal planning docs, effectively publishing them; they were moved immediately after discovery (§18.6) |

### 2.2 Changes introduced by this document

| Category | Changes |
| --- | --- |
| Keep | Vault encrypted file, the seven Kinds, the four grant modes, proxy injection and redaction, template format, the Claude Code plugin, the root helper isolation model |
| Refactor | The monolithic `dispatch.rs` dispatch split into a pipeline + registry; `AuthorizeGate` upgraded to the `Approver` trait with request digests; the `SessionAuth` mode logic folded into the policy engine |
| New | Policy engine, approval binding with one-time nonces, capability tokens, device identity keys, runtime manifests and the shared hook binary, transparent proxy, Linux helper, relay server, remote MCP endpoint, iPhone app, enclave executor, team and billing, audit hash chain, storage backend plugins, `keyvalet scan` |
| Migrate | TS MCP server gradually replaced by the Rust MCP server (§18.3); IPC v3 → v4 incremental extension (Appendix F); vault file format v1 → v2 (§8.4) |

---

## 3. Overall architecture

### 3.1 Component diagram

```
┌──────────────────────────── User machine (Mac / Linux) ─────────────────────────┐
│  Claude Code / Codex / Cursor / Grok                                              │
│     │ MCP(stdio)      │ hooks(JSON)      │ HTTPS_PROXY(with session token) / OPENAI_BASE_URL │
│     ▼                 ▼                  ▼                                        │
│  kv-mcp (user)     kv-hook (user)    kv-proxy transparent proxy / gateway (user, no CA key) │
│     └────────────────┬┴─────────────────┘                                         │
│                      │ IPC v4 (Unix socket, peer-uid check)                       │
│                      ▼                                                            │
│  ┌──────── kv-helper (privileged: Mac root / Linux dedicated user; no outbound    │  │
│  │          network, no long-lived connections) ────────────────────────────────┐  │
│  │  Pipeline: Identity → Policy → Approver → Issuer → Deliverer → Guard → Audit │  │
│  │  Plugin registry · vault (ciphertext) · device keys (SE / TPM2)              │  │
│  │             · proxy CA private key · audit hash chain                        │  │
│  │  Approver: TouchID | TTY(Quick only) | Remote(phone, Phase 3) | Auto | Team  │  │
│  │  StorageBackend: local | keychain | 1password | infisical | bitwarden        │  │
│  └────────────────────────────┬────────────────────────────────────────────────┘  │
│                               │ IPC (local)                                       │
│                    kv-relay-client (user; the only outbound process, Phase 2)     │
└───────────────────────────────┼───────────────────────────────────────────────────┘
                                │ WebSocket + HPKE (end-to-end)
┌───────────────────────────────▼───────────────────────────────────────────────────┐
│  kv-server (self-hosted Docker or AWS; the official instance is hosted in the US) │
│  — sees only ciphertext and opaque ids                                            │
│  relay: device registration · presence · pending-approval queue(TTL)              │
│         · ciphertext storage                                          [Phase 2]   │
│  team: orgs · members · shared credentials(CEK wrapped per member)                │
│        · policy distribution · audit sync                             [Phase 2]   │
│  billing: Stripe webhook · entitlement issuing · usage metering       [Phase 2]   │
│  auth: Ory Hydra (OAuth 2.1 AS) + login/consent pages; remote MCP                 │
│        resource server                                                [Phase 3/4] │
└──────┬─────────────────────────────┬────────────────────────────┬─────────────────┘
       │ wake(id only) [Phase 3]     │ E2E [Phase 3]              │ E2E [Phase 4]
       ▼                             ▼                            ▼
  kv-push (US-hosted, holds the     iPhone App (Swift + UniFFI)   kv-enclave (AWS Nitro)
  APNs key, only forwards           two approval tiers · SE keys  remote attestation · HPKE
  approval ids)                     · pairing                     · BYO-KMS
```

### 3.2 Processes and trust boundaries

| Process | Runs as | Holds | Does not hold |
| --- | --- | --- | --- |
| `kv-mcp` | current user | IPC connection; tool schemas | any secret |
| `kv-hook` | current user, spawned by the runtime | runtime event JSON; can ask the helper "is this the fingerprint of a known secret" | secret plaintext; network |
| `kv-proxy` (transparent proxy/gateway) | current user | session token table; short-lived leaf certs requested per host from the helper (private key only in memory) | CA private key; credential plaintext |
| `kv-relay-client` | current user | relay connection, HPKE sealing, device public-key directory | secret plaintext; device private key (asks the helper over IPC to sign when needed) |
| `kv-helper` | Mac: root (spawned via sudo); Linux: system user `keyvalet` | vault ciphertext, device wraps of the UMK, device key handles, proxy CA private key, audit chain | any outbound long-lived connection; long-term server credentials |
| `kv-server` | container | ciphertext, opaque ids, device public keys, entitlements, Team emails | plaintext, UMK, CEK, credential metadata |
| Ory Hydra | container | OAuth clients and tokens | any credential |
| `kv-push` | container (US) | APNs key, device push tokens | approval contents |
| iPhone App | user | two SE keys, the phone wrap of the UMK | the full vault (pulls single ciphertext records on demand) |
| Web console (browser, from Phase 2) | user | session cookie; from Phase 3 can act as a device: a non-exportable WebCrypto P-256 key (IndexedDB) | the full vault; Strong approval capability |
| Official website (static) | — | public content: docs, pricing, `install.sh` + checksums, PCR list, CIMD documents | any user data |
| `kv-enclave` | Nitro enclave | ephemeral keys generated per boot; the CEK of a single request | UMK; anything persistent |

Where injection happens: on the proxy-execution path, `kv-proxy` (user space) only does TLS termination and forwarding — **the helper is what actually writes the secret into the request headers**. The proxy hands the credential-free request to the helper over IPC; the helper injects, sends the upstream request, redacts, and returns the response. There are exactly two network egresses: the upstream HTTPS calls made by the helper (already injected) and `kv-relay-client`; the helper itself maintains no inbound or long-lived connections.

---

## 4. Core pipeline and plugin system

### 4.1 The ten extension points

```
crate kv-core
  pipeline.rs      pipeline orchestration
  registry.rs      plugin registry
  request.rs       normalized requests, digests
  traits/
    runtime.rs     RuntimeAdapter   — a Rust trait, one impl per runtime; the manifest only carries install metadata, see §5.2
    identity.rs    IdentityProvider — device keys, agent identity
    policy.rs      PolicyEvaluator  — rule evaluation
    approver.rs    Approver         — human or automatic approval
    issuer.rs      Issuer           — turns a long-term credential into a usable one
    deliverer.rs   Deliverer        — delivery mode
    guard.rs       Guard            — pre-request / post-response middleware
    storage.rs     StorageBackend   — source of credential ciphertext
    audit.rs       AuditSink        — audit persistence
    template.rs    TemplateSource   — template source
```

Trait signatures (Rust, error details elided):

```rust
/// A normalized request to use a credential (§4.3)
pub struct UseRequest {
    pub id: Ulid,
    pub agent: AgentIdentity,          // runtime, host device, session, repo/cwd
    pub credential: CredentialRef,     // type/name or a keyvalet:// reference
    pub action: Action,                // HttpCall{method,url,headers_digest,body_digest} | AccessToken{scope} | Totp | Aws{role} | Read | ExportFile
    pub purpose: Option<String>,       // purpose stated by the agent (display and audit only; not part of authorization)
    pub digest: [u8; 32],              // SHA-256(JCS(canonical fields)); what approvals bind to
    pub nonce: [u8; 16],
    pub issued_at: u64, pub expires_at: u64,
    pub signature: Option<Signature>,  // signed by the device key of the agent's host
}

pub struct HookEvent { pub runtime: RuntimeId, pub stage: HookStage, pub tool: Option<String>, pub args: serde_json::Value, pub cwd: Option<PathBuf>, pub session: Option<String> }
pub enum HookDecision { Allow, Ask { reason: String, context: String }, Deny { reason: String }, Rewrite { args: serde_json::Value } }

pub trait RuntimeAdapter: Send + Sync {
    fn id(&self) -> RuntimeId;                                   // claude-code / codex / cursor / grok
    fn install_targets(&self) -> Vec<InstallTarget>;             // from the manifest: config paths, merge method, event names, command line
    fn parse_event(&self, stage: HookStage, raw: &[u8]) -> Result<HookEvent>;   // each vendor's JSON → unified event
    fn render_decision(&self, d: &HookDecision) -> HookOutput;   // unified decision → vendor format (JSON or exit code)
    fn caps(&self) -> RuntimeCaps;                               // can it ask, can it rewrite args, which tools it covers
}

pub trait IdentityProvider: Send + Sync {
    fn device_id(&self) -> DeviceId;
    fn sign(&self, msg: &[u8]) -> Result<Signature>;
    fn public_key(&self) -> PublicKey;                  // P-256
    fn agent_identity(&self, ctx: &ClientContext) -> AgentIdentity;
}

pub enum Decision { Auto, Ask, Strong, Deny(String) }
pub struct Tier(pub u8); // T0..T3

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, req: &UseRequest, cred: &CredentialMeta, grants: &GrantState) -> PolicyOutcome; // { tier, decision, matched_rules, budget_remaining }
}

pub enum ApprovalKind { Quick, Strong }
pub struct Approval { pub request_digest: [u8;32], pub nonce: [u8;16], pub approver: DeviceId, pub kind: ApprovalKind, pub scope: GrantScope, pub signature: Signature }

pub trait Approver: Send + Sync {
    fn capabilities(&self) -> ApproverCaps;  // Quick/Strong support, remote or not, expected latency
    async fn approve(&self, req: &UseRequest, display: &ApprovalDisplay, kind: ApprovalKind) -> Result<Approval, Denied>;
}

pub trait Issuer: Send + Sync {
    fn kinds(&self) -> &'static [Kind];
    async fn setup(&self, params: SetupParams, store: &dyn StorageBackend) -> Result<CredentialRecord>;
    async fn issue(&self, rec: &CredentialRecord, req: &UseRequest) -> Result<Issued>; // Issued = Header(s) | Token{value,exp} | AwsCreds | TotpCode | Bytes
    async fn refresh(&self, rec: &mut CredentialRecord) -> Result<()>;
}

pub enum DeliveryMode { ProxyExecute, FilePath, EnvInject, Plaintext }
pub trait Deliverer: Send + Sync {
    fn mode(&self) -> DeliveryMode;
    async fn deliver(&self, issued: Issued, req: &UseRequest, guards: &GuardChain) -> Result<DeliveryResult>;
}

pub trait Guard: Send + Sync {
    fn before(&self, req: &mut OutboundRequest) -> Result<()>;   // SSRF, host allowlist, method limits
    fn after(&self, resp: &mut OutboundResponse, secrets: &[SecretFingerprint]) -> Result<()>; // redaction, binary rejection
}

pub trait StorageBackend: Send + Sync {
    fn id(&self) -> &str;
    async fn list(&self) -> Result<Vec<CredentialMeta>>;          // metadata only
    async fn load(&self, r: &CredentialRef) -> Result<Sealed<CredentialRecord>>; // ciphertext or a backend handle
    async fn store(&self, r: &CredentialRef, rec: Sealed<CredentialRecord>) -> Result<()>;
    fn capabilities(&self) -> StorageCaps;                        // writable? references? rotation notifications?
}

pub trait AuditSink: Send + Sync {
    async fn append(&self, e: AuditEntry) -> Result<()>;
}

pub trait TemplateSource: Send + Sync {
    fn templates(&self) -> Vec<CredentialTemplate>;
}
```

### 4.2 Registry and loading

- **Official plugins**: same Cargo workspace, compiled in via `features`; `registry.rs` instantiates them at startup per the `[plugins]` section of `keyvalet.toml`. Zero IPC overhead, easy to audit. Phases 0–3 all use this layer.
- **Runtime adapters**: not code — a manifest (YAML). `kv-hook` reads the manifest to translate runtime events into `HookEvent`; `kv-mcp` reads the manifest to decide tool annotations and install paths.
- **Third-party plugins** (reserved for Phase 4): subprocess + JSON-RPC over stdio (same pattern as MCP and Terraform providers), interfaces mirroring the traits one-to-one. No dynamic libraries, no WASM.

Registry resolution order: explicit declarations in `keyvalet.toml` > built-in defaults. Multiple instances may serve the same extension point (e.g. two StorageBackends, three Approvers); the pipeline picks by capability and policy.

### 4.3 Request lifecycle

```
1  Ingress    RuntimeAdapter receives the call (MCP tool / proxy request / CLI), builds a UseRequest
2  Identity   IdentityProvider fills AgentIdentity, signs the digest with the device key
3  Resolve    StorageBackend.load fetches metadata (does not decrypt value)
4  Policy     PolicyEvaluator.evaluate → Tier + Decision
              Deny   → return [POLICY_DENIED] with reason, audit
              Auto   → jump to 7
              Ask    → 5 (Quick suffices)
              Strong → 5 (must be Strong)
5  Grant      GrantState checks whether an existing grant (four modes) covers it; T2 is never covered by Remember
6  Approval   Pick an Approver: local Touch ID > TTY > remote phone > team routing; produces an Approval (bound to digest+nonce)
7  Nonce      Record the nonce as used; reject replays
8  Issue      Issuer.issue: unwrap CEK → decrypt value → produce a usable credential (header/token/STS/TOTP)
9  Deliver    Deliverer: ProxyExecute by default; Guard.before (SSRF, host) → upstream request → Guard.after (redaction)
10 Audit      AuditSink.append: request digest, policy decision, approver device, upstream status, trace id
```

Error semantics: every rejection carries a machine-readable code (`POLICY_DENIED`, `APPROVAL_DENIED`, `APPROVAL_TIMEOUT`, `DEVICE_OFFLINE`, `BUDGET_EXCEEDED`, `HOST_NOT_ALLOWED`); the MCP layer maps them to tool errors, and `DEVICE_OFFLINE` comes with a hint about the "CI offline execution" add-on.

### 4.4 Data model

| Entity | Key fields | Stored in |
| --- | --- | --- |
| Credential | existing `CredentialRecord` + `cek_id`, `sensitivity` (normal/sensitive), `backend`, `tags` | vault or backend |
| Device | `device_id`, `pubkey` (P-256), `kind` (mac/linux/iphone/android/enclave), `capabilities`, `enrolled_at`, `umk_wrap` | local and server |
| AgentIdentity | `runtime` (claude-code/codex/cursor/grok), `runtime_version`, `host_device`, `session_id`, `repo`, `cwd`, `pid` | memory, written to audit |
| Grant | `scope = (credential, tier ≤ T1, allowed_hosts, methods, budget)`, `until`, `granted_by`, `mode`; T2 requests are never covered by grants — each must bind its digest anew (§7.6) | helper memory and local files |
| Approval | §7 | nonce store (local SQLite) |
| Capability (pre-authorization token) | §7.5 | local and server |
| PolicyRule | §6 | file |
| AuditEntry | §12 | local hash chain; Team syncs to the server |
| Org / Member / SharedCredential | §14 | server |

---

## 5. Runtime adaptation layer

### 5.1 MCP server (stdio)

- Rewrite `kv-mcp` with the Rust SDK for MCP spec 2026-07-28 (migration path in §18.3). In stdio mode the spec takes credentials "from the environment" — no OAuth; remote mode is §10.3.
- Tool set keeps the existing `credential_*` naming; all get annotations: `credential_list` / `credential_status` / `credential_audit_log` / `credential_templates` / `credential_list_types` get `readOnlyHint`; `credential_delete` / `credential_delete_type` get `destructiveHint`; `credential_http_request` / `credential_gateway` get `openWorldHint`.
- When Touch ID is unavailable (no GUI, SSH session), use MRTR: the tool returns `input_required` and lets the client collect the confirmation; only for low-risk Quick approvals — Strong approvals must go through the phone or local biometrics.
- per-session grants bind to the stdio process lifecycle, not the removed `Mcp-Session-Id`.
- New tools: `credential_scan` (§13.3), `credential_policy` (show effective policy), `credential_pair` (pair a phone, §8.3).

### 5.2 Hooks: one binary, four Rust adapters, manifests only carry install metadata

`kv-hook` is a small Rust binary (no network, no vault access, a single IPC operation `HookEvent` to query known-secret fingerprints). Each runtime has one `RuntimeAdapter` implementation (§4.1) that translates each vendor's JSON into a unified `HookEvent` and renders the unified `HookDecision` into output the vendor accepts. The manifest (Appendix C) only records **install metadata**: config file paths, merge method, event names, command line — no field mapping or output templates. Why: Cursor can only deny via exit code and cannot ask; Codex's `PreToolUse` doesn't cover all shell paths. These semantic differences are expressed with Rust types and tests — more reliable than a YAML interpreter.

```
runtime event JSON ──▶ kv-hook --runtime <name> --event <stage>
                         │ adapter.parse_event → HookEvent
                         │ detection: regex secret patterns + asking the helper
                         │            for known-secret fingerprints (HMAC, no plaintext)
                         │ decision: Allow / Ask / Deny / Rewrite (degraded by adapter.caps:
                         │            runtimes that can't ask get deny)
                         └─▶ adapter.render_decision → stdout JSON or exit code
```

Adaptation notes per runtime:

| Runtime | Config location | Events | Decision output | Notes |
| --- | --- | --- | --- | --- |
| Claude Code | plugin `hooks.json` or `settings.json` | `UserPromptSubmit`, `PreToolUse` (Write/Edit/MultiEdit/NotebookEdit/Bash), `PermissionRequest`, `PostToolUse` | JSON: `permissionDecision` allow/deny/ask/defer, `updatedInput`, `additionalContext` | existing implementation migrated into an adapter |
| Codex | `~/.codex/hooks.json` or `config.toml [hooks]` | `PreToolUse` (same name and shape) | same as Claude Code | official docs admit it doesn't cover all shell paths; documented as degraded protection |
| Cursor | `~/.cursor/hooks.json`, `.cursor/hooks.json`, plugin `cursor-plugin/hooks/hooks.json` (installed to `~/.cursor/plugins/local/`) | `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` (matcher on file-writing tools), `sessionStart` (injects KeyValet guidance as context) | stdout JSON: `{"permission": "allow"\|"deny", "user_message", "agent_message"}`; exit code 2 is equivalent to deny; `sessionStart` outputs `{"additional_context"}` | `permission: "ask"` is in the schema but Cursor doesn't enforce it — effectively a silent allow — so `kv-hook` never emits `ask`, always `deny`. The implementation does not use the generic `RuntimeAdapter`/manifest abstraction envisioned in §4.1; instead `kv-hook` gained dedicated `cursor-shell`/`cursor-mcp`/`cursor-tool`/`cursor-session` subcommands over the shared secret-detection core. `beforeMCPExecution`'s `tool_input` is a JSON string and carries `mcp_server_name` (the doc-specified server field), which exempts KeyValet's own calls (`credential_set`'s `value` legitimately carries a secret); `preToolUse` adds coverage for agent file-writing tools like `Write`/`Edit` (the dedicated events only cover shell and MCP) — its `tool_input` is an object; `beforeSubmitPrompt` can only block, not inject context, so it isn't used for paste hints |
| Grok | `~/.grok/hooks/*.json` (user-level, trusted by default), `<project>/.grok/hooks/*.json` (project-level, needs `/hooks-trust`) | `PreToolUse` (the only blocking event; `UserPromptSubmit`/`PostToolUse`/`Stop` etc. exist natively but are observe-only) | exit code: 0 = allow, 2 = deny (verified 2026-10: Grok reads Claude Code hook config for compatibility but does not parse the nested `hookSpecificOutput.permissionDecision` — unparseable means allow, so only the exit code actually works) | no ask; MCP is natively supported (`grok mcp add`, tools named `server__tool`), no Grok-specific code needed; matcher `.*` covers MCP calls, and KeyValet's own tools (`keyvalet__*` / server fields) are exempted inside `kv-hook` |
| Devin CLI | plugin `devin-plugin/hooks.json` (`devin plugins install`), project-level `.devin/hooks.v1.json`, the `hooks` key of user-level `config.json`; MCP via plugin `.mcp.json`, `devin mcp add`, or auto-import from `~/.claude.json` | `UserPromptSubmit`, `PreToolUse` | stdout JSON: `{"decision": "approve"\|"block", "reason"}`; exit code 2 also blocks; `hookSpecificOutput.additionalContext` is parsed too (the `prompt` mode reuses it directly) | no ask — a hit blocks (same tradeoff as Cursor); tool names are Devin's own lowercase ones (`exec`/`write`/`edit`/`apply_patch`/`notebook_edit`/`write_to_process`), and `exec` scans `env` values as well; MCP calls appear both as `mcp_call_tool` wrappers and `mcp__server__tool` namespaced names — the `keyvalet` server itself is exempted in both forms (`credential_set`'s `value` legitimately carries a secret); plugin hooks are officially fail-open |

Install: `keyvalet hooks install [--runtime all|claude-code|codex|cursor|grok]` reads the manifests' install metadata, detects installed runtimes, writes or merges config files — idempotent.

What hooks can do: block recognizable-format secrets being written into files or commands (current); rewrite `.env`-reading commands into placeholder suggestions (Phase 1). The old `returnedHits` feature that blocked "KeyValet return values being written to files" depended on a user-space plaintext cache and was removed on 2026-10-09 — that capability is no longer promised. What hooks cannot do is written into the docs: some Codex shell paths, Copilot's timeout-allow behavior, nested invocations. The core guarantee always comes from `proxy_only`.

### 5.3 CLI

```
keyvalet run -- <cmd>          run a command with placeholder env vars the transparent proxy swaps out (§5.4)
keyvalet exec <cred> -- <cmd>  inject a single credential into a child process (export_file / env, needs approval)
keyvalet proxy [--port]        start the transparent proxy, print the env vars to set
keyvalet scan [paths]          scan .env, ~/.claude.json, .cursor/mcp.json, ~/.codex/config.toml; import and replace with placeholders
keyvalet hooks install         install runtime hooks
keyvalet pair                  show a QR code, pair a phone
keyvalet policy show|test      show effective policy; evaluate a hypothetical request
keyvalet audit tail|export     audit
keyvalet grant <cred> --hours  pre-authorize (§7.5)
```

### 5.4 Transparent HTTPS proxy (Phase 2, opt-in)

- **Client authentication**: `keyvalet run -- <cmd>` generates a session token for that run and writes `HTTPS_PROXY=http://<token>@127.0.0.1:8788` into the child process; the proxy refuses connections without a token or with a mismatched one; the token expires with the session. Without this step, any local process could borrow the proxy to get injection.
- **CA ownership**: the CA private key is generated and held by the helper; at proxy startup the helper issues short-lived (24h) leaf certs for the session's bound hosts — leaf private keys only exist in the proxy's memory. User-space malware cannot read the CA key, so it cannot MITM other traffic.
- **Only two injection triggers**: a `${KEYVALET:type/name}` placeholder appears in the request, or `keyvalet run --inject <cred>` explicitly designates a credential and host for the session. No "auto-inject by host".
- Env vars (`NODE_USE_ENV_PROXY=1`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`) are set by `keyvalet run` on the child process only — the user's global environment is untouched.
- The proxy does TLS termination only for session-bound hosts; other domains pass through CONNECT undecrypted. HTTP/1.1 first, h2 passes through, gRPC injection comes later.
- The proxy never holds plaintext: once a request matches an injection rule it is handed to the helper over IPC for execution (same path as the gateway).
- Known pitfalls are documented: Octokit doesn't read proxy vars; Go 1.27 disables the system verifier when `SSL_CERT_FILE` is set; tools that ignore proxy vars need Claude Code `/sandbox` network isolation.

### 5.5 SDK gateway

The existing `GatewayOpen` stays: open a local HTTP endpoint for a single credential; SDKs point at it via `OPENAI_BASE_URL`; streaming supported; peer-uid check; treat the URL as a session cookie. Phase 1 folds it into the unified `Deliverer::ProxyExecute`.

### 5.6 Remote MCP endpoint (Phase 4)

See §10.4. Cloud agents like ChatGPT and the Claude app connect to `https://<server>/mcp` over OAuth 2.1 (Ory Hydra as the authorization server); the tool set matches local, and the executor is chosen by routing (§9).

---

## 6. Policy engine (Phase 1)

### 6.1 Risk tiers

| Tier | Default classification | Default decision |
| --- | --- | --- |
| T0 read-only | GET/HEAD to `allowed_hosts`; MCP tools with `readOnlyHint`; metadata ops like `credential_list` | Auto (audited) |
| T1 write | POST/PUT/PATCH to `allowed_hosts`; `access_token` (non-sensitive credentials); TOTP | Ask (coverable by the four grant modes) |
| T2 sensitive | DELETE; paths matching `/admin|/iam|/billing|/payments|/keys|/users|/secrets`; credentials marked `sensitive`; `credential_get` plaintext; `export_file`; AWS STS into a high-privilege role; over budget | Strong (never covered by Remember) |
| T3 forbidden | host not in the allowlist; private/loopback/link-local IPs; non-HTTPS; response is a binary containing a secret | Deny |

### 6.2 Rule sources and merging

```
Precedence (high → low):
  org policy (Team, distributed by the server, can only tighten or set floors)
  user policy (~/.config/keyvalet/policy.yaml)
  repo policy (<repo>/.keyvalet/policy.yaml, can only tighten, never loosen)
  built-in defaults
Merge rule: for a given request take the strictest decision; Deny > Strong > Ask > Auto; budgets take the minimum.
Repo policies come from untrusted directories — any "loosening" entry is ignored and audited.
```

### 6.3 Rule syntax

See Appendix B. Match fields: `credential`, `host`, `method`, `path` (glob), `runtime`, `repo`, `time` (time windows), `tier`; actions: `auto | ask | strong | deny`; budgets: `calls_per_hour`, `calls_per_day`, `bytes_per_day`.

### 6.4 Recommending rules from history

Local helper statistics (no plaintext): if credential × host × method was approved N consecutive times with no denials, the next prompt offers "always allow read-only requests for this"; accepting writes into the user policy. Only T0/T1 downgrades from Ask → Auto are recommended — never T2.

---

## 7. Approval subsystem

### 7.1 What the approval UI shows

Every prompt (Touch ID copy, TTY, phone) uniformly shows: credential name, the agent-stated purpose, **the real request**, runtime and repo, risk tier, and the grant scope for this approval (this once / this credential this session / N hours). "Real request" prefers a human-readable summary generated from the template's `summarize` rule (e.g. OpenAI: `POST chat/completions · model=gpt-5 · 2.1 KB · first 80 chars…`; GitHub: `DELETE repos/x/y`); templates without a rule show method, host, path, and body size. Hashes go to audit only — never shown to people.

### 7.2 Request normalization and digest

```
canonical = JCS(RFC 8785) of {
  v: 1, credential, action.kind, method, host(lowercase), path(normalized), query_keys(sorted),
  body_sha256, headers_digest(name list of non-credential headers only), agent.runtime, agent.repo, purpose, nonce, exp
}
digest = SHA-256(canonical)
```

The approval signature covers `digest || nonce || decision || scope`. The executor recomputes the digest before executing — any field change mismatches.

### 7.3 One-time nonces

Local SQLite table `nonces(nonce, digest, used_at, exp)`; `INSERT OR FAIL` before execution; expired entries are cleaned up. For remote approvals the nonce is generated by the requester — the relay is not involved.

### 7.4 Approver implementations

| Impl | Phase | Quick | Strong | Notes |
| --- | --- | --- | --- | --- |
| `touchid` | current | yes | yes | wraps the existing `touch_id_gate` (cooldown, locking) |
| `tty` | 1 | yes | no | Linux without GUI: prints the request digest on the controlling terminal and requires typing a confirmation code; T0/T1 only. Security statement: it shares the user session with the agent — it protects against agent misuse, not against a compromised agent; on Linux the only Strong approval is the phone (Phase 3) |
| `remote-phone` | 2 | yes | yes | pushed to the iPhone via relay; Quick = lock-screen action (device-unlock gate, not a biometric key); Strong = opening the app with Face ID |
| `auto` | 1 | — | — | when policy decides Auto, produces a self-signed "approval" audited as `auto` |
| `team` | 3 | yes | yes | routes to the credential owner's phone; N-of-M for sensitive credentials |

Selection order: local GUI present and the credential doesn't require the phone → `touchid`; no GUI → paired phone → `remote-phone`; otherwise `tty` (Quick only); Strong required with no Strong-capable approver → deny with an explanation.

### 7.5 Pre-authorization capability tokens

For unattended use (CI, overnight jobs):

```json
{
  "iss": "device:ab12…",          // issuing device (Mac or iPhone)
  "sub": "user:…",
  "act": { "sub": "agent:ci/github/owner/repo" },
  "aud": "executor:*",
  "authorization_details": [{
    "type": "keyvalet:credential",
    "credential": "openai/default",
    "hosts": ["api.openai.com"], "methods": ["POST"], "paths": ["/v1/chat/completions"],
    "budget": { "calls": 500, "per": "24h" }
  }],
  "nbf": 1760000000, "exp": 1760086400, "jti": "01J…"
}
```

ES256, signed by the device key; the executor verifies the signature, checks the scope, and debits the budget; revocation uses the local and server `revoked_jti` lists. The token itself contains no secrets — it only says "may be used"; the key stays in the vault or is unwrapped via KMS (§11.4).

### 7.6 Precise definition of grant scope

The four grant modes decide "whether the next similar request skips approval" — the scope must be precise, otherwise digest binding only protects the first request:

```
grant = { credential, max_tier: T1, allowed_hosts(from credential http.allowed_hosts), methods(the policy-allowed set), budget, until, mode }
coverage check: same credential AND tier ≤ T1 AND host ∈ allowed_hosts AND method ∈ methods AND budget not exceeded → skip approval, audit records grant_id
T2: never covered by any grant — each request re-binds its digest and requires Strong
Remember: only stretches `until`; changes none of the rules above
```

`per_use` produces no grant; `per_credential` produces one lasting until the session ends; `per_session` produces one per credential for the session; `remember` produces one lasting until `until`. Prompt throttling: concurrent T0/T1 requests for the same credential within 30 seconds merge into one approval, implemented as a temporary grant with `until = now + 30s`; T2 never merges.

---

## 8. Keys, identity, and vault format

### 8.0 Platform support and protection boundaries

Per Product §1.4: ship macOS Secure Enclave local master-key protection first; the next phase focuses on Linux / CI calls and identity integration, with TPM optional; a Windows TPM + Hello local client is scheduled against concrete demand; cloud isolated execution prefers AWS Nitro Enclaves + KMS. VBS Enclaves, SGX, and Azure / GCP keep only extension interfaces for now.

Device identity keys (§8.1) and the vault decryption key (§8.2) are described separately. A non-exportable device private key does not automatically give a UMK, CEK, derived AES master key, or credential plaintext inside an ordinary process the same hardware protection.

- **Local hardware protection**: first verify user-session / Keychain context, hardware operations, and authentication constraints in a spike that never touches the real vault, then implement an explicit migration. If a fixed AES master key is derived via ECDH + HKDF and handed to the helper, the guarantee stops at "the hardware private key is non-exportable" — after intercepting one derived master key, offline decryption works until rotation. `Zeroizing` and `mlock` reduce residue and paging; they are not an isolation boundary against a compromised root / kernel.
- **Linux / CI**: the caller may hold only a constrained identity plus capability tokens, while an online Mac helper or a later isolated executor holds and uses the long-term credentials — routing in §9. Pairing and the relay are prerequisites for the remote path; a local Linux helper is the compatibility path — after remote approval, returning the key to an ordinary helper adds no runtime isolation.
- **Isolated execution**: use the §9 `Executor` to perform approved operations instead of returning master-key bytes to the caller. Authorization checks, vault/credential decryption, signing, token exchange, credential injection, TLS, and response redaction all happen inside the trusted execution environment; only policy-permitted results leave it. The KMS `Recipient` path and policy governance are in §11.4.
- **Compatibility and recovery**: macOS supports Secure Enclave only — if the hardware is unavailable, setup and access stop; later platforms like Linux may offer an explicit software-protection option per platform decision, and hardware-access failure must never silently degrade. Machine migration, backups, hardware damage, and recovery are verified before migration ships; the recovery code and other devices' wraps are independent decryption paths whose threat model cannot be skipped.

**2026-10-09 first landing:** the `kv-vault::MasterKeyProvider` interface works with `kv-platform::enclave`, and hardware operations run in a fixed, root-owned `kv-touchid` subprocess; after clearing the environment it drops privileges — `setgroups(1, &gid)` + `setgid` + `setuid` leave the subprocess holding exactly the `SUDO_UID` / `SUDO_GID` identity and a single supplementary group (uid 0 / gid 0 targets are refused; `kv-touchid` itself exits immediately if started as root or wheel). CryptoKit's `SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation` is a device-bound encrypted representation that can live in the `master_key` metadata of `vault.enc` — no persistent Keychain item needed. A minimal Swift C-ABI bridge carries that Swift API; everything else — vault, policy, IPC, process management — stays in Rust. The permanent Security Keychain item spike returns `errSecMissingEntitlement` under the current ad-hoc signing; the encrypted-representation approach passes under the same signing conditions.

Hardware P-256 ECDH + HKDF-SHA256 derives a fixed AES key using the `userPresence` ACL, `WhenUnlockedThisDeviceOnly`, and a fresh `LAContext` per subprocess; authentication is handled by the system. The recovery passphrase derives a wrapping key via Argon2id (64 MiB, three passes, parallelism 1, 16-byte random salt) and encrypts the AES master key with AES-256-GCM. Hardware metadata and the recovery wrap bind to the vault's AEAD additional authenticated data; ciphertext and metadata live in the same file and commit together via fsync + rename — no two-file commit gap.

macOS currently supports hardware mode only: the installer ends existing helper / MCP sessions first, then runs `setup-enclave`; the root CLI reads an independent recovery passphrase directly through a hidden terminal or native input box — the passphrase never passes through the installer or an agent. New vaults initialize the hardware key directly; old vaults keep read-only code for the file key used only during migration — file keys are no longer generated, and the helper and normal CLI operations reject the old mode. `migrate-to-enclave` remains as a command alias; `protection`, `enclave-test`, `recover-vault`, `finish-enclave-migration` are also provided, plus the hardware-free `recovery-check` / `recovery-read` (read-only, see the re-review below). Initialization, migration, and recovery all verify the new hardware key can be re-derived in an independent subprocess before committing. Migration no longer produces `vault.migration-backup.enc` (it would be byte-identical to the new `vault.enc`, no rollback value); backups left by old versions are deleted by `rotate-recovery`, `recover-vault`, or `finish-enclave-migration`; the old file key is deleted after the commit succeeds; old sessions detect the metadata change and refuse reads and writes. `remember` does not skip the hardware session unlock; per-credential / per-use modes still authorize each concrete use after unlocking.

Verified on this machine (macOS 26.5.1 / arm64, ad-hoc hardened-runtime signing): normal-user creation and cross-process derivation pass; root running under the user's GUI bootstrap / security audit session passes migration, re-unlock, recovery, and old-session invalidation on a temporary vault. Directly launching via an AppleScript administrator session once returned LocalAuthentication `-1000` (UI connection dead); the test harness passed after entering the user session via `launchctl asuser`. That switch is only for the standalone test harness — the production path is launched by the user session through sudo. Unauthenticated graphical sessions, T2 devices, password fallback on fingerprint-less devices, and cross-OS-update behavior still need the release matrix. Day-to-day CI skips interactive hardware tests.

Same-day acceptance of the production install path on this machine passed: the installer completed master-key rotation and migration on the real `/var/db/keyvalet` vault via sudo, deleted the old file key and the old install; the latest root helper opened a session with one fresh hardware authentication, successfully listed 6 credentials, protection status `secure_enclave`, recovery configured, old file key absent. Acceptance recorded counts and protection status only — no credential values were read or printed; see the on-machine acceptance record after Action Guide §1.6.

**2026-10-09 re-review and corrections:**

- **The encrypted representation binds only the device.** Apple DTS corrected this in 2026-05: `dataRepresentation` does not bind the App ID, Team ID, or code signature — any process on the same device (including unsigned ones) that obtains it can load it, while the SEP still enforces `userPresence` per use. Its confidentiality therefore depends on the vault file's root-only permission; `protection`, session state, and audit never output it. A compromised root can initiate derivation at any time with arbitrary authentication copy, and one approval yields the fixed AES master key — consistent with "root is not in the threat model", but it must not be written as "exposed only during legitimate unlocks".
- **Runtime context.** Apple DTS explicitly does not support SE or the Data Protection Keychain in `launchd` daemons. Today `kv-touchid` runs de-privileged from a root process launched via sudo — its uid, bootstrap, and security audit session are all inherited from the user's GUI session, identical to a command the user runs in a terminal: it counts as user context. The resident Unix-socket helper (implemented as the `dev.keyvalet.helper` daemon) cannot do SE operations directly; they are handed to `dev.keyvalet.agent`, a per-user LaunchAgent in the user's login session, and the daemon validates its identity by audit token + code requirement before trusting its answers.
- **Contingency when SE is unavailable.** `recover-vault` needs to create a new SE key on the machine; if a system update or similar breaks the SE path, it cannot complete either. New: `recovery-check` (no hardware — verifies the recovery passphrase can decrypt and shows the record count) and `recovery-read <types|list|get>` (root CLI opens read-only with the recovery passphrase; writes and old-key deletion are refused; audited as `recovery_passphrase_read_only`). The helper does not accept this mode, so it is not a runtime software fallback; after moving to a healthy Mac, `recover-vault` still works.

- **Device binding (implemented 2026-10-09).** For newly set-up, migrated, recovered, or rotated vaults: master key = HKDF-SHA256(ikm = SE-derived key, salt = root-only 32-byte `device-binding-<id>.key`, info = `keyvalet/master-key/device-binding/v1`). Every key change (init, migrate, recover, rotate) creates a new digest-named binding file and deletes the old file after commit (the old fixed name `device-binding.key` is still readable); afterwards, older `vault.enc` copies on the machine need the recovery passphrase to decrypt; deleted files may persist until existing APFS local snapshots expire. The Time Machine exclusion is set before the secret is written; `keyvalet protection` reports `binding_excluded_from_backups` (third-party backup tools don't honor the exclusion); its SHA-256 digest goes into AEAD-authenticated metadata, and a missing or replaced file errors before any prompt. This makes a vault copy (backup, snapshot) plus one approved prompt insufficient to decrypt; root can still read both — the root boundary is unchanged. The recovery wrap wraps the final master key, so recovery onto a new machine doesn't need the binding file. Old unbound vaults keep working, `protection` shows `device_binding: false`, and `setup-enclave` suggests running `rotate-recovery`.
- **Changing the recovery passphrase (`rotate-recovery`).** After hardware-unlocking the current vault, rotate the SE key, master key, and recovery passphrase together, and enable device binding. Re-wrapping the old master key alone cannot revoke the old passphrase — anyone who already opened the wrap with the old passphrase still holds the same master key, so the master key must rotate. Vault copies made before rotation still decrypt with the old passphrase.

### 8.1 Device identity keys

| Platform | Implementation | Notes |
| --- | --- | --- |
| macOS | Encrypted representation of a CryptoKit `SecureEnclave.P256` private key — same as the §8.0 master key — stored in a root-only file; no persistent Keychain item (`kSecAttrTokenIDSecureEnclave` + Keychain returns `errSecMissingEntitlement` under ad-hoc signing, see §8.0) | Non-exportable; signing and ECDH. The encrypted representation binds only the device — confidentiality depends on file permissions. A key without `userPresence` for unattended relay signing can be silently used by root; it must be separate from `userPresence`-gated approval keys |
| Linux | Optional TPM 2.0 via `tss-esapi` (P-256 device key) | TPM has no "user presence": without an authValue, on-machine root (and the `tss` group with access to `/dev/tpmrm0`) can silently use it; setting a PIN amounts to a passphrase plus TPM anti-hammering; binding PCRs can break unsealing after kernel / firmware updates, needing re-sealing or the recovery path. TPM only protects against copying the vault elsewhere for offline decryption — weaker than macOS SE + `userPresence`. Without TPM, explicitly enable the software compatibility option — `0600`, state and audit marked `software_key`; once TPM is enabled, access failures do not automatically fall back to the software key |
| Windows (scheduled on demand) | Candidates: Windows Hello `KeyCredential` (RSA-2048, signs after system-UI auth) or the NCrypt Platform Crypto Provider (TPM) | Two known ways to bind Hello to key derivation: sign a fixed challenge and use SHA-256 of the signature as the wrapping key (KeePassXC's approach — relies on RSA PKCS#1 v1.5 being deterministic); or `RequestDeriveSharedSecretAsync` on build 26100+. NCrypt / TPM provide hardware binding but not Hello binding. Windows services run in session 0 and cannot show Hello — an agent process in the user's interactive session is needed. Caller isolation and offline fallback both need feasibility verification; no VBS Enclave isolation is assumed |
| iPhone | two SE P-256 keys: `quick` (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no biometric ACL), `strong` (`.biometryCurrentSet`) | SE keys don't sync over iCloud — every device registers separately |
| enclave | P-256 generated at boot, public key goes into the attestation document | destroyed when the process exits |

All signatures are ES256; all end-to-end encryption uses HPKE (RFC 9180) `DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM`, consistent with the SE's ECDH capability.

### 8.2 Key hierarchy

```
device keys DK_i (per device)
UMK (random 256-bit) ──┬── wrap(DK_mac)      ─┐
                       ├── wrap(DK_iphone)   ─┤ stored locally + server (ciphertext)
                       ├── wrap(DK_linux)    ─┤
                       └── wrap(K_recovery)  ─┘ K_recovery = Argon2id(recovery code)
CEK_j (per credential) ── AES-256-GCM wrapped by UMK
credential ciphertext ── AES-256-GCM(CEK_j)
```

Adding a device: a registered device unwraps the UMK, re-wraps it for the new device, and hands it over via the pairing channel (§8.3). Revoking a device: delete its wrap and rotate the UMK (re-wrap every CEK wrap — no need to re-encrypt the credential ciphertext).

### 8.3 Pairing protocol (Phase 2)

```
Mac/Linux                                  iPhone
 generate pairing_token (one-time, 10 min)
 QR code = { relay_url, pairing_token, DK_pub, device_meta }
                              ── scan ──▶
                                            generate/fetch DK_iphone_pub
                                            POST relay /pair { token, pub, App Attest assertion }
 relay forwards ◀──────────────────────────────
 both sides compute safety_code = SHA-256(DK_pub_a || DK_pub_b), take 6 decimal digits
 user confirms the two 6-digit codes match
 Mac HPKE-encrypts wrap(UMK) to DK_iphone, delivered via relay
```

App Attest lets the relay reject registrations from non-official apps; self-built-app users can disable that check (self-hosted relay config).

### 8.4 Vault file format v2

The existing `EncryptedFile` is upgraded to an envelope format:

```json
{ "version": 2,
  "umk_wraps": { "<device_id>": { "alg": "HPKE-P256", "ct": "…" }, "recovery": { "alg": "argon2id+aesgcm", "params": {…}, "ct": "…" } },
  "credentials": { "<type/name>": { "cek_wrap": "…", "ct": "…", "meta": { /* non-sensitive metadata in plaintext: kind, template, allowed_hosts, created_at */ } } },
  "audit_head": "<hash>" }
```

Migration: on first launch as v2, read v1, generate the UMK and device wraps, generate and re-encrypt CEKs one by one, write v2, keep the v1 backup for 30 days. Metadata is plaintext so `list` doesn't need decryption — but before uploading to the server the whole file gets another HPKE layer (including metadata), so the server sees only opaque ids and ciphertext and doesn't learn which services the user uses.

### 8.5 Agent identity

`AgentIdentity` is filled by the helper from `ClientContext` (currently: client name, cwd) and process info, signed by the host device key. In CI (Phase 2, Team v1): a GitHub Actions OIDC token serves as the agent's identity credential — the server or local helper validates `iss/aud/sub` and maps it to a capability token.

---

## 9. Executors and routing

### 9.1 Executor trait

```rust
pub trait Executor: Send + Sync {
    fn id(&self) -> DeviceId;
    fn caps(&self) -> ExecCaps;          // which Action kinds, streaming support, max duration
    async fn execute(&self, sealed: SealedJob) -> Result<SealedResult>; // SealedJob = {UseRequest, Approval/Capability, CEK} HPKE-encrypted to this executor
}
```

### 9.2 Routing algorithm (executed by the requesting helper or the remote MCP endpoint)

```
if the request is local and the local machine can execute   → local, no relay
elif a helper of the user is online in the relay presence    → that helper (approval via local Touch ID or push to phone)
elif the phone is foregrounded and the action is short       → phone (non-streaming, < 20 s estimate)
elif the org has the CI offline-execution add-on and an      → enclave (Phase 4; approval via phone or capability token)
     enclave is available
else                                                        → DEVICE_OFFLINE (with the add-on hint)
```

The presence table is maintained by the relay's WebSocket heartbeats; routing decisions go into audit.

### 9.3 Streaming and long requests

Local and enclave support streaming (SSE/chunked); the phone does not (30 s background limit); the remote MCP endpoint forwards upstream streaming responses to the cloud agent in chunks.

---

## 10. Server side: relay, remote MCP endpoint, team, and billing

### 10.1 Technology choices

Rust (axum + tokio), Postgres (SQLite for self-hosted), no Redis (presence and queues use Postgres LISTEN/NOTIFY), Caddy or ALB for TLS. Single binary `kv-server` with feature flags: `relay`, `team`, `billing`, `console` (Web console, Phase 2), `remote-mcp` (Phase 4). The OAuth 2.1 authorization server is **not self-built**: use Ory Hydra (open source, deployed with the relay in Docker); `kv-server` only implements the login/consent pages and the resource server; OIDC SSO also goes through Hydra's federated login.

### 10.2 Users and account model

| Tier | Identity | Recovery |
| --- | --- | --- |
| Free | pure device identity: the first device's registration creates an anonymous account, later devices join via pairing; no email | recovery code + any registered device |
| Team | org account created via email magic link, bound by device signature; invited members log in by email and register devices | same; owner can revoke member devices |
| Remote MCP (Phase 4) | Hydra-issued OAuth tokens bound to {user, agent client_id}; user login via device authorization (confirmed on a paired phone) | — |

The only user data the server stores: emails (Team), device public keys, entitlements, opaque blobs.

### 10.3 relay (Phase 2)

The relay's client is the user-space `kv-relay-client` process — the helper never touches the network; when it needs a device signature it asks the helper over IPC and never holds the private key.

| Function | Design |
| --- | --- |
| Device registration | `POST /v1/devices`: public key, kind, capabilities, push token (iPhone only), App Attest assertion |
| Presence | `WS /v1/presence`: `kv-relay-client` and the app hold a long connection, 30 s heartbeat; entries `{user, device, caps, last_seen}` |
| Pending-approval queue | `POST /v1/approvals`: the requester uploads a blob HPKE-encrypted to the target approval device + metadata (id, expiry, target device only); default TTL 5 minutes |
| Approval reply | `POST /v1/approvals/{id}/reply`: the approval device uploads the Approval encrypted to the requester |
| Wake (Phase 3) | relay sends `{device_push_token, approval_id}` to `kv-push`; `kv-push` sends APNs (`mutable-content:1`); the NSE pulls the blob from the relay and decrypts it for display (within 30 s) |
| Ciphertext storage | `PUT /v1/blobs/{id}`: vault ciphertext (with encrypted metadata), UMK wraps, shared-CEK wraps; the server doesn't know what the keys mean |
| Rate limiting | approval requests per device per minute; blob capacity per user; fair-use quota for Free |

E2E message envelope: `{ v, from_device, to_device, hpke_enc, ciphertext, sig }` — the signature covers the ciphertext; the relay only checks that the `from_device` signature is valid and belongs to the same user or org.

### 10.4 Remote MCP endpoint (Phase 4)

- Follows the MCP authorization spec 2026-07-28: publish the PRM at `/.well-known/oauth-protected-resource`; the authorization server is Ory Hydra (OAuth 2.1 + PKCE, `resource` parameter required, `iss` checked); client registration prefers CIMD (a client metadata document hosted on `keyvalet.dev`), with Hydra's DCR as fallback.
- User login: device authorization (scan a code, confirm on a paired phone) — no passwords; Team users can use SSO.
- Access tokens bind `{user, agent client_id, scopes}`; each tool call becomes a `UseRequest`, routed by §9 to an executor; the endpoint itself holds no keys.
- Cloud agents' tool calls usually time out at 60 s — approval latency must stay under 30 s; session-level grants or capability tokens are recommended over per-call phone approvals.
- Streaming tool output is forwarded over HTTP chunked.

### 10.5 Team module

See §14.

### 10.6 Billing module (Phase 2)

- Stripe Checkout and Customer Portal; webhooks update `entitlements(user|org, tier, seats, addons, valid_until)`.
- The server issues **entitlement tokens** (ES256, 7-day validity) to devices; the helper caches and verifies them offline — a network outage doesn't break paid features for 7 days.
- Metering: machine-identity count (only for fair-use checks, not billed); enclave executions (Phase 4) reported daily by the parent instance, overage at $0.5 per thousand.

### 10.7 Deployment and hosting locations

| Mode | Composition | Notes |
| --- | --- | --- |
| A self-hosted | `docker compose`: kv-server, hydra, postgres, caddy | one-command script; `KV_RELAY_PUSH_GATEWAY` can point to a self-hosted push gateway or be disabled |
| Official instance | same as A, deployed in the US (us-east-1 or a US VPS), operated by the overseas entity | a trust requirement for US developers; hosting domestically in China would be a red flag even with only ciphertext |
| B AWS (Phase 4) | kv-server on ECS; RDS Postgres; ALB; plus the enclave executor (§11) | the same Terraform works for customer BYO accounts |

`kv-push` is deployed separately in the US and holds only the APNs key; its interface is `POST /wake { push_token, approval_id }` and accepts no other fields.

---

## 11. Nitro enclave executor (Phase 4)

2026-10-09 decision: the first cloud isolated-execution option; the precondition is a team showing demand for device-offline or unattended execution. This phase implements only the AWS path — other clouds are added per customer demand. The protection boundary includes the parent instance's root; the Nitro platform, enclave code, and KMS policy governance are still trusted; no absolute non-extractability is promised.

### 11.1 Composition

```
EC2 c7g.large (parent instance, untrusted)            Nitro enclave (kv-enclave)
  relay client (present online as an executor device)   NSM fetches the attestation document
                                                        (ephemeral public key + nonce)
  vsock-proxy (allowlist: relay, KMS, upstream APIs)    HPKE-opens the SealedJob → gets the CEK
  kmstool proxy (IMDS credentials relayed to enclave)   decrypt credential → inject → direct TLS
                                                        to upstream (via vsock L4 forwarding)
  usage reporting                                       Guard redaction → result HPKE-encrypted
                                                        to the requester → destroy the CEK
```

The parent instance sees only TLS ciphertext and the enclave's encrypted output.

### 11.2 Remote attestation

- After boot the enclave generates two ephemeral keys and requests an NSM attestation document: `public_key` = an ephemeral **RSA** public key for KMS (the KMS `Recipient` `KeyEncryptionAlgorithm` only supports `RSAES_OAEP_SHA_256`, see §11.4); `user_data` = an ephemeral HPKE P-256 public key the requester uses to seal the CEK; `nonce` distributed by the relay. The document is uploaded to the relay. Both private keys exist only in enclave memory.
- Before first sending a job to a given enclave, the requester (Mac helper or iPhone) verifies: COSE_Sign1 signature → certificate chain to the AWS Nitro root (pinned fingerprint) and validity → `PCR0` in the allowlist → takes the HPKE public key from `user_data`. Only after verification passes does it HPKE-encrypt the CEK to it.
- The relay-distributed `nonce` provides no freshness guarantee against the relay. Confidentiality comes from the signed binding of PCRs to the ephemeral public key: if the relay replays an old document, the worst case is the requester encrypts to a destroyed key — a denial of service, not a CEK leak.
- Implementation: Rust uses `aws-nitro-enclaves-cose` + `x509-cert`; Swift uses SwiftCOSE + swift-certificates + CryptoKit P384 (about 1–2 weeks of work).

### 11.3 Reproducible builds and PCR publishing

- Build the Docker image with kaniko `--reproducible` or Nix (monzo/aws-nitro-util), then `nitro-cli build-enclave` produces the EIF; the same image yields identical PCRs.
- Every release: build in CI, record `PCR0/1/2`, sign and publish to `https://keyvalet.dev/attestation/pcrs.json` and the GitHub Release.
- **The client's PCR0 allowlist ships with the client binary and is never updated online**: switching enclave versions requires a client update — the operator cannot unilaterally make clients accept a new image. A Phase-4 alternative to evaluate: the allowlist is signed by both Simvito Limited and an independent auditor and distributed online.
- Debug-mode enclaves (all-zero PCRs) are never accepted by clients.

### 11.4 Two key-retrieval paths and their trust statements

| Path | Scenario | Mechanism | Whom you trust |
| --- | --- | --- | --- |
| Online approval | phone or Mac present | the approving device unwraps the CEK, HPKE-encrypts it to the verified enclave public key, sends it with the job | enclave code (PCRs) + AWS Nitro; the operator cannot get the CEK |
| Pre-authorized, BYO-KMS (default) | all devices offline; the customer's own AWS account holds the KMS key | the user device encrypts the CEK directly with `kms:Encrypt` (32 bytes — not the plaintext-returning `GenerateDataKey`); the ciphertext sits on the relay; the key policy follows the template below and only allows `kms:Decrypt` with a matching attestation document; the enclave calls `kms:Decrypt` with `Recipient{AttestationDocument, RSAES_OAEP_SHA_256}` and gets a `CiphertextForRecipient` encrypted to the RSA key in the document — openable only inside the enclave; the job must carry a valid capability token (§7.5) | the customer's own AWS account governance + enclave code |
| Pre-authorized, managed KMS (optional) | customer has no AWS account | same, but the KMS key lives in Simvito Limited's AWS account | **Simvito Limited's AWS account governance**. Account admins could change the key policy, drop the attestation condition, and directly decrypt CEKs stored on the relay. This is stated explicitly in product and docs — not written as "only attested enclaves can decrypt" |

Managed-KMS mitigations: a dedicated AWS account, minimal admins, CloudTrail alerts on key-policy changes with a public digest, capability tokens still signed by user devices (scope and budget constrained), BYO-KMS as the default recommendation.

**Key policy template (mandatory for both BYO-KMS and managed KMS — the deploy tool validates before enabling).** AWS's default key policy grants the account `kms:*` and lets IAM policies authorize — in that state the parent-instance role (holding IMDS credentials) or any principal granted `kms:Decrypt` via IAM can decrypt CEK plaintext directly without a `Recipient`. The template requires:

1. Admin statements must not include `kms:Decrypt` or `kms:ReEncrypt*` (e.g. use `NotAction`), and must not keep the default account-level `kms:*` statement.
2. Allow `kms:Decrypt` only for the enclave role, conditioned on `kms:RecipientAttestation:ImageSha384 = <PCR0>` (optionally add `PCR8` to bind the EIF signing certificate). Without an attestation document the condition fails.
3. Explicit Deny for all principals: `kms:Decrypt` when `kms:RecipientAttestation:ImageSha384` is missing (`Null`) or mismatched; unconditional Deny on `kms:ReEncrypt*` — prevents re-encrypting the ciphertext to another attacker-controlled key and decrypting there. Explicit Deny also overrides IAM policies and grants.
4. The device principal sealing the CEK gets only `kms:Encrypt`; the encryption context binds `{org, credential_id}`, and the enclave must present the same context when decrypting.
5. `PutKeyPolicy`, `CreateGrant`, `DisableKeyRotation`, and similar changes go into CloudTrail alerting. Someone who can modify the key policy can still delete those Denys — that is what "account governance" in the table means.

The enclave never gets the UMK — only the single CEK of a single job.

### 11.5 Capacity, cost, and availability

- A c7g.large has only 2 vCPUs: Graviton has no hyperthreading, the parent keeps at least 1 vCPU, so the enclave gets at most 1; the allocator defaults to reserving 2 vCPUs — change it to 1. "Hundreds of concurrent" is not yet measured — load-test a 1-vCPU enclave before launch; if insufficient move to c7g.xlarge and recompute cost. Auto Scaling group fixed at 1–2 machines, Spot-first with on-demand fallback; c7g.large on-demand ≈ $53/month/machine, ~$35–38 with a 1-year Savings Plan.
- Enclaves are stateless and replaceable at any time; unchanged PCRs mean clients need no re-trust.
- Upstream timeout 60 s; streaming max 10 minutes.

---

## 12. Audit

### 12.1 Entries

```json
{ "seq": 1842, "ts": "2026-10-08T03:12:45Z", "prev": "<sha256>", "hash": "<sha256>",
  "event": "use", "credential": "openai/default", "kind": "static",
  "agent": { "runtime": "claude-code", "version": "2.1.3", "repo": "github.com/x/y", "cwd_hash": "…" },
  "action": { "type": "http", "method": "POST", "host": "api.openai.com", "path": "/v1/chat/completions", "body_sha256_8": "a1b2c3d4" },
  "purpose": "Summarize meeting notes", "digest_8": "9f8e7d6c",
  "policy": { "tier": 1, "decision": "ask", "rules": ["user:openai-write"] },
  "approval": { "kind": "quick", "approver": "device:iphone-…", "mode": "per_credential" },
  "executor": "device:mac-…", "upstream": { "status": 200, "bytes": 4120, "ms": 812, "redactions": 0 },
  "trace": { "traceparent": "00-…" } }
```

`hash = SHA-256(prev || JCS(entry without hash))`; every 100 entries the device key signs a checkpoint. Plaintext, tokens, and full URL query values never enter audit.

### 12.2 OTel mapping

When exporting OTLP, map: `gen_ai.tool.name` ← MCP tool name; `gen_ai.agent.name` ← runtime; `gen_ai.tool.call.id` ← MCP call id; keep the MCP `_meta.traceparent`. Custom fields live in the `keyvalet.*` namespace. The conventions are still Development — keep the mapping layer in its own module to track them easily.

### 12.3 Team sync

Entries are encrypted with the org audit key (HPKE to the org's set of audit devices) and uploaded to the server; the server only stores and exports by time; SIEM export decrypts on the client or an org audit device and pushes (Team v1 in Phase 2 offers JSONL and OTLP).

---

## 13. Storage backends and import

### 13.1 Backends

| Backend | Phase | Read | Write | Notes |
| --- | --- | --- | --- | --- |
| `local` | current | yes | yes | vault v2 |
| `keychain` | 2 | yes | yes | macOS Keychain items; optional `kSecAttrSynchronizable` via iCloud (credential ciphertext only — no SE keys) |
| `onepassword` | 2 | yes | no | `op` CLI; stores `op://vault/item/field` references, read live at use, not cached; requires an unlocked 1Password |
| `bitwarden` | 3 | yes | no | `bw` CLI, needs a `bw unlock` session |
| `infisical` | 2 | yes | no | API; can consume its dynamic secrets directly |
| `github-oidc` | 2 | yes | — | CI: OIDC token → capability token; stores no static values |

`StorageBackend.load` returns `Sealed`: local backends return ciphertext, external backends return a "handle" — decryption or reading happens only inside the Issuer.

### 13.2 Reference syntax

`keyvalet://<type>/<name>` refers to a vault credential; `op://…` passes through to the 1Password backend; the `${KEYVALET:type/name}` placeholder is used in files and env vars.

### 13.3 `keyvalet scan`

Scan targets: `.env*`, `~/.claude.json`, `~/.claude/settings*.json`, `.cursor/mcp.json`, `~/.cursor/mcp.json`, `~/.codex/config.toml`, `~/.config/grok/*` (to verify), `export` lines in shell rc files.
Flow: regex + template `test` request to verify validity (with user confirmation) → native window for selection → helper writes into the vault → the original file is rewritten with placeholders → the backup is deleted reusing the `delete_source_file` confirmation flow. Plaintext never passes through MCP or the model context.

---

## 14. Team features

### 14.1 Team v1 (Phase 2, no phone required)

| Feature | Design |
| --- | --- |
| Orgs and members | email magic link creates an org; tables `orgs`, `members(role: owner/admin/member)`, `devices`; invite links; members register devices |
| Shared credentials | ciphertext uploaded to the relay by the owner; the CEK is wrapped once per authorized member's device public key; members approve use on their own Mac/Linux with local Touch ID / TTY; removing a member deletes their wrap and rotates the CEK |
| CEK wrapping for new members | one of two (decided in Phase 2): A — any online holder device confirms and re-wraps, zero-knowledge but with friction; B — an org-managed device (a resident helper) holds the org CEK and wraps on behalf — low friction but it holds the key, must be explicit in product. Default A; B is a full-Team option |
| Org policy | admins maintain the policy file, distributed signed by the server; member helpers merge it at the highest precedence (tighten-only) |
| CI identity | GitHub Actions OIDC → server validates → issues capability tokens (scope limited by org policy) → executes on a member's online device or a self-hosted executor; no static secrets in CI |
| Audit export | entries encrypted to the org audit-device set; export JSONL / OTLP |
| Billing | per seat; machine identities unmetered (fair use) |

### 14.2 Full Team (Phase 3)

| Feature | Design |
| --- | --- |
| Approval routing | T1/T2 requests on shared credentials push to the owner's or a designated approver's phone |
| N-of-M | `sensitive` credentials need multi-person approval like 2-of-3; execution only after Approvals aggregate |
| Strong approvals on Linux / CI | via the phone |
| SSO | OIDC (Okta, Entra, Google) via Ory Hydra federation; SAML based on design-partner demand (Phase 4) |
| 90-day encrypted audit retention | the server stores ciphertext only |
| Credential rotation | templates gain rotation endpoints that periodically rotate the upstream API key and sync to members (end of Phase 3 or Phase 4) |

### 14.3 Add-on: CI offline execution (Phase 4)

See §11 and §15.

---

## 15. Official relay quota and the CI offline-execution add-on

- Free users' fair-use quota on the official relay: 3 devices, 2,000 remote approvals per month, pending approvals retained 7 days; overage prompts joining a Team.
- Team: unlimited managed relay; ciphertext synced across devices; full Team includes 90-day encrypted audit retention.
- CI offline-execution add-on (Phase 4): executes in the enclave when all devices are offline; BYO-KMS by default; metered at $0.5 per thousand calls, 2,000 included per seat per month; the `DEVICE_OFFLINE` error hints at enabling the add-on.
- No individual Cloud SKU; individual offline needs are served by self-hosting a relay or joining a Team.
- Data residency: the official relay is in the US; audit and ciphertext are encrypted with user keys and unreadable by the server.

---

## 16. Security design highlights

| Topic | Design |
| --- | --- |
| Privileged helper | keep the existing root (Mac) model and `verify_root_environment`; on Linux use system user `keyvalet` + systemd service + Unix socket with peer-uid checks on connections; **implemented on Mac in v0.1**: `kv-helper --daemon` is a `launchd` daemon (`dev.keyvalet.helper`) serving sessions over `/var/run/keyvalet/helper.sock`, and SE/prompt work runs in the per-user LaunchAgent `dev.keyvalet.agent` (`kv-touchid --agent`), whose code signature the daemon verifies via audit token (§8.0); the stdin/stdout sudo mode stays for this version as the fallback. The helper never touches the network and holds no long-lived connections; the relay client lives in user space |
| Replay and tampering | digest binding + one-time nonces + expiry; approval signatures cover decision and scope; grant scope precisely defined (§7.6) |
| Clocks | tokens and approvals allow ±5 min skew. The enclave does not trust time from the relay or the parent instance (a compromised relay dialing back the clock would revive expired capability tokens); candidate trusted time sources are the clock Nitro provides to enclaves, or the signed `timestamp` inside the NSM attestation document — verified at implementation time. Relay time is only a sanity check — excessive skew rejects execution |
| SSRF | Guard.before: HTTPS only; refuse private/loopback/link-local addresses; DNS-rebinding defense (resolve then compare); only `allowed_hosts` |
| Redaction | existing `redact.rs` (multiple encoding variants) + binaries containing a secret are refused; redaction fingerprints compare via HMAC — no plaintext kept in user space |
| Transparent proxy | session-token authentication; CA private key in the helper, proxy only gets short-lived leaf certs; injection only on placeholders or explicit `--inject`; users can always `keyvalet proxy uninstall-ca` |
| Lost phone | recovery code + other registered devices; server-side device-key revocation; UMK rotation |
| Revocation | three revocation lists — devices, capability-token `jti`s, shared-credential members; the helper syncs every 10 minutes and falls back to cache offline with shortened token validity |
| Supply chain | minimal Rust dependencies, `cargo-deny`, `cargo-vet`; Sigstore-signed releases; install script verifies hashes; reproducible enclave builds; untrusted Node runtimes refused (current) |
| Hook bypass | documented explicitly: some Codex shell paths, Copilot timeout-allow, nested invocations; the core guarantee is `proxy_only` |
| Server compromise | attacker gets ciphertext, device public keys, metadata (device online times, approval counts, Team emails); cannot forge approvals (no device private keys) and cannot decrypt; remediation: rotate relay tokens, rotate the UMK if needed |
| Managed KMS path | trust is the operator's AWS account governance — stated in product; BYO-KMS default; dedicated account, change alerts, public digests |
| PCR allowlist | ships with the client binary; never updated online unilaterally |
| Malicious user-space process | unchanged from the current SECURITY.md conclusion: malware running as the user can trigger approvals; binding display to the real request and template `summarize` reduce mis-approvals |
| TTY approvals | shares the user session with the agent — protects against misuse, not compromise; T0/T1 only |

---

## 17. Observability and operations

- Helper and server logs contain no secrets and no full URLs; default `info`.
- Server metrics: online device count, pending-approval queue depth, median approval latency, push failure rate, enclave job success rate and duration, Stripe webhook failures.
- Health checks: `/healthz` (liveness), `/readyz` (DB and push gateway reachable).
- Backups: daily Postgres snapshots (all ciphertext and metadata); enclaves are stateless.
- Incident response: the public `SECURITY.md` reporting channel; playbooks for key incidents (relay compromise, PCR leak): revoke the PCR allowlist, force client updates.

---

## 18. Engineering plan

### 18.1 Repo layout (target): a single repo

The official website, Web console, iOS/Android apps, server, helper, plugins, templates, and deploy scripts all live in one repository — directories split by language, CI filtered by path.

```
keyvalet/                         monorepo
  rust/                           Cargo workspace: all Rust crates
    crates/
      kv-core        pipeline, registry, traits, policy engine, approvals, capability tokens
      kv-vault       vault v2, key hierarchy
      kv-protocols   Issuer implementations (existing)
      kv-proxy       Deliverer/Guard: gateway, transparent proxy, redaction, SSRF
      kv-ipc         IPC v4
      kv-platform    device keys (SE/TPM2/software), Authenticator, trust
      kv-touchid     Mac biometric process (existing)
      kv-helper      privileged daemon
      kv-mcp         Rust MCP server (replaces TS from Phase 2)
      kv-hook        shared hook binary + the four RuntimeAdapters + manifests/ (install metadata)
      kv-cli         the keyvalet CLI
      kv-relay-client relay protocol, HPKE sealing, pairing; the only outbound user-space process
      kv-audit       hash chain, OTel mapping, export
      kv-storage-*   keychain / onepassword / infisical / bitwarden
      kv-server      axum server: relay, team, billing, console (Web console, askama + htmx, static assets embedded via rust-embed), remote-mcp
      kv-push        push gateway
      kv-enclave     enclave binary
      kv-ffi         UniFFI bindings → generates the Swift / Kotlin packages
  ee/                source-available commercial license: kv-team, kv-billing, console team pages; compiled into the same binary via kv-server features (boundary in Open-Source Plan §1)
  apps/
    ios/             SwiftUI app (Xcode project; SwiftPM dependency on the KeyValetCore package generated by kv-ffi)
    android/         Kotlin app (Phase 4, same UniFFI path)
    macos/           optional: menu-bar status and settings (Phase 3+); the Touch ID dialog stays in kv-touchid
    web/             Web console frontend assets (TypeScript: WebCrypto device keys, HPKE, htmx extensions), build output embedded in kv-server
  site/              official website (Zola static site, zh/en): landing, docs, pricing, comparisons, downloads, security page, blog, template catalog, attestation/pcrs.json, CIMD documents
  claude-plugin/     Claude Code plugin (hooks → kv-hook, skills, commands)
  templates/         template catalog (the helper and the site's template page share one JSON)
  deploy/            docker-compose, Terraform (EC2 + enclave + KMS), Nix/kaniko builds, Caddyfile
  scripts/           install.sh, uninstall.sh, release scripts (existing)
  docs/              design docs (this document, strategy, ADRs); after site content moved to site/, the GitHub Pages source changes to Actions build output
  .github/workflows/ path-filtered: rust, ios, android, site, server-image, enclave
  justfile           cross-language task entry (build, test, release, site)
```

Current → target: `src/` (TS) is kept during migration; `docs/index.html`, `docs/guide.md`, `docs/install.sh` already moved to `site/` — `docs/` now holds design docs only (this is also the direct reason the GitHub Pages publishing path changed from `docs/` to `site/`, see above); `marketing/` copy will later merge into `site/content/`.

### 18.2 IPC v4

Incremental additions over v3's 24 operations (Appendix F), protocol version 4; the helper accepts v3 clients for one version cycle.

### 18.3 TS → Rust migration (strangler)

1. Phase 0: the TS MCP server stays; the Rust helper replaces the TS helper (in progress), IPC v3 compatible.
2. Phase 1: **features before rewrites**. The policy engine, approval binding, and Linux are all implemented in the Rust helper; the TS server only proxies the new IPC operations; hooks switch to `kv-hook` + adapters, and `claude-plugin/hooks/run.sh` only forwards.
3. Phase 2: `kv-mcp` (Rust) ships; once it reaches feature parity with the TS server, the install script defaults to Rust; TS stays for one version.
4. Phase 3: TS code leaves the default build.

### 18.4 Testing strategy

- Unit: policy merging, digest normalization, nonces, HPKE sealing, redaction fuzzing (`cargo-fuzz`).
- Integration: fake runtimes (recorded Claude Code/Codex/Cursor hook events replayed), fake upstreams (wiremock), fake relay.
- End-to-end: smoke with real runtimes (launch the Claude Code/Codex/Cursor CLIs in CI and run scripts); real Nitro in a nightly job.
- Security: SSRF case tables, replay cases, grant-mode matrix (4 modes × 4 tiers).

### 18.5 Release

- Mac: notarized pkg and `install.sh`; Linux: static binaries + `.deb/.rpm`; iOS: App Store; server: signed container image; enclave: EIF + PCR announcement; website: GitHub Pages.
- Version compatibility matrix documented: MCP server ↔ helper ↔ app ↔ server ↔ console.

### 18.6 Official website (`site/`, reworked in Phase 0)

| Page | Content | Source |
| --- | --- | --- |
| Home | one-line positioning, 60-second demo, three differentiators, install command | `marketing/` copy |
| Why | incident retro series (s1ngularity, Comment and Control, GhostSplice, CVE-2026-21852, DuneSlide), each mapped to a control point | blog |
| Compare | vs 1Password, vs Infisical Agent Vault, vs plain .env | Strategy doc §3 |
| Pricing | Free / Team v1 / Full Team / add-ons; FAQ | Strategy doc §8 |
| Docs | install, concepts, all tools, templates, gateway, CLI, policy syntax, self-hosting relay, hook install | existing `guide.md` migrated in |
| Template catalog | generated at build time from `templates/catalog.json`, one page per service | shared data |
| Security | renders `SECURITY.md`, threat model, PCR allowlist, reproducible-build notes, vuln-report channel | repo files |
| Downloads | `install.sh`, per-platform binaries, sha256, Sigstore signatures | release artifacts |
| Legal | privacy policy, terms of service, data-processing notes (Team needs) | — |
| Machine-readable | `/attestation/pcrs.json` (signed), `/oauth/client.json` (CIMD, Phase 4), `/.well-known/security.txt` | CI-generated |

Tech: Zola (static site generator in the Rust ecosystem, zero Node deps), multilingual zh/en, built-in search index; built by GitHub Actions and published to GitHub Pages (current hosting) with a custom domain; from Phase 2 the same artifact also deploys to a US VPS running Caddy as a mirror. The site holds no user data and no backend logic; the pricing page's "get started" jumps to the console.

### 18.7 Web console (`kv-server`'s `console` feature + `apps/web/`, from Phase 2)

Team v1's admin surface, server-rendered, no SPA framework: askama templates + htmx, with a little TypeScript only for WebCrypto. Security baseline: same-site cookies, CSRF tokens, strict CSP, no inline scripts.

| Feature | Phase | Notes |
| --- | --- | --- |
| Login | 2 | email magic link + device confirmation; no passwords |
| Org and members | 2 | create org, invite links, roles, remove members (triggers a CEK-rotation task executed by an online device) |
| Seats and billing | 2 | show entitlements and usage; "manage billing" jumps to the Stripe Customer Portal |
| Policy | 2 | org `policy.yaml` editor, server-validated (tighten-only), version history, signed distribution |
| Devices | 2 | list, last-seen, revoke |
| Shared credentials | 2 | metadata only: name, backend, holder, authorized members; "share to member" is initiated in the console, but the encrypted wrap is produced by the owner's online device; the console never sees plaintext or CEKs |
| Audit | 2 | metadata stats (counts, devices, times) and export jobs; entry contents are encrypted — the console cannot decrypt them at this stage |
| Browser as a device | 3 | a non-exportable WebCrypto P-256 key stored in IndexedDB, registered as a device via phone pairing; then: decrypt audit entries, give Quick approvals (not Strong), view decrypted metadata of shared credentials |
| SSO setup | 3 | integrate Ory Hydra's federated login (OIDC) |
| Add-ons and enclave status | 4 | CI offline-execution activation, BYO-KMS config, current PCRs |

### 18.8 Client apps (`apps/`)

| App | Phase | Tech | Shared core |
| --- | --- | --- | --- |
| iOS | 3 | SwiftUI; two Secure Enclave keys; App Attest; Notification Service Extension; QR pairing | `kv-ffi` generates the Swift package via UniFFI: HPKE, approval signing and digest verification, pairing, audit decryption, capability-token issuing |
| Android | 4 | Kotlin; StrongBox + BiometricPrompt; Key Attestation | the same `kv-ffi` generates the Kotlin package |
| macOS menu bar | Phase 3+, optional | SwiftUI menu bar: status, grant-mode switching, recent approvals, pairing entry | talks to the helper over IPC; the Touch ID dialog stays in the separate `kv-touchid` process |

Rule: all crypto and protocol logic is written exactly once in Rust — apps never implement HPKE, digests, or signature formats themselves; the UniFFI interface has contract tests in `kv-ffi`; the Swift/Kotlin side only does UI and system APIs (SE, Keystore, push).

### 18.9 Build and release pipeline for the monorepo

- Task entry `justfile`: `just build`, `just test`, `just site`, `just release <version>`.
- CI filtered by path: `rust/**` runs cargo test and clippy; `apps/ios/**` uses a macOS runner + fastlane for unit tests and TestFlight; `site/**` builds with Zola and publishes Pages; `deploy/**` validates Terraform and compose; `rust/crates/kv-enclave/**` runs the reproducible EIF build and compares PCRs.
- Rust cross-compilation: macOS arm64/x86_64, Linux x86_64/arm64 (musl static); server and push container images signed. From Phase 2, Rust artifacts are reproducible (pinned toolchain, `SOURCE_DATE_EPOCH`, no build paths), with dual-machine CI builds comparing hashes.
- Versioning: a single `VERSION` at the repo root — all artifacts share it; the compatibility matrix lives in `docs/compat.md`.
- Release script: generates sha256 and the Sigstore signature for `install.sh`, updates `site/static/attestation/pcrs.json`, pushes the GitHub Release.

---

## 19. Phase-deliverable mapping

| Phase | New modules | Key interfaces |
| --- | --- | --- |
| 0 (months 0–1) Ship | macOS Secure Enclave local master-key protection verification and explicit migration (§8.0); approvals show the real request + digest binding (Touch ID copy); tool annotations; `kv-hook` covering Claude Code / Codex, a Cursor adapter prototype, Grok verified; `keyvalet scan`; SDK upgrade to 2026-07-28; website rework (pricing, comparisons, security page) with site content moved from `docs/` to `site/` | local master-key protection and migration interfaces; `UseRequest`, `Approval`, `RuntimeAdapter`, manifest (install metadata) |
| 1 (months 1–4) Policy & Linux | policy engine; grant-scope definition; template `summarize`; Linux / CI calls and identity integration, local helper compatibility path (system user, Unix socket, optional TPM2, TTY Quick-only; §8.0); `keyvalet hooks install --all`; audit hash chain; capability tokens (issued on Mac, used in CI) | `PolicyEvaluator`, `Approver` upgrade, IPC v4 |
| 2 (months 4–8) relay & Team v1 | `kv-server` (relay, team, billing) + Ory Hydra + Docker deployment, official instance US-hosted; `kv-relay-client`; vault v2 with multi-device UMK wraps; Team v1; Stripe and entitlement tokens; Web console v1 (org, members, billing, policy, devices); transparent proxy opt-in (session tokens, CA in the helper); `kv-mcp` Rust edition; `keychain`, `onepassword`, `infisical`, `github-oidc` backends | relay protocol, HPKE sealing, `StorageBackend`, `Deliverer`, team data model |
| 3 (months 8–14) iPhone & Full Team | iPhone app shipped (two approval tiers, pairing, NSE, App Attest); `kv-push`; console "browser as a device" (audit decryption, Quick approvals); `remote-phone` Approver; approval routing, N-of-M; phone Strong approvals for Linux / CI; OIDC SSO; `bitwarden` backend; third-party security audit | pairing protocol, push wake, N-of-M aggregation |
| 4 (months 14–24) CI offline execution, remote MCP, Enterprise | AWS Nitro enclave executor (BYO-KMS default, managed-KMS trust statement, reproducible EIF, client-pinned PCR list); remote MCP endpoint (Hydra as AS, PRM, CIMD); Enterprise self-hosted Terraform; SCIM; Okta Cross-App Access; Vault / OpenBao backends; credential rotation; Android app; macOS menu bar (optional); a Windows TPM + Hello local client scheduled separately only on concrete demand | `Executor`, KMS condition policies, remote MCP resource server |

---

## 20. Open questions

1. **Grok**: ✅ researched and integrated 2026-10 (see the §5.2 table, `docs/runtimes.md`): both MCP and hooks are natively supported, `kv-hook grok-tool` is implemented. The only open item is "never exercised in a real Grok Build environment — medium confidence", not "never researched".
   **Devin CLI**: ✅ integrated (see the §5.2 table, `docs/runtimes.md`): a native plugin `devin-plugin/` (skills as `/keyvalet:*` commands, `hooks.json`, `.mcp.json`), `kv-hook devin-tool` implemented, MCP calls verified working and audited. The only open item is that `devin-tool` hasn't been watched end-to-end hitting a real secret in a live session (unit tests cover the documented payload shapes).
2. **Interactive approval on Linux**: TTY confirmation codes are weaker than biometrics — Quick only. A stronger local candidate is polkit `auth_self`: a polkit agent verifies the user's password or an fprintd fingerprint, and the agent can't pass without knowing the password; another candidate is a `pinentry`-style GUI tool. Both prove user identity without hardware key binding — TBD.
3. **Timing of the Mac helper's stdin/stdout → Unix socket migration**: involves launchd and `sudo` flow changes — recommend end of Phase 1. The precondition is moving Secure Enclave operations out of the daemon: Apple doesn't support SE in `launchd` daemons — it must run in a per-user LaunchAgent inside the user's login session, with the helper verifying via audit token; see §8.0.
4. **An iOS Nitro attestation verification library**: nothing off the shelf — needs assembly and interop testing.
5. **SAML**: high implementation cost — Phase 3 prioritizes OIDC, SAML depends on design-partner demand.
6. **KMS cost and quotas**: the pre-authorized path costs one KMS call per decryption — negligible per-use billing, but throttling needs monitoring.
7. **FTO**: the IETF user-mediated delivery draft declares pending patent applications; KeyValet is a proxy-side model but claim scope still needs review.
8. **Transparent proxy vs HTTP/2 and gRPC**: Phase 2 supports HTTP/1.1 termination first, h2 passes through undecrypted; gRPC injection comes later.
9. **CEK wrapping for new Team members**: online-holder confirmation (zero-knowledge, friction) vs an org-managed device (low friction, holds keys) — decided in Phase 2 with design-partner feedback.
10. **Trademark**: the KeyValet trademark search and potential conflicts — done in Phase 0.

---

## Appendix A: `keyvalet.toml` example

```toml
[core]
default_grant_mode = "per_credential"
strong_tier = 2            # T2 and above force Strong

[plugins]
identity  = ["secure-enclave"]              # or "tpm2" / "software"
approvers = ["touchid", "remote-phone", "tty", "auto"]
issuers   = ["static", "oauth2", "jwt", "github-app", "google-sa", "aws", "totp"]
deliverers = ["proxy", "file", "env"]       # omitting "plaintext" forbids credential_get plaintext
guards    = ["ssrf", "redact"]
storage   = ["local", "onepassword"]
audit     = ["local-chain", "otlp"]
templates = ["catalog", "n8n", "custom:~/.config/keyvalet/templates"]

[runtimes]
enabled = ["claude-code", "codex", "cursor", "grok"]

[relay]
url = "https://relay.example.com"           # self-hosted or official
push_gateway = "https://push.keyvalet.dev"  # set to "" to disable push

[proxy]
transparent = false                          # opt-in
listen = "127.0.0.1:8788"
require_session_token = true                 # cannot be disabled: tokenless connections are refused
leaf_cert_ttl = "24h"                        # leaf certs issued by the helper; the CA key never leaves it

[audit.otlp]
endpoint = "http://localhost:4318"
```

## Appendix B: `policy.yaml` example

```yaml
version: 1
defaults:
  tier_decisions: { T0: auto, T1: ask, T2: strong, T3: deny }
rules:
  - name: openai-readonly-auto
    match: { credential: "openai/*", host: "api.openai.com", method: [GET, HEAD] }
    decision: auto
  - name: github-delete-strong
    match: { credential: "github/*", method: [DELETE] }
    decision: strong
  - name: payments-sensitive
    match: { host: "api.stripe.com", path: ["/v1/charges*", "/v1/payouts*"] }
    tier: T2
  - name: ci-budget
    match: { runtime: "ci/*", credential: "openai/default" }
    budget: { calls_per_day: 500 }
  - name: night-block
    match: { time: { not_between: ["09:00", "23:00"], tz: "Asia/Shanghai" }, tier: [T2] }
    decision: deny
```

Repo-level policies may only make `decision` stricter than defaults, `budget` smaller, `tier` higher; violating entries are ignored and audited.

## Appendix C: runtime manifest example

Manifests contain only install metadata; event parsing and decision rendering live in the corresponding `RuntimeAdapter` (Rust).

```yaml
# kv-hook/manifests/claude-code.yaml
runtime: claude-code
detect:
  paths: ["~/.claude/settings.json", "~/.claude.json"]
install:
  target: "~/.claude/settings.json"
  merge: json
  hooks:
    - event: PreToolUse
      matcher: "Write|Edit|MultiEdit|NotebookEdit|Bash"
      command: "kv-hook --runtime claude-code --event pre-tool"
      timeout: 10
    - event: UserPromptSubmit
      command: "kv-hook --runtime claude-code --event prompt"
mcp:
  target: "~/.claude.json"
  entry: { command: "kv-mcp", args: [] }
```

```yaml
# kv-hook/manifests/cursor.yaml
runtime: cursor
install:
  target: "~/.cursor/hooks.json"
  merge: json
  hooks:
    - event: beforeShellExecution
      command: "kv-hook --runtime cursor --event shell"
    - event: preToolUse
      command: "kv-hook --runtime cursor --event pre-tool"
mcp:
  target: "~/.cursor/mcp.json"
  entry: { command: "kv-mcp", args: [] }
```

Codex's manifest is nearly identical to Claude Code's (target file `~/.codex/hooks.json`, MCP written into `~/.codex/config.toml`); Grok's manifest only has `runtime: grok` and an `mcp` section — the hook part is filled in after verification.

## Appendix D: approval request and capability token examples

An approval request (shown to a human):

```
KeyValet requests to use credential openai/default (T1 write)
Purpose (agent-stated): Summarize meeting notes
Real request: POST api.openai.com /v1/chat/completions  body 2.1 KB  sha256 a1b2c3d4
Origin: claude-code 2.1.3 · github.com/x/y · this machine
Grant scope: [this once] [this credential, this session] [remember 4 hours]
```

Capability tokens: see §7.5.

## Appendix E: server API summary

| Method | Path | Purpose | Auth |
| --- | --- | --- | --- |
| POST | `/v1/devices` | register a device | pairing token or registered-device signature |
| WS | `/v1/presence` | presence and message channel | device-signature challenge |
| POST | `/v1/approvals` | submit an encrypted approval request | device signature |
| POST | `/v1/approvals/{id}/reply` | approval reply | device signature |
| GET | `/v1/approvals/{id}` | NSE pulls the blob | device signature |
| PUT/GET | `/v1/blobs/{id}` | ciphertext storage | device signature |
| POST | `/v1/accounts/magic-link`, `/v1/accounts/verify` | Team email accounts (Phase 2) | email token + device signature |
| GET | `/.well-known/oauth-protected-resource` | PRM (Phase 4) | public |
| — | `/oauth2/auth`, `/oauth2/token`, `/.well-known/openid-configuration` | provided by Ory Hydra (Phase 3 SSO, Phase 4 remote MCP) | — |
| POST | `/mcp` | remote MCP (Streamable HTTP) | Bearer |
| POST | `/v1/orgs`, `/v1/orgs/{id}/members`, `/v1/orgs/{id}/shares` | team | member-device signature + role |
| GET | `/v1/orgs/{id}/policy` | signed org policy | member |
| POST | `/v1/billing/webhook` | Stripe | Stripe signature |
| GET | `/v1/entitlements` | entitlement tokens | device signature |
| POST | `/v1/attestation` | enclave uploads attestation document | executor-device signature |
| GET | `/attestation/pcrs.json` | current PCR allowlist | public, signed |

## Appendix F: new IPC v4 operations

| Operation | Notes |
| --- | --- |
| `PolicyEvaluate` | returns tier/decision for a given request (used by `keyvalet policy test` and hooks) |
| `ApprovalRequest` / `ApprovalStatus` | start a remote approval, query status |
| `CapabilityIssue` / `CapabilityRevoke` | capability tokens |
| `PairStart` / `PairComplete` | pairing |
| `DeviceList` / `DeviceRevoke` | device management |
| `HookEvent` | hooks report events and query known-secret fingerprints (HMAC) |
| `ProxyRegister` | transparent-proxy registration and sessions |
| `Scan` | scanning and import |
| `BackendList` | storage backends and credential sources |
| `AuditVerify` | verify the hash chain |

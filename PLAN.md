# pi-contain — design plan v1

Capability-based guardrail extension for pi. Replaces pattern-matching
(deny-the-bad) with containment + default-ask (allow-the-provably-safe).
Answer approvals locally in the TUI **or** via Telegram; first answer wins.

## Goals
1. No command classification by regex. Gate at mechanism layer: verbs, resolved
   paths, sandbox profiles.
2. Approvals grant **rules** (verb × resolved scope × capability), never strings.
3. Chains (`&& ; |`) decompose into segments; each gets its own verdict; the
   first blocking segment produces one approval request naming it precisely.
4. Guard protects itself: its config/grants/token/code are hard-deny targets
   for the agent (no prompt — a prompt is a social-engineering surface).
5. Portable approval channel: any Telegram bot via token + whitelisted chat ids.

## Non-goals (v1)
- No prefix-run while waiting (fresh-shell-per-call breaks cd/env state; the
  synchronous gate IS the pause; approval runs the whole chain atomically).
- No VM/isolated-network sandbox (bwrap shares the kernel; same-user trust domain).
- No per-OS sandbox matrix: bwrap on Linux, fail-closed elsewhere.

## Decision pipeline (per `bash` tool_call)

```
parse → segments (chain-aware: track cd/env/assignments forward)
  for each segment, in order:
    SAFE        read-only verb, literal args, no indirection     → auto
    SANDBOXABLE effects ⊆ writable set (workspace, /tmp), no net → auto, wrapped in bwrap
    GRANTED     matches existing grant predicate                  → auto
    SECRET      resolved target matches secrets globs            → HARD DENY (no prompt)
    SELF        target = guard's own files                       → HARD DENY (no prompt)
    ASK         crosses boundary (network, write outside, exec
                unknowns, undecidable)                           → approval request (first one wins)
  if any ASK unresolved → whole call pauses at the gate
  approve  → entire command runs unmodified (single shell, state intact)
  deny     → block with: "blocked at segment N: <seg> — reason; others were fine"
  timeout  → deny (fail closed), notify both channels
```

Read/write/edit tools: same pipeline minus segmentation; `path` param is exact,
no extraction heuristics. Secret globs are hard-deny for reads AND writes.

## Sandbox (bwrap, confirmed working on this host)
- Profiles: `ro` = `--ro-bind / /` (+ dev/proc), no `--share-net` ⇒ no network.
  `rw` = `ro` + `--bind` workspace + `--bind /tmp`.
- Secrets and guard files are **masked inside the sandbox too** (tmpfs overlay
  at concrete resolved paths) — sandboxed code cannot read `.env`/`~/.ssh` even
  though the root mount is read-only-readable.
- bwrap missing or userns disabled ⇒ SANDBOXABLE downgrades to ASK (fail closed).

## Approval & decision flow (comprehensive)

**Request payload** (identical both channels):
```
[pi-contain] approval needed — <session>
workspace: /srv/app
command:   cd /srv && rg TODO src && curl -X POST https://api.x.com/hook
blocked:   segment 3 — curl -X POST https://api.x.com/hook
reason:    network; write outside workspace
options:   [once] [session] [forever: curl→api.x.com] [deny] [stop]
```

**Decisions**: `once` (this call only) · `session` (grant lives in memory,
dies with session) · `forever` (persisted predicate; only offered where the
segment is rule-generalizable) · `deny` (block, precise reason) · `stop`
(deny + abort turn, mirroring permission-gate semantics).

**Arbiter (first-wins)**:
- `PendingApproval { id, key, resolve, settledBy, timer }` in a Map.
- Local TUI component and Telegram callback both call `resolve(id, decision, via)`.
- First settles; late answer gets "already answered via <other>" (local notify
  + `answerCallbackQuery` + edit Telegram message with outcome).
- Timeout watchdog per request (default 300s) → deny + notify both channels.
- Coalescing: identical request `key` (canonical verb+scope) re-requested by
  another concurrent call (subagents) attaches to the existing pending — one
  Telegram message, "asked N×" counter. Anti prompt-fatigue.
- Request ids: short random, embedded in `callback_data` (`c:<id>:<dec>` <64B).

**Grant predicates** (stored, never strings):
```jsonc
{ "verb": "rm", "scope": { "paths": ["/tmp/**"] }, "caps": ["write"], "origin": "telegram", "ts": "…" }
{ "verb": "curl", "scope": { "hosts": ["api.x.com"], "methods": ["POST"] }, "caps": ["network"] }
```
- Matching: parse segment → verb → `realpath` every path arg (kills
  `/tmp/../home`) → glob match → caps check.
- Generalization offered explicitly in the prompt (user picks breadth);
  destructive verbs cap breadth (no "rm anywhere" forever).
- Never generalizable: `bash script.sh`, interpreters `-c`, `npx`, `curl|sh` —
  effects not decidable from text ⇒ once/session only, or sandbox.

## Telegram module
- Config: `{ tokenEnv: "CONTAIN_TELEGRAM_TOKEN", allowedChatIds: [$CONTAIN_CHAT_ID], timeoutMs }`
  — extension reads process.env[tokenEnv]; any bot wireable, no secret file on disk.
- Long-poll `getUpdates` loop in-process (no webhook, no public endpoint),
  `allowed_updates: ["callback_query","message"]`, dedupe by `update_id`.
- Verify `from.id ∈ allowedChatIds`; others ignored silently (logged).
- On resolve: `answerCallbackQuery` + edit message ("✅ approved via TUI").
- Token never logged; token file + grants + config + package dir are all in the
  SELF hard-deny set. NOTE: current token transited chat — rotate via BotFather
  after setup.
- No Telegram config / unreachable API ⇒ channel disabled, local prompt still
  works (degrade, don't fail).

## Config schema (contain.json)
```jsonc
{
  "mode": "strict",                       // strict | normal | off
  "sandbox": { "enabled": true, "writable": ["$WORKSPACE", "/tmp"], "network": false },
  "secrets": [".env*", "~/.ssh/**", "~/.aws/**", "~/*.token"],
  "readOnly": ["**/*.db", "**/node_modules/**", "**/.git/**"],
  "askVerbs": ["sudo", "mount", "npx", "systemctl", "git push", "curl@mutating"],
  "approval": { "timeoutMs": 300000, "telegram": { "tokenEnv": "…", "allowedChatIds": [] } }
}
```

## @aliou/sh verdict (task #1)
v0.3.3, "WIP", single author, 0 tests shipped in package. We do NOT need it to
be fully correct — we need three behaviors, each wrapped fail-closed:
1. statement splitting at `&& ; | ;()` boundaries,
2. literal word extraction (quoted/expanded parts flagged, not guessed),
3. throwing (not silently mis-parsing) on input it can't handle.
Probe battery pins these against adversarial cases (`$()`, process
substitution, nested quotes, heredocs, `R=rm; $R -rf`, unicode). Any parse
anomaly ⇒ segment is UNDECIDABLE ⇒ sandbox-or-ask. Never trust, always contain.

## Test plan
- Unit: segmentation battery, chain-aware resolution (`cd /etc && cat passwd`),
  realpath tricks, grant match/decay, arbiter race (TUI vs TG vs timeout),
  coalescing, self-protection denies.
- Integration: real bwrap (write to /tmp ok, /home EROFS, net fails, secrets
  masked), full pipeline per decision matrix.
- Live: one Telegram round-trip (send → callback → resolve → edit).

## Milestones
1–9 tracked in the todo tool. Done ⇒ v1 shipped as local pi package
(`~/.pi/agent/git/local/pi-contain`), wired via `settings.json` packages.

## Threat model (explicit)
Stops: obfuscated destruction (`$R -rf`, base64|sh, scripts), secret reads
(incl. via sandboxed interpreters), self-disabling, grant-recursion fatigue,
prompt-fatigue spam (coalescing).
Does NOT stop: anything the user approves; kernel/network-level attacks from
approved unsandboxed code; same-user TTY/session compromise.

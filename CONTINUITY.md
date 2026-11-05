# pi-contain — continuity

## PLAN
See PLAN.md. v1 shipped 2026-04-18; git-subcommand fix + /yolo + dialog-dismiss added same day.

## DECISIONS
- 2026-04-18 [USER] Approvals via Telegram OR pi session; first answer wins.
- 2026-04-18 [USER] Token via env var name (CONTAIN_TELEGRAM_TOKEN), not a file.
- 2026-04-18 [USER] No prefix-run while waiting (fresh-shell-per-call breaks chain state).
- 2026-04-18 [USER] /yolo = session-scoped dev toggle; while off agent may edit package.
- 2026-04-18 [CODE] @aliou/sh fail-closed; Tilde literal; readonly verbs need literal args.
- 2026-04-18 [CODE] $WORKSPACE pins to SESSION cwd (chain `cd` must not move writable set).
- 2026-04-18 [CODE] readOnly globs before writable containment.
- 2026-04-18 [CODE] git: GIT_RO→safe, GIT_NET (push/pull/fetch/clone/ls-remote/submodule)→ask(net),
  local mutation→sandbox. (`git` must NOT sit in the READONLY verb table.)
- 2026-04-18 [CODE] Local select gets AbortSignal; arbiter aborts dialog when another channel
  settles (no zombie prompts).

## PROGRESS
- 2026-04-18 AUDIT REMEDIATION COMPLETE: 93/93 tests. All C1–C5, H1–H5, M1–M7
  addressed; live re-proofs all correct (see OUTCOMES).
- Key discoveries: @aliou/sh hides heredoc-body expansions (delimiter quoting
  IS exposed — unquoted ⇒ undecidable); `~user` parses as plain Literal
  (guard in wordValue); find -exec never matched due to join(" -") flag
  doubling (FIND_UNSAFE_ARG now exact-match per arg).
- Earlier: scope-explicit approvals, session-exact fallback grants,
  /yolo (+status bar), AbortSignal dialog dismiss, telegram multi-chat,
  once-approves-one, tamper fingerprint (contain-state.json), config
  fail-loud to strict, approved write-outside runs sandboxed w/ bound dirs.
- 74/74 tests green. Scope-explicit approvals shipped: every option self-describes
  its grant (once=session/forever scope text derived from the actual predicate),
  session always persists something (exact-scope fallback for breadthless asks),
  local prompt title carries the command, Telegram shows per-option scopes.
- Fixed: multi-word verbs ("git push") now carried on ApprovalRequest.verb —
  segment.split(" ")[0] stored "git" and never matched.
- 71/71 prior: git routing + real-bwrap containment.
- Live-verified: safe/sandbox silent, secret hard-deny, self-protection (blocked the agent),
  approval prompt (git push, curl), /yolo toggle.
- Installed: settings.json → `git/local/pi-contain`; guardrails removed (rollback: re-add line).
- Config: ~/.pi/agent/extensions/contain.json (chat $CONTAIN_CHAT_ID, tokenEnv).

## DISCOVERIES
- pi: ctx.ui.select(title, opts, {signal}) — signal dismisses dialog programmatically.
- pi: registerCommand(name, {description, handler}) for slash commands.
- pi: tool_call input mutable in place; local packages via `pi install .`.
- Live self-protection moment: agent blocked editing classify.ts — threat model works.

## OUTCOMES
- 2026-04-18 nit-wave: gate.ts added to fingerprint list; .local un-skipped in
  glob enumeration (certs under ~/.local/share); interpreter opaque-payload
  matches combined short flags (-lc/-uc). 102/102.
- Nit #4 (telegram truncation/probe/parseHosts) verified ALREADY SHIPPED —
  auditor read a pre-reload tree. Grants file clean/empty (the historical
  /dev/null inconsistency = yolo-state, no stale grant).
- Audit 2026-04-18: all criticals/highs/mediums remediated and re-proven:
  C1 sandbox · C2 deny · H5 sandbox(scrubbed) · C3/C3b sandbox · M5 sandbox ·
  M2 sandbox · C5/C5b deny · M1 ask · regressions none.
- M3/M4 resolved as misdiagnosis: “ENOENT-hiding/output filtering” was the
  sandbox tmpfs masking layer; “non-determinism” was prompt-state + masking
  interplay. No hidden runtime layer exists; masking behavior now documented.
- Residual accepted risks (documented, by design): approved net commands run
  raw with full env; guard source readable with approval (policy, not hole);
  same-user trust domain (kernel-level attacks out of scope).
- User TODO: rotate bot token; keep CONTAIN_TELEGRAM_TOKEN exported.

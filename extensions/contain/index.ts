import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { loadConfig } from "../../src/config.ts";
import { GrantStore } from "../../src/grants.ts";
import { Arbiter, type ApprovalRequest, type Decision, type DecisionType } from "../../src/arbiter.ts";
import { TelegramChannel } from "../../src/telegram.ts";
import { gateToolCallSync, persistGrant } from "../../src/gate.ts";
import { decideBash } from "../../src/pipeline.ts";
import { buildWrap } from "../../src/sandbox.ts";

export default async function contain(pi: ExtensionAPI) {
  const cfg = loadConfig();
  const configuredMode = cfg.mode;
  const grants = new GrantStore(cfg.grantsPath);

  // Tamper evidence: fingerprint the guard's own source at every load and
  // compare against the last-seen fingerprint (stored in a guard-owned file
  // the agent cannot write). Mismatch ⇒ loud warning each session start.
  const statePath = path.join(path.dirname(cfg.configPath), "contain-state.json");
  let tamperWarn: string | null = null;
  try {
    const files = [
      path.join(path.resolve(fileURLToPathSafe()), "index.ts"),
      ...["arbiter", "classify", "config", "gate", "grants", "pipeline", "sandbox", "segments", "telegram"].map(
        (m) => path.join(path.resolve(fileURLToPathSafe(), "../..", "src"), `${m}.ts`),
      ),
    ];
    const h = createHash("sha256");
    for (const f of files.sort()) {
      if (existsSync(f)) h.update(f + "\0" + readFileSync(f));
    }
    const fingerprint = h.digest("hex");
    let prev: string | null = null;
    if (existsSync(statePath)) {
      prev = JSON.parse(readFileSync(statePath, "utf8")).fingerprint ?? null;
    }
    if (prev && prev !== fingerprint)
      tamperWarn = "pi-contain: guard source changed since last session — verify this was you";
    writeFileSync(statePath, JSON.stringify({ fingerprint, at: new Date().toISOString() }, null, 2), { mode: 0o600 });
  } catch {
    // Fingerprinting is best-effort evidence, never a gate: if it cannot run,
    // continue without it rather than disabling the guard.
  }
  function fileURLToPathSafe(): string {
    // this module: extensions/contain/index.ts → its directory
    return new URL(".", import.meta.url).pathname;
  }

  // Status-bar state. Never write to stdout/stderr from a TUI extension —
  // console output corrupts the input area. Everything visible lives in the
  // keyed footer slot "pi-contain".
  type UIRef = { setStatus: (key: string, text: string | undefined) => void; notify: (m: string, t?: "info" | "warning" | "error") => void };
  let uiRef: UIRef | null = null;
  let tgDown = false;
  const refreshStatus = () => {
    if (!uiRef) return;
    const parts: string[] = [];
    if (cfg.mode === "off") parts.push("YOLO");
    if (tgDown) parts.push("TG ERR");
    uiRef.setStatus("pi-contain", parts.length ? parts.join(" · ") : undefined);
  };

  // Local dialogs by request id: aborted when another channel settles first,
  // so the prompt disappears instead of lingering in the chat.
  const localDialogs = new Map<string, AbortController>();

  let telegram: TelegramChannel;
  const arbiter = new Arbiter(cfg.approval.timeoutMs, (req, d) => {
    if (telegram?.enabled) telegram.editOutcome(req.id, d.type, d.via);
    if (d.via !== "tui") localDialogs.get(req.id)?.abort();
  });
  telegram = new TelegramChannel(cfg.approval.telegram, {
    arbiter,
    onHealth: (healthy) => {
      tgDown = !healthy;
      refreshStatus();
    },
  });
  if (cfg.mode !== "off") await telegram.start();

  pi.on("session_start", (_event, ctx) => {
    grants.clearSession();
    uiRef = ctx.ui as unknown as UIRef;
    if (cfg.configError)
      ctx.ui.notify(`pi-contain: ⚠️ contain.json failed to parse — STRICT DEFAULTS ACTIVE (${cfg.configError}). Fix the config; do not run ungated.`, "warning");
    if (tamperWarn) ctx.ui.notify(tamperWarn, "warning");
    if (telegram.enabled) ctx.ui.notify("pi-contain: Telegram approvals active", "info");
    refreshStatus();
  });

  pi.on("session_end", () => {
    arbiter.flush();
  });

  // ---- /yolo: session-scoped development toggle (user-initiated, in-memory).
  // Restarting pi (or /yolo on) restores the configured mode. While off, the
  // agent can edit the package — that is the sanctioned dev hatch.
  pi.registerCommand("yolo", {
    description: "pi-contain: yolo mode — disables all gating for this session",
    handler: async (args, ctx) => {
      const arg = args.trim().toLowerCase();
      const yoloActive = () => cfg.mode === "off";
      if (arg === "status") {
        ctx.ui.notify(`pi-contain: yolo ${yoloActive() ? "ON — gating DISABLED" : "off — gating active"} (mode: ${cfg.mode})`, "info");
        return;
      }
      if (arg && arg !== "on" && arg !== "off") {
        ctx.ui.notify("usage: /yolo [on|off|status] — no argument toggles", "warning");
        return;
      }
      const wantYolo = arg ? arg === "on" : !yoloActive();
      cfg.mode = wantYolo ? "off" : configuredMode === "off" ? "strict" : configuredMode;
      if (cfg.mode === "off") {
        arbiter.flush();
        ctx.ui.notify("pi-contain: 🎉 YOLO — gating disabled for this session. /yolo off to re-arm.", "warning");
      } else {
        ctx.ui.notify(`pi-contain: yolo off — re-armed (mode: ${cfg.mode})`, "info");
      }
      uiRef = ctx.ui as unknown as UIRef;
      refreshStatus();
    },
  });

  async function runApproval(
    req: ApprovalRequest,
    ctx: { hasUI: boolean; ui: { select: (t: string, o: string[], opts?: { signal?: AbortSignal }) => Promise<string | undefined>; notify: (m: string, t?: "info" | "warning" | "error") => void } },
  ): Promise<Decision> {
    const promise = arbiter.create(req);
    let wired = false;
    if (telegram.enabled) {
      void telegram.sendApproval(req);
      wired = true;
    }
    if (ctx.hasUI) {
      wired = true;
      const ac = new AbortController();
      localDialogs.set(req.id, ac);
      const options = req.options.map((o) => {
        switch (o) {
          case "once": return "✅ Once — this exact command";
          case "session": return `🔁 Session — ${req.scopes.session}`;
          case "forever": return `♾ Forever — ${req.scopes.forever ?? req.scopes.session}`;
          case "deny": return "🚫 Deny";
          case "stop": return "⏹ Stop";
        }
      });
      const cmdPreview = req.command.length > 160 ? `${req.command.slice(0, 160)}…` : req.command;
      void ctx.ui
        .select(`pi-contain: ${req.reason}\n› ${cmdPreview}\n◈ ${req.breakdown}`, options, { signal: ac.signal })
        .then((choice) => {
          localDialogs.delete(req.id);
          // Dialog dismissed programmatically (another channel settled) → nothing to do.
          if (choice === undefined && arbiter.get(req.id) === null) return;
          let type: DecisionType;
          if (choice === undefined) type = "deny"; // escape key / dialog timeout
          else if (choice.startsWith("✅")) type = "once";
          else if (choice.startsWith("🔁")) type = "session";
          else if (choice.startsWith("♾")) type = "forever";
          else if (choice.startsWith("⏹")) type = "stop";
          else type = "deny";
          arbiter.resolve(req.id, type, "tui");
        });
    }
    if (!wired) {
      arbiter.resolve(req.id, "deny", "timeout");
      ctx.ui.notify("pi-contain: no approval channel available — denied", "warning");
    }
    return promise;
  }

  pi.on("tool_call", async (event, ctx) => {
    uiRef = ctx.ui as unknown as UIRef;
    const input = event.input as Record<string, unknown>;
    const d = gateToolCallSync(event.toolName, input, ctx.cwd, { cfg, grants });
    if (d === "unhandled" || d.action === "allow") {
      if (d !== "unhandled" && d.command) input.command = d.command; // sandbox wrap
      return;
    }
    if (d.action === "deny") return { block: true, reason: d.reason };
    const decision = await runApproval(d.request, ctx as never);
    if (decision.type === "deny")
      return { block: true, reason: `pi-contain: denied (${d.request.reason}) — answered via ${decision.via}` };
    if (decision.type === "stop")
      return { block: true, reason: "pi-contain: user requested stop" };
    if (decision.type === "session" || decision.type === "forever")
      persistGrant(d.request, decision.type, decision.via === "telegram" ? "telegram" : "tui", grants);
    // Approved write-outside: still contained — sandbox with the exact
    // approved targets bound rw (existing files bind as files; only
    // not-yet-existing targets fall back to their parent dir).
    if (d.request.kind === "write-outside" && d.request.targets.length && input.command !== undefined) {
      const extra = [
        ...new Set(d.request.targets.flatMap((t) => (existsSync(t) ? [t] : [path.dirname(t)]))),
      ].filter((p) => existsSync(p));
      if (extra.length) input.command = buildWrap(String(input.command), cfg, ctx.cwd, extra);
    }
    // approved
  });

  // pi-contain why <cmd> — explain mode: prints per-segment verdicts
  pi.registerCommand("contain-why", {
    description: "pi-contain: show per-segment verdicts for a command (dry run)",
    handler: async (args, ctx) => {
      const cmd = args.trim();
      if (!cmd) {
        ctx.ui.notify("usage: /contain-why <command>", "warning");
        return;
      }
      const d = decideBash(cmd, ctx.cwd, { cfg, grants });
      const verdict = d.action === "allow" && d.command ? "sandbox (auto-wrapped)" : d.action;
      ctx.ui.notify(
        `verdict: ${verdict}${d.action === "ask" ? `\nblocked: ${d.request.segment}\nscope: ${d.request.scopes.session}` : ""}${d.reason ? `\n${d.reason}` : ""}`,
        "info",
      );
    },
  });
}

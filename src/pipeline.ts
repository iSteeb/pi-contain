import { DESTRUCTIVE, evaluateCommand, type EvalDeps, type SegEval } from "./classify.ts";
import type { ContainConfig } from "./config.ts";
import { requestKey, type ApprovalRequest } from "./arbiter.ts";
import { grantId, type Grant, type GrantStore } from "./grants.ts";
import { buildWrap, sandboxAvailable } from "./sandbox.ts";
import { globMatch } from "./classify.ts";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

export type BashDecision =
  | { action: "allow"; command?: string }
  | { action: "deny"; reason: string }
  | { action: "ask"; request: ApprovalRequest };

export interface PipelineDeps {
  cfg: ContainConfig;
  grants: GrantStore;
}

function commonRoot(targets: string[]): string | null {
  if (targets.length === 0) return null;
  const split = targets.map((t) => t.split("/"));
  const first = split[0];
  const prefix: string[] = [];
  for (let i = 0; i < first.length; i++) {
    if (split.every((s) => s[i] === first[i])) prefix.push(first[i]);
    else break;
  }
  while (prefix.length && !prefix[0]) prefix.shift();
  return prefix.length ? "/" + prefix.join("/") : null;
}

/** Suggested forever-grant scope for an ask. Null ⇒ no forever option. */
export function breadthFor(e: SegEval, cfg: ContainConfig): ApprovalRequest["breadth"] | undefined {
  if (e.kind === "system" || e.kind === "undecidable") return undefined;
  if (DESTRUCTIVE.has(e.verb)) return undefined; // breadth cap
  if (e.kind === "net" && e.hosts.length > 0)
    return { label: `${e.verb} → ${e.hosts.join(", ")}`, hosts: e.hosts };
  if (e.targets.length > 0) {
    // single target → its parent dir; multiple → deepest common ancestor
    const root = e.targets.length === 1
      ? path.dirname(e.targets[0])
      : commonRoot(e.targets);
    if (root && root !== "/") return { label: `${e.verb} under ${root}/**`, paths: [`${root}/**`] };
  }
  if (e.kind === "readonly")
    // scope lockfile/node_modules grants to the exact files asked about —
    // never a global verb+kind license over every read-only path
    return e.targets.length
      ? { label: `${e.verb} on ${e.targets.length} file(s)`, paths: e.targets }
      : { label: `${e.verb} on read-only paths`, paths: undefined };
  return undefined;
}

/** Exact human scope of what a session/forever grant would cover. */
export function scopeLabel(e: SegEval, breadth: ApprovalRequest["breadth"]): string {
  if (breadth) return breadth.label;
  if (e.kind === "net") return `${e.verb} (any host)`;
  if (e.targets.length > 0) return `${e.verb} on exactly ${e.targets.join(", ")}`;
  if (e.kind === "readonly") return `${e.verb} on read-only paths`;
  return `${e.verb} (this command class)`;
}

function buildAsk(command: string, cwd: string, e: SegEval, cfg: ContainConfig, breakdown: string): ApprovalRequest {
  const breadth = breadthFor(e, cfg);
  const scope = scopeLabel(e, breadth);
  return {
    id: grantId(),
    key: requestKey(e),
    title: "pi-contain: approval needed",
    command,
    segment: `${e.verb} ${e.targets.join(" ")}`.trim(),
    verb: e.verb,
    reason: e.reason,
    kind: e.kind,
    workspace: cwd,
    options: ["once", "session", ...(breadth ? (["forever"] as const) : []), "deny", "stop"],
    breadth,
    targets: e.targets,
    hosts: e.hosts,
    breakdown,
    scopes: { session: scope, forever: breadth ? scope : undefined },
  };
}

export function decideBash(
  command: string,
  cwd: string,
  deps: PipelineDeps,
): BashDecision {
  const cfg = deps.cfg;
  if (cfg.mode === "off") return { action: "allow" };
  const evalDeps: EvalDeps = {
    cfg,
    sandboxAvail: cfg.sandbox.enabled && sandboxAvailable(),
    granted: (e) => deps.grants.granted(e) !== null,
  };
  let ws = cwd;
  try {
    ws = realpathSync(cwd);
  } catch { /* keep cwd */ }
  const r = evaluateCommand(command, ws, evalDeps);
  if (r.action === "allow") return { action: "allow" };
  if (r.action === "sandbox") return { action: "allow", command: buildWrap(command, cfg, ws) };
  if (r.action === "deny") return { action: "deny", reason: `pi-contain: ${r.reason}` };
  return { action: "ask", request: buildAsk(command, ws, r.blocker!, cfg, r.breakdown) };
}

export type FileDecision =
  | { action: "allow" }
  | { action: "deny"; reason: string }
  | { action: "ask"; request: ApprovalRequest };

function resolveFile(p: string, cwd: string): string {
  let s = p.replace(/^~(?=\/|$)/, homedir());
  if (!path.isAbsolute(s)) s = path.resolve(cwd, s);
  try {
    return realpathSync(s);
  } catch {
    return path.normalize(s);
  }
}

export function decideFile(
  tool: "read" | "write" | "edit",
  p: string,
  cwd: string,
  deps: PipelineDeps,
): FileDecision {
  const cfg = deps.cfg;
  if (cfg.mode === "off") return { action: "allow" };
  const t = resolveFile(p, cwd);
  if (globMatch(cfg.secrets, t))
    return { action: "deny", reason: `pi-contain: secret policy blocks ${t}` };
  if (cfg.selfPaths.some((s) => t === s || t.startsWith(s.replace(/\/+$/, "") + "/")))
    return { action: "deny", reason: `pi-contain: guard self-protection blocks ${t}` };
  if (tool !== "read" && cfg.protectWrite.some((s) => t === s || t.startsWith(s.replace(/\/+$/, "") + "/")))
    return { action: "deny", reason: `pi-contain: extension-code protection blocks write to ${t}` };
  if (tool === "read") return { action: "allow" };
  if (globMatch(cfg.readOnly, t)) {
    const e: SegEval = {
      verdict: "ask", reason: `read-only policy: ${t}`, kind: "readonly",
      verb: tool, targets: [t], hosts: [],
    };
    if (deps.grants.granted(e)) return { action: "allow" };
    return { action: "ask", request: buildAsk(p, cwd, e, cfg, `${tool}[ask]`) };
  }
  return { action: "allow" };
}

/**
 * Build the grant a session/forever decision persists. With breadth → the
 * broad predicate. Without → the exact evaluated scope (same verb/kind plus
 * exact targets/hosts), so "session" always persists something real.
 */
export function grantFromDecision(req: ApprovalRequest, origin: "tui" | "telegram"): Grant | null {
  const useBreadth = req.breadth && (req.breadth.paths || req.breadth.hosts);
  return {
    id: grantId(),
    verb: req.verb,
    kind: req.kind,
    paths: useBreadth ? req.breadth!.paths : req.targets.length ? req.targets : undefined,
    hosts: useBreadth ? req.breadth!.hosts : req.hosts.length ? req.hosts : undefined,
    destructive: false,
    origin,
    createdAt: new Date().toISOString(),
  };
}

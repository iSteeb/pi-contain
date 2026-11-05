import { decideBash, decideFile, grantFromDecision, type BashDecision, type FileDecision } from "./pipeline.ts";
import type { ContainConfig } from "./config.ts";
import type { GrantStore } from "./grants.ts";
import type { ApprovalRequest } from "./arbiter.ts";

export interface GateDeps {
  cfg: ContainConfig;
  grants: GrantStore;
}

export type GateOutcome =
  | { action: "allow"; command?: string }
  | { action: "deny"; reason: string }
  | { action: "ask"; request: ApprovalRequest };

/**
 * Pure decision logic for a tool call — no UI, no pi types. The extension
 * entry delegates here; tests exercise this directly with the real tool
 * names and input shapes pi emits ({"path"} for read/write/edit,
 * {"command"} for bash).
 */
export function gateToolCallSync(
  toolName: string,
  input: Record<string, unknown>,
  cwd: string,
  deps: GateDeps,
): GateOutcome | "unhandled" {
  if (deps.cfg.mode === "off") return { action: "allow" };

  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const d: BashDecision = decideBash(command, cwd, deps);
    if (d.action === "allow") return { action: "allow", command: d.command };
    if (d.action === "deny") return { action: "deny", reason: d.reason };
    return { action: "ask", request: d.request };
  }

  if (toolName === "read" || toolName === "write" || toolName === "edit") {
    // pi's file tools use `path`; accept `file_path` as a defensive alias
    const p = String(input.path ?? input.file_path ?? "");
    const d: FileDecision = decideFile(toolName, p, cwd, deps);
    if (d.action === "allow") return { action: "allow" };
    if (d.action === "deny") return { action: "deny", reason: d.reason };
    return { action: "ask", request: d.request };
  }

  return "unhandled";
}

/** Grant persistence for session/forever approvals (shared by entry paths). */
export function persistGrant(req: ApprovalRequest, type: "session" | "forever", origin: "tui" | "telegram", grants: GrantStore): void {
  const g = grantFromDecision(req, origin);
  if (g) grants.add(g, type === "forever");
}

export type DecisionType = "once" | "session" | "forever" | "deny" | "stop";
export type DecisionVia = "tui" | "telegram" | "timeout";

export interface ApprovalRequest {
  id: string;
  /** Coalescing key: identical pending requests share one prompt. */
  key: string;
  title: string;
  command: string;
  segment: string;
  verb: string;
  reason: string;
  kind: string;
  workspace: string;
  options: DecisionType[];
  breadth?: { label: string; paths?: string[]; hosts?: string[] };
  /** Exact evaluated facts the request was built from (grant predicates). */
  targets: string[];
  hosts: string[];
  /** Per-segment verdict summary, e.g. `ls[safe] · rm build[sandbox] · curl[ASK]`. */
  breakdown: string;
  /** Human-readable scope of each persistence option — shown at decision time. */
  scopes: { session: string; forever?: string };
}

export interface Decision {
  type: DecisionType;
  via: DecisionVia;
}

export function requestKey(e: {
  verb: string;
  kind: string;
  targets: string[];
  hosts: string[];
}): string {
  return [e.verb, e.kind, ...[...e.targets].sort(), ...[...e.hosts].sort()].join("|");
}

interface Pending {
  req: ApprovalRequest;
  resolvers: Array<(d: Decision) => void>;
  timer: ReturnType<typeof setTimeout>;
  n: number;
}

/** First-wins arbitration across local TUI and Telegram. Timeout denies. */
export class Arbiter {
  private pending = new Map<string, Pending>(); // by request id
  private byKey = new Map<string, string>(); // key → request id

  constructor(private timeoutMs: number, private onSettled?: (req: ApprovalRequest, d: Decision) => void) {}

  create(req: ApprovalRequest): Promise<Decision> {
    const existingId = this.byKey.get(req.key);
    if (existingId) {
      const p = this.pending.get(existingId)!;
      p.n += 1;
      return new Promise<Decision>((res) => p.resolvers.push(res));
    }
    const p: Pending = {
      req,
      resolvers: [],
      timer: setTimeout(() => this.resolve(req.id, "deny", "timeout"), this.timeoutMs),
      n: 1,
    };
    this.byKey.set(req.key, req.id);
    this.pending.set(req.id, p);
    return new Promise<Decision>((res) => p.resolvers.push(res));
  }

  /** Returns false when unknown/settled (loser of the race). */
  resolve(id: string, type: DecisionType, via: DecisionVia): boolean {
    const p = this.pending.get(id);
    if (!p) return false;
    clearTimeout(p.timer);
    this.pending.delete(id);
    this.byKey.delete(p.req.key);
    // "Once" approves exactly ONE call: coalesced waiters (identical
    // commands racing from parallel tool calls) are denied, not inherited.
    if (type === "once" && p.resolvers.length > 1) {
      p.resolvers[0]({ type, via });
      for (const r of p.resolvers.slice(1)) r({ type: "deny", via });
    } else {
      const d: Decision = { type, via };
      for (const r of p.resolvers) r(d);
    }
    this.onSettled?.(p.req, { type, via });
    return true;
  }

  get(id: string): ApprovalRequest | null {
    return this.pending.get(id)?.req ?? null;
  }

  pendingCount(): number {
    return this.pending.size;
  }

  /** Drop everything (session end) — unresolved waiters get deny. */
  flush(): void {
    for (const id of [...this.pending.keys()]) this.resolve(id, "deny", "timeout");
  }
}

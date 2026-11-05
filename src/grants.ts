import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { globMatch, type SegEval } from "./classify.ts";

export interface Grant {
  id: string;
  verb: string;
  kind: string; // net | write-outside | readonly | system | undecidable
  paths?: string[]; // resolved-target globs this grant covers
  hosts?: string[];
  destructive: boolean;
  origin: "tui" | "telegram" | "api";
  createdAt: string;
}

export function grantId(): string {
  return Math.random().toString(36).slice(2, 10);
}

/**
 * Grants are predicates over parsed segments — never command strings.
 * A grant matches when the verb and kind match and every resolved target /
 * host of the segment falls inside the grant's scope.
 */
export function grantMatches(g: Grant, e: SegEval): boolean {
  if (g.verb !== e.verb || g.kind !== e.kind) return false;
  if (g.paths) {
    if (e.targets.length === 0) return false;
    if (!e.targets.every((t) => g.paths!.some((p) => globMatch([p], t)))) return false;
  }
  if (g.hosts) {
    if (e.hosts.length === 0) return false;
    if (!e.hosts.every((h) => g.hosts!.includes(h))) return false;
  }
  return true;
}

export class GrantStore {
  session: Grant[] = [];
  forever: Grant[] = [];
  constructor(private file: string) {
    if (existsSync(file)) {
      try {
        const data = JSON.parse(readFileSync(file, "utf8"));
        this.forever = Array.isArray(data.forever) ? data.forever : [];
      } catch {
        this.forever = []; // corrupt store: start empty, fail closed
      }
    }
  }

  granted(e: SegEval): Grant | null {
    return (
      this.forever.find((g) => grantMatches(g, e)) ??
      this.session.find((g) => grantMatches(g, e)) ??
      null
    );
  }

  add(g: Grant, persist: boolean): void {
    (persist ? this.forever : this.session).push(g);
    if (persist) this.save();
  }

  clearSession(): void {
    this.session = [];
  }

  private save(): void {
    mkdirSync(path.dirname(this.file), { recursive: true });
    writeFileSync(this.file, JSON.stringify({ forever: this.forever }, null, 2), { mode: 0o600 });
  }
}

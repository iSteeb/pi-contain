import { describe, expect, it } from "vitest";
import { grantMatches, GrantStore } from "./grants.ts";
import type { SegEval } from "./classify.ts";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const seg = (over: Partial<SegEval>): SegEval => ({
  verdict: "ask", reason: "", kind: "write-outside", verb: "rm",
  targets: [], hosts: [], ...over,
});

describe("grant predicates", () => {
  it("matches verb + path scope", () => {
    const g = { id: "x", verb: "rm", kind: "write-outside", paths: ["/tmp/**"], destructive: false, origin: "tui", createdAt: "" };
    expect(grantMatches(g, seg({ targets: ["/tmp/a"], verb: "rm" }))).toBe(true);
    expect(grantMatches(g, seg({ targets: ["/tmp/a", "/tmp/b/c"], verb: "rm" }))).toBe(true);
  });

  it("rejects targets outside scope", () => {
    const g = { id: "x", verb: "rm", kind: "write-outside", paths: ["/tmp/**"], destructive: false, origin: "tui", createdAt: "" };
    expect(grantMatches(g, seg({ targets: ["/home/u/x"], verb: "rm" }))).toBe(false);
    expect(grantMatches(g, seg({ targets: ["/tmp/a", "/home/u/x"], verb: "rm" }))).toBe(false);
  });

  it("rejects different verb or kind", () => {
    const g = { id: "x", verb: "rm", kind: "write-outside", paths: ["/tmp/**"], destructive: false, origin: "tui", createdAt: "" };
    expect(grantMatches(g, seg({ targets: ["/tmp/a"], verb: "mv" }))).toBe(false);
    expect(grantMatches(g, seg({ targets: ["/tmp/a"], verb: "rm", kind: "readonly" }))).toBe(false);
  });

  it("host-scoped net grants", () => {
    const g = { id: "x", verb: "curl", kind: "net", hosts: ["api.x.com"], destructive: false, origin: "telegram", createdAt: "" };
    expect(grantMatches(g, seg({ verb: "curl", kind: "net", hosts: ["api.x.com"] }))).toBe(true);
    expect(grantMatches(g, seg({ verb: "curl", kind: "net", hosts: ["api.x.com", "evil.com"] }))).toBe(false);
    expect(grantMatches(g, seg({ verb: "curl", kind: "net", hosts: [] }))).toBe(false);
  });

  it("path-grant requires at least one target", () => {
    const g = { id: "x", verb: "rm", kind: "write-outside", paths: ["/tmp/**"], destructive: false, origin: "tui", createdAt: "" };
    expect(grantMatches(g, seg({ targets: [] }))).toBe(false);
  });
});

describe("GrantStore", () => {
  it("session grants clear; forever grants persist", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "g-"));
    const file = path.join(dir, "g.json");
    const s1 = new GrantStore(file);
    s1.add({ id: "1", verb: "rm", kind: "write-outside", paths: ["/tmp/**"], destructive: false, origin: "tui", createdAt: "" }, true);
    s1.add({ id: "2", verb: "curl", kind: "net", hosts: ["a.b"], destructive: false, origin: "tui", createdAt: "" }, false);
    const s2 = new GrantStore(file);
    expect(s2.granted(seg({ verb: "rm", targets: ["/tmp/z"] }))).not.toBeNull();
    expect(s2.granted(seg({ verb: "curl", kind: "net", hosts: ["a.b"] }))).toBeNull();
    s2.clearSession();
    expect(s2.granted(seg({ verb: "curl", kind: "net", hosts: ["a.b"] }))).toBeNull();
  });
});

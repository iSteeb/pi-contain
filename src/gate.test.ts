import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { gateToolCallSync, persistGrant } from "./gate.ts";
import { DEFAULTS, type ContainConfig } from "./config.ts";
import { GrantStore } from "./grants.ts";

let ws: string;
let cfg: ContainConfig;
let grants: GrantStore;

beforeEach(() => {
  ws = mkdtempSync(path.join(tmpdir(), "gate-"));
  cfg = {
    ...DEFAULTS,
    sandbox: { enabled: true, writable: ["$WORKSPACE", "/tmp"], network: false },
    selfPaths: ["/opt/guard", "/opt/guard/c.json", "/opt/guard/g.json"],
    protectWrite: ["/opt/extensions", "/opt/git"],
    configPath: "/opt/guard/c.json",
    grantsPath: path.join(ws, "grants.json"),
  };
  grants = new GrantStore(cfg.grantsPath);
});
afterEach(() => rmSync(ws, { recursive: true, force: true }));

describe("gateToolCallSync — N1: write/edit/read/bash wiring", () => {
  it("write into protectWrite tree is denied", () => {
    const d = gateToolCallSync("write", { path: "/opt/extensions/evil.ts", content: "x" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "deny" });
  });

  it("edit into protectWrite tree is denied", () => {
    const d = gateToolCallSync("edit", { path: "/opt/extensions/hypr.ts", edits: [] }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "deny" });
  });

  it("write to guard config (selfPaths) is denied", () => {
    const d = gateToolCallSync("write", { path: "/opt/guard/c.json", content: "{}" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "deny" });
  });

  it("write to a secret is denied", () => {
    const d = gateToolCallSync("write", { path: `${ws}/.env`, content: "X=1" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "deny" });
  });

  it("read of a secret is denied", () => {
    const d = gateToolCallSync("read", { path: "~/.ssh/id_rsa" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "deny" });
  });

  it("ordinary write is allowed", () => {
    const d = gateToolCallSync("write", { path: `${ws}/notes.md`, content: "hi" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "allow" });
  });

  it("bash sandboxable is wrapped; unknown tools unhandled; mode off allows", () => {
    const d = gateToolCallSync("bash", { command: "rm -rf build" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "allow" });
    if (d !== "unhandled" && d.action === "allow") expect(d.command).toContain("bwrap");
    expect(gateToolCallSync("grep", { pattern: "x" }, ws, { cfg, grants })).toBe("unhandled");
    expect(gateToolCallSync("write", { path: "/opt/extensions/x" }, ws, { cfg: { ...cfg, mode: "off" }, grants })).toMatchObject({ action: "allow" });
  });

  it("bash secret access denied via gate", () => {
    const d = gateToolCallSync("bash", { command: "cat ~/.ssh/config" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "deny" });
  });

  it("net command asks via gate and session grant round-trips", async () => {
    const d = gateToolCallSync("bash", { command: "curl -X POST https://api.x.com/h" }, ws, { cfg, grants });
    expect(d).toMatchObject({ action: "ask" });
    if (d !== "unhandled" && d.action === "ask") {
      persistGrant(d.request, "session", "telegram", grants);
      const d2 = gateToolCallSync("bash", { command: "curl -X POST https://api.x.com/other" }, ws, { cfg, grants });
      expect(d2).toMatchObject({ action: "allow" });
    }
  });
});

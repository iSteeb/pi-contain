import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { decideBash, decideFile, grantFromDecision, scopeLabel } from "./pipeline.ts";
import { DEFAULTS, type ContainConfig } from "./config.ts";
import { GrantStore } from "./grants.ts";
import type { SegEval } from "./classify.ts";
import { sandboxAvailable, resetProbe } from "./sandbox.ts";

let ws: string;
let cfg: ContainConfig;
let grants: GrantStore;

beforeEach(() => {
  ws = mkdtempSync(path.join(tmpdir(), "pipe-"));
  cfg = {
    ...DEFAULTS,
    sandbox: { enabled: true, writable: ["$WORKSPACE", "/tmp"], network: false },
    selfPaths: ["/opt/guard"],
    configPath: "/opt/guard/c.json",
    grantsPath: path.join(ws, "grants.json"),
  };
  grants = new GrantStore(cfg.grantsPath);
  resetProbe();
  if (!sandboxAvailable()) cfg.sandbox.enabled = false;
});
afterEach(() => rmSync(ws, { recursive: true, force: true }));

describe("decideBash", () => {
  it("safe command passes unmodified", () => {
    const d = decideBash("ls | grep x", ws, { cfg, grants });
    expect(d).toEqual({ action: "allow" });
  });

  it("sandboxable command is wrapped", () => {
    const d = decideBash("rm -rf build", ws, { cfg, grants }) as { action: "allow"; command?: string };
    expect(d.action).toBe("allow");
    expect(d.command).toContain("bwrap");
  });

  it("secret access denied without prompt", () => {
    const d = decideBash("cat ~/.ssh/id_rsa", ws, { cfg, grants });
    expect(d.action).toBe("deny");
  });

  it("net command asks with breadth option and explicit scopes", () => {
    const d = decideBash("curl -X POST https://api.x.com/hook", ws, { cfg, grants });
    expect(d.action).toBe("ask");
    if (d.action === "ask") {
      expect(d.request.options).toContain("forever");
      expect(d.request.breadth?.hosts).toEqual(["api.x.com"]);
      expect(d.request.scopes.session).toBe("curl → api.x.com");
      expect(d.request.scopes.forever).toBe("curl → api.x.com");
    }
  });

  it("destructive verbs get no forever option (breadth cap)", () => {
    const d = decideBash("rm -rf ~/projects", ws, { cfg, grants });
    expect(d.action).toBe("ask");
    if (d.action === "ask") expect(d.request.options).not.toContain("forever");
  });

  it("session grant from a decision suppresses the next ask", () => {
    const d = decideBash("curl -X POST https://api.x.com/hook", ws, { cfg, grants });
    if (d.action !== "ask") throw new Error("expected ask");
    const g = grantFromDecision(d.request, "telegram");
    expect(g).not.toBeNull();
    grants.add(g!, false);
    const d2 = decideBash("curl -X POST https://api.x.com/other", ws, { cfg, grants });
    expect(d2.action).toBe("allow");
    const d3 = decideBash("curl https://evil.com", ws, { cfg, grants });
    expect(d3.action).toBe("ask");
  });

  it("session on breadthless asks persists a verb-class grant (honestly labeled)", () => {
    const d = decideBash("git push origin main", ws, { cfg, grants });
    if (d.action !== "ask") throw new Error("expected ask");
    expect(d.request.breadth).toBeUndefined();
    expect(d.request.scopes.session).toContain("git push (any host)");
    expect(d.request.options).not.toContain("forever");
    const g = grantFromDecision(d.request, "tui");
    expect(g).not.toBeNull(); // session always persists something
    grants.add(g!, false);
    // same verb class, different remote/branch — covered by the session grant
    expect(decideBash("git push other-remote release", ws, { cfg, grants }).action).toBe("allow");
    // different net verb still asks
    expect(decideBash("curl https://x.com", ws, { cfg, grants }).action).toBe("ask");
  });

  it("path grants are scoped by subtree", () => {
    const d = decideBash("mkdir -p /opt/data/x", ws, { cfg, grants });
    if (d.action !== "ask") throw new Error("expected ask");
    expect(d.request.scopes.session).toContain("under /opt/data/**");
    const g = grantFromDecision(d.request, "tui");
    grants.add(g!, true);
    expect(decideBash("mkdir -p /opt/data/y/z", ws, { cfg, grants }).action).toBe("allow");
    expect(decideBash("mkdir -p /opt/other", ws, { cfg, grants }).action).toBe("ask");
  });
});

describe("scopeLabel", () => {
  it("system asks are verb-class scoped and forever-less", () => {
    const e: SegEval = { verdict: "ask", reason: "", kind: "system", verb: "sudo", targets: [], hosts: [] };
    expect(scopeLabel(e, undefined)).toBe("sudo (this command class)");
  });
  it("write-outside with exact targets labels them", () => {
    const e: SegEval = { verdict: "ask", reason: "", kind: "write-outside", verb: "mkdir", targets: ["/x"], hosts: [] };
    expect(scopeLabel(e, undefined)).toContain("on exactly /x");
  });
});

describe("decideFile", () => {
  it("read of normal file allowed", () => {
    expect(decideFile("read", "src/index.ts", ws, { cfg, grants }).action).toBe("allow");
  });

  it("read of secrets denied", () => {
    expect(decideFile("read", "~/.aws/credentials", ws, { cfg, grants }).action).toBe("deny");
  });

  it("write to guard files denied (self-protection)", () => {
    expect(decideFile("write", "/opt/guard/c.json", ws, { cfg, grants }).action).toBe("deny");
  });

  it("write to read-only globs asks with explicit scope", () => {
    const d = decideFile("edit", "node_modules/x/index.js", ws, { cfg, grants });
    expect(d.action).toBe("ask");
    if (d.action === "ask") expect(d.request.scopes.session).toContain("under");
    if (d.action === "ask") expect(d.request.scopes.session).toContain("node_modules");
  });

  it("normal write allowed", () => {
    expect(decideFile("write", "src/new.ts", ws, { cfg, grants }).action).toBe("allow");
  });
});

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { evaluateCommand, type EvalDeps } from "./classify.ts";
import { DEFAULTS, type ContainConfig } from "./config.ts";

let ws: string;
let cfg: ContainConfig;

beforeEach(() => {
  ws = mkdtempSync(path.join(tmpdir(), "contain-"));
  cfg = { ...DEFAULTS, selfPaths: ["/opt/guard"], configPath: "/opt/guard/c.json", grantsPath: "/opt/guard/g.json" };
  cfg.sandbox = { enabled: true, writable: ["$WORKSPACE", "/tmp"], network: false };
});
afterEach(() => rmSync(ws, { recursive: true, force: true }));

const deps = (over: Partial<EvalDeps> = {}): EvalDeps => ({
  cfg,
  sandboxAvail: true,
  granted: () => false,
  ...over,
});

describe("evaluateCommand", () => {
  it("read-only pipelines are safe", () => {
    expect(evaluateCommand("ls a b | grep xyz", ws, deps()).action).toBe("allow");
    expect(evaluateCommand("ls a b | grep abc", ws, deps()).action).toBe("allow");
    expect(evaluateCommand("git status && git diff", ws, deps()).action).toBe("allow");
    expect(evaluateCommand("cat notes.md", ws, deps()).action).toBe("allow");
  });

  it("git: read-only subs safe incl. in chains", () => {
    expect(evaluateCommand("git log --oneline | grep abc", ws, deps()).action).toBe("allow");
    expect(evaluateCommand("git show HEAD:src/x.ts | head -20", ws, deps()).action).toBe("allow");
  });

  it("git: network subs ask (net) even mid-chain", () => {
    const r = evaluateCommand("git add -A && git commit -m x && git push origin main", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.blocker!.kind).toBe("net");
    expect(r.blocker!.verb).toBe("git push");
    expect(r.reason).toContain("git push");
  });

  it("git: local mutation is sandboxed in workspace", () => {
    expect(evaluateCommand("git add src/x.ts && git commit -m 'x'", ws, deps()).action).toBe("sandbox");
  });

  it("git: -C flag paths are targets (outside workspace asks)", () => {
    const r = evaluateCommand("git -C /etc status", ws, deps());
    expect(r.action).toBe("ask");
  });

  it("writes inside workspace sandbox", () => {
    expect(evaluateCommand("rm -rf build", ws, deps()).action).toBe("sandbox");
    expect(evaluateCommand("echo x > /tmp/out.txt", ws, deps()).action).toBe("sandbox");
  });

  it("secret reads are hard-denied even for cat", () => {
    const r = evaluateCommand("cat ~/.ssh/id_rsa", ws, deps());
    expect(r.action).toBe("deny");
    expect(r.reason).toContain("secret");
  });

  it("workspace .env is denied", () => {
    writeFileSync(path.join(ws, ".env"), "X=1");
    const r = evaluateCommand("cat .env", ws, deps());
    expect(r.action).toBe("deny");
  });

  it("self-protection denies writes to guard files", () => {
    const r = evaluateCommand("rm -rf /opt/guard/c.json", ws, deps());
    expect(r.action).toBe("deny");
    expect(r.reason).toContain("self-protection");
  });

  it("net verbs ask with hosts for curl", () => {
    const r = evaluateCommand("curl -X POST https://api.x.com/hook", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.blocker!.hosts).toEqual(["api.x.com"]);
  });

  it("system verbs always ask", () => {
    expect(evaluateCommand("sudo rm /x", ws, deps()).action).toBe("ask");
    expect(evaluateCommand("systemctl restart nginx", ws, deps()).action).toBe("ask");
  });

  it("writes outside workspace ask (rm -rf /home)", () => {
    const r = evaluateCommand("rm -rf /home", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.blocker!.kind).toBe("write-outside");
  });

  it("path traversal cannot smuggle targets into writable set", () => {
    const r = evaluateCommand("rm -rf /tmp/../home", ws, deps());
    expect(r.action).toBe("ask");
  });

  it("undecidable commands run sandboxed when available", () => {
    expect(evaluateCommand('python -c "x=1"', ws, deps()).action).toBe("sandbox");
    expect(evaluateCommand("R=$(echo rm); $R -rf /etc", ws, deps()).action).toBe("sandbox");
  });

  it("literal var verbs resolve and get precise verdicts", () => {
    const r = evaluateCommand("R=rm; $R -rf /etc", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.blocker!.kind).toBe("write-outside");
  });

  it("without sandbox, undecidable asks (fail closed)", () => {
    expect(evaluateCommand("R=rm; $R -rf /etc", ws, deps({ sandboxAvail: false })).action).toBe("ask");
  });

  it("chain context: cd is tracked for later segments", () => {
    const sub = path.join(ws, "sub");
    mkdirSync(sub);
    const r = evaluateCommand("cd /etc && rm passwd", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.blocker!.targets[0]).toBe("/etc/passwd");
  });

  it("literal variable assignments resolve targets", () => {
    const r = evaluateCommand("F=/tmp/x; rm -rf $F", ws, deps());
    expect(r.action).toBe("sandbox");
  });

  it("grants suppress asks", () => {
    const r = evaluateCommand("curl -s https://api.x.com/h", ws, deps({ granted: (e) => e.kind === "net" && e.hosts.includes("api.x.com") }));
    expect(r.action).toBe("allow");
  });

  it("readOnly globs ask on write", () => {
    const r = evaluateCommand("rm -rf node_modules", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.blocker!.kind).toBe("readonly");
  });

  it("first blocker wins with precise reason", () => {
    const r = evaluateCommand("rg x src && curl https://evil.x.com", ws, deps());
    expect(r.action).toBe("ask");
    expect(r.reason).toContain("curl");
  });

  it("parse failures are undecidable (sandbox or ask)", () => {
    expect(evaluateCommand('echo "unclosed', ws, deps()).action).toBe("sandbox");
    expect(evaluateCommand('echo "unclosed', ws, deps({ sandboxAvail: false })).action).toBe("ask");
  });
});

describe("audit regressions", () => {
  const auditDeps = (over: Partial<EvalDeps> = {}): EvalDeps => ({
    cfg: { ...cfg, protectWrite: ["/opt/extensions", "/opt/git"], secrets: [...cfg.secrets, "/opt/creds/auth.json"] },
    sandboxAvail: true,
    granted: () => false,
    ...over,
  });

  it("C1: unquoted-heredoc substitution is contained, never safe", () => {
    expect(evaluateCommand("cat <<EOF\n$(touch ~/proof)\nEOF", ws, auditDeps()).action).toBe("sandbox");
  });

  it("C1: quoted heredoc remains safe", () => {
    expect(evaluateCommand("cat <<'EOF'\n$(touch ~/proof)\nEOF", ws, auditDeps()).action).toBe("allow");
  });

  it("C2: read-redirect to a secret is denied", () => {
    expect(evaluateCommand("wc -c < ~/.ssh/id_ed25519", ws, auditDeps()).action).toBe("deny");
    expect(evaluateCommand("cat < ~/.ssh/config", ws, auditDeps()).action).toBe("deny");
  });

  it("H5: env/printenv are not read-only — they sandbox (scrubbed env)", () => {
    expect(evaluateCommand("printenv", ws, auditDeps()).action).toBe("sandbox");
    expect(evaluateCommand("env", ws, auditDeps()).action).toBe("sandbox");
  });

  it("C3: find -exec and xargs payloads are always contained", () => {
    expect(evaluateCommand("find /etc -name passwd -exec cat {} ;", ws, auditDeps()).action).toBe("sandbox");
    expect(evaluateCommand("xargs rm < list.txt", ws, auditDeps()).action).toBe("sandbox");
  });

  it("M5: git branch -D / remote add are not read-only", () => {
    expect(evaluateCommand("git branch -D feat", ws, auditDeps()).action).toBe("sandbox");
    expect(evaluateCommand("git remote add origin https://x", ws, auditDeps()).action).toBe("sandbox");
  });

  it("M2: ~otheruser paths are unknown → contained", () => {
    expect(evaluateCommand("cat ~duzevich/.aws/credentials", ws, auditDeps()).action).toBe("sandbox");
  });

  it("C5: writes into extension/package trees are denied", () => {
    const r = evaluateCommand("echo pwn > /opt/extensions/evil.ts", ws, auditDeps());
    expect(r.action).toBe("deny");
    expect(r.reason).toContain("extension-code protection");
  });

  it("agent credential files are secrets", () => {
    expect(evaluateCommand("cat /opt/creds/auth.json", ws, auditDeps()).action).toBe("deny");
  });

  it("approvals carry a per-segment breakdown", () => {
    const r = evaluateCommand("ls | grep x && curl https://a.b", ws, auditDeps());
    expect(r.action).toBe("ask");
    expect(r.breakdown).toContain("curl[ask]");
    expect(r.breakdown).toContain("[safe]");
  });
});

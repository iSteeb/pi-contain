import { describe, expect, it, beforeAll } from "vitest";
import { execSync } from "node:child_process";
import { mkdtempSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import path from "node:path";
import { buildWrap, sandboxAvailable, resetProbe } from "./sandbox.ts";
import { DEFAULTS, type ContainConfig } from "./config.ts";

let ws: string;
const cfg: ContainConfig = {
  ...DEFAULTS,
  sandbox: { enabled: true, writable: ["$WORKSPACE", "/tmp"], network: false },
  selfPaths: ["/nonexistent-guard"],
  configPath: "/nonexistent-guard/c.json",
  grantsPath: "/nonexistent-guard/g.json",
};

beforeAll(() => {
  ws = mkdtempSync(path.join(tmpdir(), "sbx-"));
});

describe("buildWrap", () => {
  it("wraps with ro-root, writable binds, full isolation, scrubbed env", () => {
    const w = buildWrap("echo hi", cfg, ws);
    expect(w).toContain("bwrap ");
    expect(w).toContain("'--ro-bind' '/' '/'");
    expect(w).toContain(`'--bind' '${ws}' '${ws}'`);
    expect(w).toContain("'--bind' '/tmp' '/tmp'");
    expect(w).toContain("'--unshare-all'");
    expect(w).toContain("'--clearenv'");
    expect(w).toContain("'--setenv' 'PATH'");
    expect(w).toContain("'--die-with-parent'");
    expect(w.endsWith(`'/bin/sh' '-c' 'echo hi'`)).toBe(true);
  });
});

describe("bwrap integration (real)", () => {
  it("sandbox is available on this host", () => {
    resetProbe();
    expect(sandboxAvailable()).toBe(true);
  });

  it("can write inside /tmp", () => {
    execSync(buildWrap("echo x > /tmp/pi-contain-it && cat /tmp/pi-contain-it", cfg, ws));
    expect(existsSync("/tmp/pi-contain-it")).toBe(true);
    execSync("rm -f /tmp/pi-contain-it");
  });

  it("cannot write outside writable set", () => {
    const f = path.join(homedir(), ".pi-contain-it");
    expect(() =>
      execSync(buildWrap(`echo x > ${f}`, cfg, ws), { stdio: "pipe" }),
    ).toThrow();
    expect(existsSync(f)).toBe(false);
  });

  it("cannot write to non-writable dirs outside workspace", () => {
    const f = "/var/tmp/pi-contain-escape";
    expect(() =>
      execSync(buildWrap(`echo x > ${f}`, cfg, ws), { stdio: "pipe" }),
    ).toThrow();
    expect(existsSync(f)).toBe(false);
  });

  it("has no network", () => {
    let out = "";
    try {
      out = execSync(buildWrap("curl -s -m 3 https://example.com || echo NETFAIL", cfg, ws), { encoding: "utf8" });
    } catch (e) {
      out = (e as { stdout?: string }).stdout ?? "NETFAIL";
    }
    expect(out).toContain("NETFAIL");
  });

  it("masks secrets inside the sandbox", () => {
    // ~/.ssh exists on this host; inside the sandbox it is an empty tmpfs
    const out = execSync(
      buildWrap(
        "test -e ~/.ssh/config && echo LEAKED || echo MASKED; test -e ~/.ssh/id_rsa && echo LEAKED2 || echo MASKED2",
        cfg,
        ws,
      ),
      { encoding: "utf8" },
    );
    expect(out).toContain("MASKED");
    expect(out).toContain("MASKED2");
    expect(out).not.toContain("LEAKED");
  });

  it("undecidable obfuscated rm is contained", () => {
    const target = path.join(homedir(), ".pi-contain-decoy");
    writeFileSync(target, "x");
    expect(() =>
      execSync(buildWrap("R=rm; $R -f " + target, cfg, ws), { stdio: "pipe" }),
    ).toThrow();
    expect(existsSync(target)).toBe(true);
    execSync(`rm -f ${JSON.stringify(target)}`);
  });

  it("environment is scrubbed (no host secrets inside)", () => {
    const out = execSync(buildWrap("printenv | wc -l; printenv DEEPL_API_KEY | wc -c", cfg, ws), { encoding: "utf8" });
    const [envCount, deepLen] = out.trim().split("\n").map(Number);
    expect(envCount).toBeLessThan(10);
    expect(deepLen).toBe(0);
  });

  it("pid namespace isolated (no host processes visible)", () => {
    const out = execSync(buildWrap("ls /proc | grep -cE '^[0-9]+$'", cfg, ws), { encoding: "utf8" });
    expect(Number(out.trim())).toBeLessThanOrEqual(8);
  });

  it("slashless glob secrets are masked in workspace and home", () => {
    const envLocal = path.join(ws, ".env.local");
    writeFileSync(envLocal, "SECRET=1");
    const out = execSync(buildWrap("cat .env.local 2>&1 || echo MASKED", cfg, ws), { encoding: "utf8" });
    expect(out).toContain("MASKED");
  });

  it("approved write-outside sandbox: extra dirs writable, rest not", () => {
    const dir = path.join(homedir(), ".pi-contain-approved");
    mkdirSync(dir, { recursive: true });
    execSync(buildWrap(`echo ok > ${dir}/f`, cfg, ws, [dir]));
    expect(existsSync(path.join(dir, "f"))).toBe(true);
    expect(() => execSync(buildWrap(`echo x > ${homedir()}/.nope`, cfg, ws, [dir]), { stdio: "pipe" })).toThrow();
    execSync(`rm -rf ${JSON.stringify(dir)}`);
  });
});

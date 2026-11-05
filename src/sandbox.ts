import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { agentDir, type ContainConfig } from "./config.ts";
import { globToRegExp } from "./classify.ts";

let probed: boolean | null = null;

/** Probe once with the FULL profile: if the real flags can't run here, the
 * guard must ask rather than wrap-and-explode. Fail closed (false). */
export function sandboxAvailable(): boolean {
  if (probed !== null) return probed;
  try {
    execFileSync(
      "bwrap",
      ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/run",
       "--unshare-all", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "true"],
      { timeout: 5000, stdio: "ignore" },
    );
    probed = true;
  } catch {
    probed = false;
  }
  return probed;
}

export function resetProbe(): void {
  probed = null;
}

export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Bounded recursive enumeration of a path glob under a root. */
function enumerateGlob(root: string, glob: string, maxDepth: number, maxMatches = 64): string[] {
  const re = globToRegExp(glob);
  const out: string[] = [];
  const skip = new Set([".cache", "node_modules", ".git", ".cargo", ".rustup"]); // .local NOT skipped: ~/.local/share is a real cert location
  const walk = (dir: string, depth: number) => {
    if (out.length >= maxMatches || depth > maxDepth) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable dir: nothing to enumerate
    }
    for (const e of entries) {
      if (out.length >= maxMatches) return;
      const p = path.join(dir, e.name);
      if (re.test(p)) {
        out.push(p);
        continue;
      }
      if (e.isDirectory() && !skip.has(e.name)) walk(p, depth + 1);
    }
  };
  walk(root, 0);
  return out;
}

/** Concrete paths to mask inside the sandbox (secrets + guard files). */
export function maskPaths(cfg: ContainConfig, cwd?: string): { dirs: string[]; files: string[] } {
  const dirs = new Set<string>();
  const files = new Set<string>();
  const addCandidate = (p: string) => {
    const st = statSafe(p);
    if (st?.isDirectory()) dirs.add(p);
    else if (st?.isFile()) files.add(p);
  };
  const addGlobMatches = (pattern: string, dir: string) => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return; // unreadable dir: nothing to enumerate
    }
    const re = globToRegExp(pattern);
    for (const n of names) if (re.test(n)) addCandidate(path.join(dir, n));
  };
  for (const g of [...cfg.secrets, ...cfg.selfPaths]) {
    const expanded = g.replace(/^~(?=\/|$)/, homedir());
    if (expanded.includes("*")) {
      // `dir/**` → mask the whole dir
      const m = /^(.*)\/\*\*$/.exec(expanded);
      if (m) { addCandidate(m[1]); continue; }
      if (!expanded.includes("/")) {
        // slashless wildcard (`.env.*`): enumerate workspace + home top-level
        if (cwd) addGlobMatches(expanded, cwd);
        addGlobMatches(expanded, homedir());
        continue;
      }
      // slash-bearing wildcard (`**/*.pem`, `**/id_rsa*`): bounded recursive
      // enumeration under home (shallow) and workspace (deep)
      for (const p of enumerateGlob(homedir(), expanded, 3)) addCandidate(p);
      if (cwd && cwd !== homedir())
        for (const p of enumerateGlob(cwd, expanded, 8)) addCandidate(p);
      continue;
    }
    if (expanded.includes("/")) {
      addCandidate(expanded);
    } else if (cwd) {
      // slashless concrete basename (e.g. `.env`): mask it inside the workspace
      addCandidate(path.join(cwd, expanded));
    }
  }
  // whole guard dir
  const guardDir = cfg.selfPaths[0];
  if (statSafe(guardDir)?.isDirectory()) dirs.add(guardDir);
  return { dirs: [...dirs], files: [...files] };
}

function statSafe(p: string) {
  try {
    return statSync(p);
  } catch {
    return null;
  }
}

/**
 * Wrap a command in a bubblewrap sandbox: read-only root, selected writable
 * binds, secrets/guard files masked, no network, isolated PID/IPC namespaces,
 * scrubbed environment. Returns the full command string to execute instead
 * of the original.
 */
export function buildWrap(
  command: string,
  cfg: ContainConfig,
  cwd: string,
  extraWritable: string[] = [],
): string {
  const args: string[] = ["--ro-bind", "/", "/"];
  args.push("--dev", "/dev", "--proc", "/proc", "--tmpfs", "/run");
  args.push("--unshare-all"); // pid, ipc, uts, net, cgroup, user
  args.push("--clearenv");
  // Host PATH (not a secret) so mise/nix/volta-installed binaries resolve;
  // fall back to system paths if unset.
  args.push("--setenv", "PATH", process.env.PATH || "/usr/local/bin:/usr/bin:/bin");
  args.push("--setenv", "HOME", homedir());
  args.push("--setenv", "TERM", "dumb");
  args.push("--setenv", "TMPDIR", "/tmp");
  args.push("--setenv", "LANG", "C.UTF-8");
  const writable = [...cfg.sandbox.writable.map((w) =>
    w === "$WORKSPACE" ? cwd : w.replace(/^~(?=\/|$)/, homedir()),
  ), ...extraWritable];
  for (const w of writable) {
    if (existsSync(w)) args.push("--bind", w, w);
  }
  // Policy re-assert AFTER binds: agent state, extension/package trees and
  // guard files are read-only even when a writable bind covers them (mount
  // order: later mounts override earlier ones).
  const roTrees = new Set<string>([...cfg.protectWrite, ...cfg.selfPaths]);
  const agentState = agentDir(); // ~/.pi/agent (or PI_AGENT_DIR)
  if (agentState !== "/" && existsSync(agentState)) roTrees.add(agentState);
  for (const p of roTrees) {
    if (existsSync(p)) args.push("--ro-bind", p, p);
  }
  // Secrets masked last: unreadable beats read-only
  const { dirs, files } = maskPaths(cfg, cwd);
  for (const d of dirs) args.push("--tmpfs", d);
  for (const f of files) args.push("--ro-bind", "/dev/null", f);
  // /tmp is often writable — keep the X11 socket out of reach even so
  if (existsSync("/tmp/.X11-unix")) args.push("--tmpfs", "/tmp/.X11-unix");
  args.push("--die-with-parent", "--new-session", "/bin/sh", "-c", command);
  return `bwrap ${args.map((a) => shellQuote(a)).join(" ")}`;
}

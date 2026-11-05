import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { ContainConfig } from "./config.ts";
import { isWriteRedirect, parseSegments, type Segment, type XWord } from "./segments.ts";

// ---------------------------------------------------------------- verb tables

const READONLY = new Set([
  "ls", "cat", "head", "tail", "wc", "sort", "uniq", "cut", "file", "stat",
  "du", "df", "pwd", "echo", "printf", "whoami", "id", "uname", "date",
  "hostname", "which", "type", "tree", "jq", "rg", "grep",
  "find", "basename", "dirname", "realpath", "readlink",
  "md5sum", "sha256sum", "diff", "cmp", "xxd", "base64",
]);
// NOTE: `env`/`printenv` deliberately NOT here — they dump the host env
// (API keys) unsandboxed. They fall through to sandbox-with-scrubbed-env.

/** git subcommands that hit the network → ask(net), grants apply. */
const GIT_NET = new Set(["push", "pull", "fetch", "clone", "ls-remote", "submodule"]);

const GIT_RO = new Set([
  "status", "diff", "log", "show", "blame", "ls-files", "rev-parse",
  "describe", "shortlog", "cat-file", "grep", "cherry", "count-objects",
  "name-rev",
]);
// branch/tag/remote/reflog removed: their mutating flags (-D, -f, add,
// delete, expire…) are indistinguishable cheaply — they sandbox instead.

const STATE = new Set([
  "cd", "pushd", "popd", "export", "set", "unset", "shift", "alias",
  "unalias", "umask", "true", "false", ":", "return", "break", "continue",
  "local", "readonly", "declare", "typeset",
]);

const NET = new Set([
  "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "socat",
  "dig", "nslookup", "host", "ping", "ftp", "telnet", "npm", "pnpm", "yarn",
  "pip", "pip3", "uv", "poetry", "cargo", "go", "docker", "podman",
  "helm", "kubectl", "terraform", "tofu", "npx", "pnpx", "bunx", "uvx",
  "pipx", "gh", "aws", "gcloud", "az", "brew", "apt", "apt-get", "dnf",
  "yum", "pacman", "snap", "flatpak", "redis-cli", "psql", "mysql",
]);
// `xargs` deliberately NOT here: its payload is unknowable from argv — it
// is always contained (sandbox) instead.

/** Never sandboxed, always ask, forever-grants capped/forbidden. */
export const SYSTEM_ASK = new Set([
  "sudo", "doas", "pkexec", "systemctl", "service", "mount", "umount",
  "swapon", "swapoff", "iptables", "nft", "ufw", "firewall-cmd", "crontab",
  "shutdown", "reboot", "poweroff", "halt", "kill", "killall", "pkill",
  "useradd", "usermod", "userdel", "groupadd", "modprobe", "rmmod",
  "chattr", "setcap", "mkfs", "wipefs", "blkdiscard", "visudo", "sysctl",
]);

/** Forever grants forbidden for these (breadth cap). */
export const DESTRUCTIVE = new Set([
  "rm", "rmdir", "unlink", "truncate", "dd", "mkfs", "wipefs", "chmod",
  "chown", "chgrp", "shred", "mv",
]);

/** Verbs where every non-flag argument is a filesystem target. */
const WRITE = new Set([
  "rm", "rmdir", "unlink", "mkdir", "touch", "mv", "cp", "ln",
  "truncate", "chmod", "chown", "chgrp", "dd", "tar", "gzip",
  "gunzip", "zip", "unzip", "install", "shred", "tee",
]);

const FIND_UNSAFE_ARG = /^-(delete|exec(dir)?|ok(dir)?|f(print|printf|ls)\w*)$/;
const findIsUnsafe = (args: (string | null)[]) => args.some((a) => a !== null && FIND_UNSAFE_ARG.test(a));

// ------------------------------------------------------------------- globbing

export function globToRegExp(pattern: string): RegExp {
  let p = pattern.replace(/^~(?=\/|$)/, homedir());
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") {
      if (p.slice(i, i + 3) === "**/") { re += "(?:.*/)?"; i += 2; }
      else if (p.slice(i, i + 2) === "**") { re += ".*"; i += 1; }
      else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function globMatch(globs: string[], target: string): boolean {
  return globs.some((g) => {
    // `dir/**` should also match the directory itself
    if (/\/\*\*$/.test(g)) {
      const re2 = globToRegExp(g.replace(/\/\*\*$/, ""));
      if (re2.test(target)) return true;
    }
    const re = globToRegExp(g);
    // slashless patterns are basenames: match at any depth
    if (!g.includes("/")) return re.test(target) || re.test(target.split("/").pop()!);
    return re.test(target);
  });
}

// ----------------------------------------------------------------- resolution

export interface ChainCtx {
  cwd: string;
  vars: Map<string, string>;
}

/** Resolve a word to a string, or null when not statically known. */
export function wordValue(w: XWord, ctx: ChainCtx): string | null {
  if (w.literal) {
    // `~otheruser/…` expands against a home we cannot know — unknown, so
    // the segment degrades to containment instead of "safe".
    if (/^~[^/]/.test(w.text)) return null;
    return w.text;
  }
  const m = /^\$([A-Za-z_]\w*)$/.exec(w.text);
  if (m && ctx.vars.has(m[1])) return ctx.vars.get(m[1])!;
  return null;
}

/** Resolve to an absolute, traversal-safe path. Returns null if unknown. */
export function resolveTarget(raw: string, ctx: ChainCtx): string | null {
  // `~otheruser/...` resolves against ANOTHER home — we can't know it.
  // Treat as unknown so the segment degrades to containment.
  if (/^~[^/]/.test(raw)) return null;
  let s = raw;
  if (s.startsWith("~")) s = path.join(homedir(), s.slice(1));
  if (!path.isAbsolute(s)) s = path.resolve(ctx.cwd, s);
  const tail: string[] = [];
  let cur = s;
  while (cur !== "/" && !existsSync(cur)) {
    tail.unshift(path.basename(cur));
    cur = path.dirname(cur);
  }
  try {
    const real = realpathSync(cur);
    return path.normalize(tail.length ? path.join(real, ...tail) : real);
  } catch {
    return path.normalize(s);
  }
}

function isPathLike(s: string, ctx: ChainCtx): boolean {
  if (/^[./~]/.test(s)) return true;
  if (s.includes("/")) return true;
  const abs = path.resolve(ctx.cwd, s);
  return existsSync(abs);
}

// ----------------------------------------------------------------- evaluation

export type Verdict = "safe" | "sandbox" | "deny" | "ask";

export interface SegEval {
  verdict: Verdict;
  reason: string;
  kind: string; // net | write-outside | readonly | system | undecidable | sudo | secret | self
  verb: string;
  targets: string[];
  hosts: string[];
}

export interface EvalDeps {
  cfg: ContainConfig;
  sandboxAvail: boolean;
  /** Returns true when a grant covers this segment. */
  granted: (e: SegEval) => boolean;
}

function writableSet(cfg: ContainConfig, cwd: string): string[] {
  return cfg.sandbox.writable.map((w) =>
    w === "$WORKSPACE" ? cwd : w.replace(/^~(?=\/|$)/, homedir()),
  );
}

function parseHosts(verb: string, args: string[]): string[] {
  if (verb !== "curl" && verb !== "wget") return [];
  const hosts: string[] = [];
  for (const a of args) {
    const m = /^(?:https?|ssh|ftp):\/\/(?:[^@\/]+@)?([^\/:@]+)/.exec(a);
    if (m) hosts.push(m[1]);
    else if (/^[\w.-]+\.[a-z]{2,}/i.test(a)) hosts.push(a);
  }
  return hosts;
}

/** Targets that are never meaningful writes — stderr/stdout discards etc. */
const DEV_DEVICE = /^(\/dev\/(null|zero|full|stdout|stderr|tty|fd\/\d+))$/;

/** Interpreter verbs whose `-c` payload is opaque code. */
const INTERPRETER = new Set([
  "bash", "sh", "zsh", "dash", "ksh", "python", "python3", "node", "deno",
  "bun", "tsx", "perl", "ruby", "php", "awk", "gawk",
]);

function evaluateSegment(
  seg: Segment,
  ctx: ChainCtx,
  deps: EvalDeps,
  writable: string[],
): SegEval {
  const worst: SegEval = { verdict: "safe", reason: "", kind: "", verb: "", targets: [], hosts: [] };
  const worse = (e: SegEval) => {
    const rank = { safe: 0, sandbox: 1, ask: 2, deny: 3 } as const;
    if (rank[e.verdict] > rank[worst.verdict]) Object.assign(worst, e);
  };

  // chain context updates (assignments + cd) — literal only
  for (const a of seg.assignments) {
    const v = wordValue(a.value, ctx);
    if (v !== null) ctx.vars.set(a.name, v);
  }

  for (const cmd of seg.cmds) {
    const verbRaw = wordValue(cmd.verb, ctx);
    const args: (string | null)[] = cmd.args.map((a) => wordValue(a, ctx));

    // interpreter -c/-k payloads are opaque code: skip target analysis
    // entirely (script text must never match secrets/policy by accident)
    if (verbRaw !== null && INTERPRETER.has(verbRaw) && args.some((a) => a !== null && /^-[a-z]*[ck][a-z]*$/i.test(a))) {
      if (deps.sandboxAvail && deps.cfg.sandbox.enabled)
        worse({ verdict: "sandbox", reason: "interpreter payload is opaque; contained", kind: "undecidable", verb: verbRaw, targets: [], hosts: [] });
      else
        worse({ verdict: "ask", reason: "interpreter payload is opaque and sandbox unavailable", kind: "undecidable", verb: verbRaw, targets: [], hosts: [] });
      continue;
    }

    // collect candidate targets: path-like args + write redirects
    const targets: string[] = [];
    const unknownArgs = args.some((a) => a === null);
    const writeVerb = WRITE.has(verbRaw);
    for (const a of args) {
      if (a === null) continue;
      if (writeVerb ? !a.startsWith("-") : isPathLike(a, ctx)) {
        const r = resolveTarget(a, ctx);
        if (r) targets.push(r);
      }
    }
    const redirectTargets: string[] = [];
    const readRedirectTargets: string[] = [];
    for (const r of seg.redirects) {
      const t = wordValue(r.target, ctx);
      if (t === null) continue;
      if (DEV_DEVICE.test(t)) continue; // 2>/dev/null etc: not a policy target
      const rr = resolveTarget(t, ctx);
      if (rr === null) continue;
      if (isWriteRedirect(r)) redirectTargets.push(rr);
      else if (r.op === "<") readRedirectTargets.push(rr);
    }

    // ---- hard protects (args, write redirects, AND read redirects —
    // `wc -c < ~/.ssh/id_rsa` must not sail past the secret policy)
    const writeTargets = [...(writeVerb ? targets : []), ...redirectTargets];
    for (const t of [...targets, ...redirectTargets, ...readRedirectTargets]) {
      if (globMatch(deps.cfg.secrets, t)) {
        return { verdict: "deny", reason: `secret policy blocks ${t}`, kind: "secret", verb: verbRaw ?? cmd.verb.text, targets: [t], hosts: [] };
      }
      if (deps.cfg.selfPaths.some((p) => t === p || t.startsWith(p + "/"))) {
        return { verdict: "deny", reason: `guard self-protection blocks ${t}`, kind: "self", verb: verbRaw ?? cmd.verb.text, targets: [t], hosts: [] };
      }
      // loaded extension/package code: reads allowed, writes denied
      if (
        writeTargets.includes(t) &&
        deps.cfg.protectWrite.some((p) => t === p || t.startsWith(p.replace(/\/+$/, "") + "/"))
      ) {
        return { verdict: "deny", reason: `extension-code protection blocks write to ${t}`, kind: "self", verb: verbRaw ?? cmd.verb.text, targets: [t], hosts: [] };
      }
    }

    if (verbRaw === null) {
      // non-literal verb: containment or ask
      if (deps.sandboxAvail && deps.cfg.sandbox.enabled)
        worse({ verdict: "sandbox", reason: "non-literal verb", kind: "undecidable", verb: cmd.verb.text, targets, hosts: [] });
      else
        worse({ verdict: "ask", reason: "cannot statically determine the command", kind: "undecidable", verb: cmd.verb.text, targets, hosts: [] });
      continue;
    }
    const verb = verbRaw;

    // ---- state verbs
    if (STATE.has(verb)) {
      if (verb === "cd" || verb === "pushd") {
        const dst = args[0] ? resolveTarget(args[0], ctx) : null;
        if (dst) ctx.cwd = dst;
        else ctx.vars.clear(); // unknown cd: all later relative paths unknown
      }
      continue;
    }

    const hasWriteRedirect = redirectTargets.length > 0 || seg.redirects.some((r) => isWriteRedirect(r) && wordValue(r.target, ctx) === null);

    // ---- read-only (all args statically known, no expansions anywhere,
    // no write redirects — segment-level undecidable covers heredocs and
    // non-literal redirect targets)
    if (
      READONLY.has(verb) &&
      !unknownArgs &&
      !seg.undecidable &&
      !hasWriteRedirect &&
      (verb !== "find" || !findIsUnsafe(args))
    ) {
      continue; // safe
    }

    // ---- payload-unknowable verbs: find -exec/-delete/-ok, xargs — always
    // contained regardless of how tame the root looks
    if ((verb === "find" && findIsUnsafe(args)) || verb === "xargs") {
      if (deps.sandboxAvail && deps.cfg.sandbox.enabled)
        worse({ verdict: "sandbox", reason: "payload not statically knowable; contained", kind: "undecidable", verb, targets, hosts: [] });
      else
        worse({ verdict: "ask", reason: "payload not statically knowable and sandbox unavailable", kind: "undecidable", verb, targets, hosts: [] });
      continue;
    }

    const hosts = parseHosts(verb, args.filter((a): a is string => a !== null));
    const gitSub = verb === "git" ? (args.find((a) => a !== null && !a.startsWith("-")) ?? null) : null;

    // ---- git: read-only subs safe; network subs ask(net); local mutation confined
    if (verb === "git" && gitSub && !hasWriteRedirect) {
      if (GIT_RO.has(gitSub)) continue; // safe
      if (GIT_NET.has(gitSub)) {
        const e: SegEval = { verdict: "ask", reason: `git ${gitSub} needs network`, kind: "net", verb: `git ${gitSub}`, targets, hosts };
        if (deps.granted(e)) continue;
        worse(e);
        continue;
      }
      // local mutating git (add/commit/checkout/…) — containment rules below
    }

    // ---- net
    if (NET.has(verb) || deps.cfg.askVerbs.includes(verb)) {
      const e: SegEval = { verdict: "ask", reason: `${verb} needs network / external reach`, kind: "net", verb, targets, hosts };
      if (deps.granted(e)) continue;
      worse(e);
      continue;
    }

    // ---- system
    if (SYSTEM_ASK.has(verb)) {
      const e: SegEval = { verdict: "ask", reason: `${verb} affects the host system`, kind: "system", verb, targets, hosts };
      if (deps.granted(e)) continue;
      worse(e);
      continue;
    }

    // ---- writes / exec / unknown: readOnly policy first, then containment
    const allTargets = [...new Set([...targets, ...redirectTargets])];
    if (allTargets.some((t) => globMatch(deps.cfg.readOnly, t))) {
      const e: SegEval = { verdict: "ask", reason: `read-only policy: ${allTargets.join(", ")}`, kind: "readonly", verb, targets: allTargets, hosts };
      if (deps.granted(e)) continue;
      worse(e);
      continue;
    }
    if (allTargets.every((t) => writable.some((w) => t === w || t.startsWith(w.replace(/\/+$/, "") + "/")))) {
      worse({ verdict: "sandbox", reason: "effects confined to writable set", kind: "contained", verb, targets: allTargets, hosts });
      continue;
    }
    if (unknownArgs && allTargets.length === 0) {
      // unknown targets: containment (sandbox masks secrets, ro-bind root)
      if (deps.sandboxAvail && deps.cfg.sandbox.enabled)
        worse({ verdict: "sandbox", reason: "targets not statically known; contained", kind: "undecidable", verb, targets: [], hosts });
      else
        worse({ verdict: "ask", reason: "targets not statically known and sandbox unavailable", kind: "undecidable", verb, targets: [], hosts });
      continue;
    }
    // targets known and outside writable
    const e: SegEval = { verdict: "ask", reason: `writes outside the sandbox (${allTargets.join(", ")})`, kind: "write-outside", verb, targets: allTargets, hosts };
    if (deps.granted(e)) continue;
    worse(e);
  }
  return worst;
}

export interface EvalResult {
  action: "allow" | "sandbox" | "deny" | "ask";
  reason: string;
  blocker: SegEval | null;
  segments: number;
  /** Per-segment verdict summary for approval prompts. */
  breakdown: string;
}

export function evaluateCommand(
  command: string,
  cwd: string,
  deps: EvalDeps,
): EvalResult {
  let segments: Segment[];
  try {
    segments = parseSegments(command);
  } catch {
    return {
      action: deps.sandboxAvail && deps.cfg.sandbox.enabled ? "sandbox" : "ask",
      reason: "shell parse failed; command treated as undecidable",
      blocker: { verdict: "ask", reason: "parse failure", kind: "undecidable", verb: "", targets: [], hosts: [] },
      segments: 1,
    };
  }
  const ctx: ChainCtx = { cwd, vars: new Map() };
  const writable = writableSet(deps.cfg, cwd); // pinned to session workspace, not chain cwd
  let sandbox = false;
  const parts: string[] = [];
  for (const seg of segments) {
    const e = evaluateSegment(seg, ctx, deps, writable);
    const label = e.verdict === "safe" ? seg.cmds[0]?.verb.text ?? "?" : e.verb || "?";
    parts.push(`${label}[${e.verdict}]`);
    if (e.verdict === "deny") return { action: "deny", reason: e.reason, blocker: e, segments: segments.length, breakdown: parts.join(" · ") };
    if (e.verdict === "ask") return { action: "ask", reason: e.reason, blocker: e, segments: segments.length, breakdown: parts.join(" · ") };
    if (e.verdict === "sandbox") sandbox = true;
  }
  return sandbox
    ? { action: "sandbox", reason: "", blocker: null, segments: segments.length, breakdown: parts.join(" · ") }
    : { action: "allow", reason: "", blocker: null, segments: segments.length, breakdown: parts.join(" · ") };
}

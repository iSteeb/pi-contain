import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface ContainConfig {
  mode: "strict" | "normal" | "off";
  sandbox: { enabled: boolean; writable: string[]; network: boolean };
  secrets: string[];
  readOnly: string[];
  askVerbs: string[];
  approval: {
    timeoutMs: number;
    telegram: { tokenEnv: string; allowedChatIds: number[] };
  };
  /** Full-deny paths (read AND write): guard's own brain. */
  selfPaths: string[];
  /** Write-deny trees: all installed extension/package sources. Reads stay
   *  open (policy choice) but tampering with any loaded code is denied. */
  protectWrite: string[];
  /** Set when contain.json failed to parse — callers must surface it. */
  configError: string | null;
  configPath: string;
  grantsPath: string;
}

export function packageDir(): string {
  return path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
}

export function agentDir(): string {
  return process.env.PI_AGENT_DIR
    ? path.resolve(process.env.PI_AGENT_DIR)
    : path.join(homedir(), ".pi", "agent");
}

export const DEFAULTS: Omit<
  ContainConfig,
  "selfPaths" | "configPath" | "grantsPath"
> = {
  mode: "strict",
  protectWrite: [],
  configError: null,
  sandbox: { enabled: true, writable: ["$WORKSPACE", "/tmp"], network: false },
  secrets: [
    ".env",
    ".env.*",
    "*.env",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.netrc",
    "~/*.token",
    "~/*.key",
    "**/*.pem",
    "**/id_rsa*",
    "**/id_ed25519",
  ],
  readOnly: ["**/node_modules/**", "**/.git/**", "**/*.db", "**/dist/**"],
  askVerbs: [],
  approval: {
    timeoutMs: 300_000,
    telegram: {
      tokenEnv: "CONTAIN_TELEGRAM_TOKEN",
      allowedChatIds: [],
    },
  },
};

function deepMerge<T>(base: T, over: unknown): T {
  if (over === null || over === undefined) return base;
  if (Array.isArray(base) || typeof base !== "object") return over as T;
  if (typeof over !== "object" || Array.isArray(over)) return over as T;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(over as Record<string, unknown>)) {
    const bk = (base as Record<string, unknown>)[k];
    out[k] =
      bk && typeof bk === "object" && !Array.isArray(bk) ? deepMerge(bk, v) : v;
  }
  return out as T;
}

export function loadConfig(dir = agentDir()): ContainConfig {
  const configPath = path.join(dir, "extensions", "contain.json");
  const grantsPath = path.join(dir, "extensions", "contain-grants.json");
  let user: unknown = {};
  let configError: string | null = null;
  if (existsSync(configPath)) {
    try {
      user = JSON.parse(readFileSync(configPath, "utf8"));
    } catch (e) {
      // Fail LOUD, not open: fall back to strict defaults and flag the error
      // so every session start warns the user their config is being ignored.
      user = {};
      configError = String(e);
    }
  }
  const merged = deepMerge(DEFAULTS, user);
  return {
    ...merged,
    configPath,
    grantsPath,
    configError,
    selfPaths: [
      packageDir(),
      configPath,
      grantsPath,
      path.join(dir, "extensions", "contain-state.json"),
      path.join(dir, "settings.json"),
    ],
    protectWrite: [path.join(dir, "extensions"), path.join(dir, "git")],
    secrets: [
      ...merged.secrets,
      // harness credentials and session transcripts are secrets too
      path.join(dir, "auth.json"),
      path.join(dir, "trust.json"),
      path.join(dir, "sessions", "**"),
    ],
  };
}

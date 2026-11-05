import type { ApprovalRequest, Arbiter, DecisionType } from "./arbiter.ts";

const CODES: Record<string, DecisionType> = {
  o: "once",
  s: "session",
  f: "forever",
  d: "deny",
  x: "stop",
};
const LABELS: Record<DecisionType, string> = {
  once: "✅ Once",
  session: "🔁 Session",
  forever: "♾ Forever",
  deny: "🚫 Deny",
  stop: "⏹ Stop",
};

export interface TelegramCfg {
  tokenEnv: string;
  allowedChatIds: number[];
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface TelegramDeps {
  arbiter: Arbiter;
  fetchImpl?: FetchLike;
  log?: (msg: string) => void;
  /** Health signal for status UI: true when polling is live, false when down. */
  onHealth?: (healthy: boolean) => void;
}

function esc(s: string): string {
  return s.replace(/([&_*[\]()~`>#+\-=|{}.!])/g, "\\$1");
}

/**
 * Telegram approval channel. Long-polls getUpdates in-process; approval
 * buttons settle arbiter requests. Degrades silently when unconfigured.
 */
export class TelegramChannel {
  enabled = false;
  private offset = 0;
  private stopped = false;
  private failures = 0;
  private msgIds = new Map<string, Array<{ chatId: number; messageId: number }>>();
  private fetchImpl: FetchLike;
  private token: string;

  constructor(
    private cfg: TelegramCfg,
    private deps: TelegramDeps,
  ) {
    this.fetchImpl = deps.fetchImpl ?? ((u, i) => fetch(u, i));
    this.token = process.env[cfg.tokenEnv] ?? "";
  }

  get chatId(): number | null {
    return this.cfg.allowedChatIds[0] ?? null;
  }

  private async api(method: string, body: unknown): Promise<any> {
    const res = await this.fetchImpl(
      `https://api.telegram.org/bot${this.token}/${method}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) throw new Error(`telegram ${method}: HTTP ${res.status}`);
    return res.json();
  }

  async start(): Promise<boolean> {
    if (!this.token || !this.chatId) {
      this.deps.log?.(
        !this.token
          ? `pi-contain: telegram disabled (set $${this.cfg.tokenEnv})`
          : "pi-contain: telegram disabled (no allowedChatIds)",
      );
      return false;
    }
    try {
      const me = await this.api("getMe", {});
      this.enabled = true;
      this.stopped = false;
      this.deps.log?.(`pi-contain: telegram on (@${me.result?.username})`);
      this.deps.onHealth?.(true);
      void this.poll();
      return true;
    } catch (e) {
      this.deps.log?.(`pi-contain: telegram unreachable (${String(e)})`);
      this.deps.onHealth?.(false);
      return false;
    }
  }

  stop(): void {
    this.stopped = true;
    this.enabled = false;
  }

  private async poll(): Promise<void> {
    while (!this.stopped) {
      try {
        const r = await this.api("getUpdates", {
          offset: this.offset,
          timeout: 25,
          allowed_updates: ["callback_query"],
        });
        this.failures = 0;
        for (const u of r.result ?? []) {
          this.offset = Math.max(this.offset, u.update_id + 1);
          this.handleUpdate(u);
        }
      } catch {
        this.failures += 1;
        if (this.failures >= 3) {
          this.enabled = false;
          this.deps.log?.("pi-contain: telegram poll failed 3×; channel disabled");
          this.deps.onHealth?.(false);
          return;
        }
        await new Promise((r) => setTimeout(r, 3000));
      }
    }
  }

  private handleUpdate(u: any): void {
    const cb = u.callback_query;
    if (!cb?.data) return;
    if (!this.cfg.allowedChatIds.includes(cb.from?.id)) {
      void this.api("answerCallbackQuery", { callback_query_id: cb.id, text: "Not authorized." });
      return;
    }
    const m = /^c:(\w+):(\w)$/.exec(cb.data);
    if (!m) return;
    const [, id, code] = m;
    const type = CODES[code];
    const req = this.deps.arbiter.get(id);
    if (!type || !req) {
      void this.api("answerCallbackQuery", { callback_query_id: cb.id, text: "Expired or unknown request." });
      return;
    }
    if (type === "forever" && !req.options.includes("forever")) {
      void this.api("answerCallbackQuery", { callback_query_id: cb.id, text: "Forever not offered for this request." });
      return;
    }
    const ok = this.deps.arbiter.resolve(id, type, "telegram");
    void this.api("answerCallbackQuery", {
      callback_query_id: cb.id,
      text: ok ? `${LABELS[type]} ✓` : "Already answered",
    });
    if (ok) this.editOutcome(id, type, "telegram");
  }

  async sendApproval(req: ApprovalRequest): Promise<void> {
    if (!this.enabled) return;
    const lines = [
      `*${esc(req.title)}*`,
      `workspace: \`${esc(req.workspace)}\``,
      `command: \`${esc(req.command.slice(0, 3500))}\``,
      `blocked: \`${esc(req.segment)}\``,
      `segments: ${esc(req.breakdown)}`,
      `reason: ${esc(req.reason)}`,
      "",
      "*what each option approves:*",
      `  ✅ once — this exact command`,
      `  🔁 session — ${esc(req.scopes.session)}`,
    ];
    if (req.options.includes("forever"))
      lines.push(`  ♾ forever — ${esc(req.scopes.forever ?? req.scopes.session)}`);
    if (req.options.length === 0) return;
    const keyboard = [
      req.options.filter((o) => o === "once" || o === "session").map((o) => ({ text: LABELS[o], callback_data: `c:${req.id}:${invert(o)}` })),
      req.options.filter((o) => o === "forever" || o === "deny" || o === "stop").map((o) => ({ text: LABELS[o], callback_data: `c:${req.id}:${invert(o)}` })),
    ].filter((row) => row.length > 0);
    try {
      const entries: Array<{ chatId: number; messageId: number }> = [];
      for (const chat of this.cfg.allowedChatIds) {
        const r = await this.api("sendMessage", {
          chat_id: chat,
          text: lines.join("\n"),
          parse_mode: "MarkdownV2",
          reply_markup: { inline_keyboard: keyboard },
        });
        if (r.result?.message_id) entries.push({ chatId: chat, messageId: r.result.message_id });
      }
      this.msgIds.set(req.id, entries);
    } catch (e) {
      this.deps.log?.(`pi-contain: telegram sendApproval failed (${String(e)})`);
    }
  }

  editOutcome(id: string, type: DecisionType, via: string): void {
    const entries = this.msgIds.get(id);
    if (!entries) return;
    this.msgIds.delete(id);
    for (const e of entries) {
      void this.api("editMessageText", {
        chat_id: e.chatId,
        message_id: e.messageId,
        text: `${LABELS[type]} — via ${via}`,
      }).catch(() => {});
    }
  }
}

function invert(o: DecisionType): string {
  return { once: "o", session: "s", forever: "f", deny: "d", stop: "x" }[o];
}

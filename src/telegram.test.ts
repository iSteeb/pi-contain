import { describe, expect, it, vi } from "vitest";
import { TelegramChannel } from "./telegram.ts";
import { Arbiter, type ApprovalRequest } from "./arbiter.ts";

function makeChannel(allowedIds = [42], envToken = "T0K") {
  process.env.CONTAIN_TELEGRAM_TOKEN = envToken;
  const arbiter = new Arbiter(5000);
  const calls: Array<{ url: string; body: any }> = [];
  const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify({ ok: true, result: { message_id: 7, username: "b" } }), { status: 200 });
  });
  const tg = new TelegramChannel(
    { tokenEnv: "CONTAIN_TELEGRAM_TOKEN", allowedChatIds: allowedIds },
    { arbiter, fetchImpl: fetchImpl as never, log: () => {} },
  );
  return { tg, arbiter, calls, fetchImpl };
}

const req: ApprovalRequest = {
  id: "abc123",
  key: "curl|net|api.x.com",
  title: "pi-contain: approval needed",
  command: "curl -X POST https://api.x.com/hook",
  segment: "curl https://api.x.com",
  verb: "curl",
  reason: "curl needs network",
  kind: "net",
  workspace: "/w",
  options: ["once", "session", "forever", "deny", "stop"],
  breadth: { label: "curl → api.x.com", hosts: ["api.x.com"] },
  targets: [],
  hosts: ["api.x.com"],
  breakdown: "curl[ask]",
  scopes: { session: "curl → api.x.com", forever: "curl → api.x.com" },
};

describe("TelegramChannel", () => {
  it("start requires token + chat id; getMe gates polling", async () => {
    const { tg } = makeChannel();
    expect(await tg.start()).toBe(true);
    tg.stop();
  });

  it("disabled without token env", async () => {
    process.env.CONTAIN_TELEGRAM_TOKEN = "";
    const tg = new TelegramChannel({ tokenEnv: "CONTAIN_TELEGRAM_TOKEN", allowedChatIds: [1] }, { arbiter: new Arbiter(1), log: () => {} });
    expect(await tg.start()).toBe(false);
  });

  it("sendApproval builds keyboard with callback data + explicit scopes", async () => {
    const { tg, calls } = makeChannel();
    (tg as any).enabled = true;
    await tg.sendApproval(req);
    const send = calls.find((c) => c.url.endsWith("sendMessage"))!;
    expect(send.body.chat_id).toBe(42);
    const kb = send.body.reply_markup.inline_keyboard.flat();
    expect(kb.find((b: any) => b.text.includes("Forever"))?.callback_data).toBe("c:abc123:f");
    expect(kb.find((b: any) => b.text.includes("Deny"))?.callback_data).toBe("c:abc123:d");
    expect(send.body.text).toContain("blocked:");
    expect(send.body.text).toContain("session — curl");
    expect(send.body.text).toContain("forever — curl");
    expect(send.body.text).toContain("this exact command");
  });

  it("callback from whitelisted user settles the arbiter", async () => {
    const { tg, arbiter, calls } = makeChannel();
    (tg as any).enabled = true;
    const p = arbiter.create(req);
    (tg as any).handleUpdate({
      update_id: 1,
      callback_query: { id: "cb1", from: { id: 42 }, data: "c:abc123:s", message: { message_id: 7 } },
    });
    expect(await p).toEqual({ type: "session", via: "telegram" });
    expect(calls.some((c) => c.url.endsWith("answerCallbackQuery"))).toBe(true);
  });

  it("callback from stranger is rejected without settling", async () => {
    const { tg, arbiter } = makeChannel();
    (tg as any).enabled = true;
    const p = arbiter.create(req);
    (tg as any).handleUpdate({
      update_id: 1,
      callback_query: { id: "cb2", from: { id: 999 }, data: "c:abc123:o", message: { message_id: 7 } },
    });
    expect(arbiter.pendingCount()).toBe(1);
    arbiter.resolve("abc123", "deny", "tui");
    expect((await p).type).toBe("deny");
  });

  it("forever button refused when not offered", async () => {
    const { tg, arbiter } = makeChannel();
    (tg as any).enabled = true;
    const r2 = { ...req, options: ["once", "deny", "stop"] };
    const p = arbiter.create(r2);
    (tg as any).handleUpdate({
      update_id: 2,
      callback_query: { id: "cb3", from: { id: 42 }, data: "c:abc123:f", message: { message_id: 7 } },
    });
    expect(arbiter.pendingCount()).toBe(1);
    arbiter.resolve("abc123", "deny", "tui");
    expect((await p).type).toBe("deny");
  });

  it("poll marks disabled after repeated failures", async () => {
    const { tg } = makeChannel();
    const failing = vi.fn(async () => new Response("{}", { status: 500 }));
    (tg as any).fetchImpl = failing;
    (tg as any).enabled = true;
    await (tg as any).poll().catch(() => {});
    expect(tg.enabled).toBe(false);
  });
});

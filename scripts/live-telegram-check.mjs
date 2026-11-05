#!/usr/bin/env node
// Live wiring check: sends a real approval message to the configured chat and
// waits for a button tap. Verifies sendMessage → callback → answerCallbackQuery
// → editMessageText end-to-end. No pi session required.
const TOKEN = process.env.CONTAIN_TELEGRAM_TOKEN;
const CHAT = Number(process.env.CONTAIN_CHAT_ID);
const API = (m) => `https://api.telegram.org/bot${TOKEN}/${m}`;
const call = async (m, b) => (await fetch(API(m), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) })).json();

if (!TOKEN) { console.error("set CONTAIN_TELEGRAM_TOKEN"); process.exit(1); }

const id = Math.random().toString(36).slice(2, 8);
const kb = { inline_keyboard: [
  [
    { text: "✅ Once", callback_data: `c:${id}:o` },
    { text: "🚫 Deny", callback_data: `c:${id}:d` },
  ],
]};

const sent = await call("sendMessage", {
  chat_id: CHAT,
  text: "*pi\\-contain: live wiring test*\nIf you can read this and tap a button, remote approvals work\\. You have 60s\\.",
  parse_mode: "MarkdownV2",
  reply_markup: kb,
});
if (!sent.ok) { console.error("sendMessage failed:", JSON.stringify(sent)); process.exit(1); }
console.log(`sent (msg ${sent.result.message_id}) — waiting for a tap…`);

const deadline = Date.now() + 60_000;
let offset = 0;
(async () => {
  while (Date.now() < deadline) {
    const r = await call("getUpdates", { offset, timeout: 25, allowed_updates: ["callback_query"] });
    for (const u of r.result ?? []) {
      offset = Math.max(offset, u.update_id + 1);
      const cb = u.callback_query;
      if (!cb?.data?.includes(id)) continue;
      if (cb.from?.id !== CHAT) {
        await call("answerCallbackQuery", { callback_query_id: cb.id, text: "Not authorized." });
        continue;
      }
      await call("answerCallbackQuery", { callback_query_id: cb.id, text: "Received ✓" });
      await call("editMessageText", { chat_id: CHAT, message_id: sent.result.message_id, text: `Test complete: ${cb.data.endsWith(":o") ? "APPROVED" : "DENIED"} by ${cb.from.first_name} ✓` });
      console.log(`✓ callback received: ${cb.data} from ${cb.from.id} (${cb.from.first_name})`);
      process.exit(0);
    }
  }
  await call("editMessageText", { chat_id: CHAT, message_id: sent.result.message_id, text: "Test window expired (no tap) — wiring is send-only-verified." });
  console.log("no tap within 60s (send path verified)");
})();

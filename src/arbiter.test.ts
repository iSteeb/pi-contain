import { describe, expect, it, vi } from "vitest";
import { Arbiter, requestKey, type ApprovalRequest } from "./arbiter.ts";

const req = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  id: "r1",
  key: requestKey({ verb: "curl", kind: "net", targets: [], hosts: ["a.b"] }),
  title: "t",
  command: "c",
  segment: "s",
  reason: "r",
  kind: "net",
  workspace: "/w",
  options: ["once", "deny"],
  ...over,
});

describe("Arbiter", () => {
  it("first answer wins; second gets nothing", async () => {
    const a = new Arbiter(5000);
    const p = a.create(req());
    expect(a.resolve("r1", "once", "tui")).toBe(true);
    expect(a.resolve("r1", "deny", "telegram")).toBe(false);
    expect(await p).toEqual({ type: "once", via: "tui" });
  });

  it("timeout denies", async () => {
    const a = new Arbiter(20);
    const p = a.create(req());
    expect(await p).toEqual({ type: "deny", via: "timeout" });
  });

  it("identical keys coalesce into one pending request", async () => {
    const a = new Arbiter(5000);
    const p1 = a.create(req({ id: "r1" }));
    const p2 = a.create(req({ id: "r2" })); // same key
    expect(a.pendingCount()).toBe(1);
    a.resolve("r1", "session", "telegram");
    expect((await p1).type).toBe("session");
    expect((await p2).type).toBe("session");
  });

  it("M6: once approves exactly one coalesced waiter; the rest are denied", async () => {
    const a = new Arbiter(5000);
    const p1 = a.create(req({ id: "r1" }));
    const p2 = a.create(req({ id: "r2" }));
    const p3 = a.create(req({ id: "r3" }));
    a.resolve("r1", "once", "tui");
    expect((await p1).type).toBe("once");
    expect((await p2).type).toBe("deny");
    expect((await p3).type).toBe("deny");
  });

  it("different keys stay separate", () => {
    const a = new Arbiter(5000);
    a.create(req({ id: "r1", key: "k1" }));
    a.create(req({ id: "r2", key: "k2" }));
    expect(a.pendingCount()).toBe(2);
  });

  it("flush denies everything pending", async () => {
    const a = new Arbiter(5000);
    const p = a.create(req());
    a.flush();
    expect((await p).via).toBe("timeout");
  });

  it("onSettled fires once with the winner", async () => {
    const onSettled = vi.fn();
    const a = new Arbiter(5000, onSettled);
    a.create(req());
    a.resolve("r1", "stop", "telegram");
    expect(onSettled).toHaveBeenCalledTimes(1);
    expect(onSettled.mock.calls[0][1]).toEqual({ type: "stop", via: "telegram" });
  });
});

import { describe, expect, it } from "vite-plus/test";

import { GrantRegistry, ProtectedHostError } from "./ProtectedAuthentication.ts";

const claim = { threadId: "thread", tabId: "tab", agentSessionId: "env\0agent" };

const code = (run: () => unknown) => {
  try {
    run();
    return null;
  } catch (error) {
    return error instanceof ProtectedHostError ? error.code : String(error);
  }
};

describe("GrantRegistry", () => {
  it("redeems a fresh grant once, for the tab and session it was minted for", () => {
    const grants = new GrantRegistry({ now: () => 1_000, ttlMs: 60_000 });
    const minted = grants.mint(claim);
    expect(minted.expiresAt).toBe(61_000);
    expect(grants.redeem(minted.grant)).toEqual(claim);
    expect(code(() => grants.redeem(minted.grant))).toBe("grant-invalid");
  });

  it("refuses an expired grant and forgets it", () => {
    let now = 1_000;
    const grants = new GrantRegistry({ now: () => now, ttlMs: 60_000 });
    const minted = grants.mint(claim);
    now = 61_000;
    expect(code(() => grants.redeem(minted.grant))).toBe("grant-invalid");
    now = 1_000;
    expect(code(() => grants.redeem(minted.grant))).toBe("grant-invalid");
  });

  it("refuses a grant it never minted", () => {
    const grants = new GrantRegistry();
    grants.mint(claim);
    expect(code(() => grants.redeem("t3pa_not-a-grant"))).toBe("grant-invalid");
  });
});

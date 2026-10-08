// @effect-diagnostics nodeBuiltinImport:off globalDate:off - Plain Node code shared with the socket API.
/**
 * Protected authentication for agent-owned server browser tabs.
 *
 * An agent asks for a grant on a tab it owns (`preview_authentication_grant`).
 * A credential service redeems the grant over a private host API and drives
 * one protected interval: inspect, fill, submit, clear, read, fetch, end.
 * T3 performs those mechanical steps and never learns which credential is in
 * use. While an interval holds a tab, every tab sharing its browser context is
 * locked against observation; see `ServerBrowser` for the enforcement points.
 *
 * Errors carry a code only, never page content or values.
 */
import * as NodeCrypto from "node:crypto";

/** How long an unused grant stays redeemable. */
export const GRANT_TTL_MS = 60_000;
/** The longest a single interval may hold a tab, whatever deadline the client asks for. */
export const MAX_INTERVAL_MS = 180_000;

export type ProtectedHostErrorCode =
  | "grant-invalid"
  | "tab-not-found"
  | "tab-closed"
  | "tab-not-owned"
  | "busy"
  | "navigated"
  | "target-missing"
  | "target-not-editable"
  | "timeout"
  | "unavailable"
  | "failed";

/** A host failure with a code and nothing else. */
export class ProtectedHostError extends Error {
  readonly code: ProtectedHostErrorCode;

  constructor(code: ProtectedHostErrorCode) {
    super(`Protected authentication failed: ${code}`);
    this.name = "ProtectedHostError";
    this.code = code;
  }
}

export interface GrantClaim {
  readonly threadId: string;
  readonly tabId: string;
  readonly agentSessionId: string;
}

const digest = (grant: string) => NodeCrypto.createHash("sha256").update(grant).digest("hex");

/** Short-lived, single-use, tab-bound grants. Only digests are kept. */
export class GrantRegistry {
  private readonly grants = new Map<string, GrantClaim & { readonly expiresAt: number }>();
  private readonly now: () => number;
  private readonly ttlMs: number;

  constructor(options: { readonly now?: () => number; readonly ttlMs?: number } = {}) {
    this.now = options.now ?? Date.now;
    this.ttlMs = options.ttlMs ?? GRANT_TTL_MS;
  }

  mint(claim: GrantClaim): { readonly grant: string; readonly expiresAt: number } {
    const now = this.now();
    for (const [key, entry] of this.grants) if (entry.expiresAt <= now) this.grants.delete(key);
    const grant = `t3pa_${NodeCrypto.randomBytes(32).toString("base64url")}`;
    const expiresAt = now + this.ttlMs;
    this.grants.set(digest(grant), { ...claim, expiresAt });
    return { grant, expiresAt };
  }

  /** Consumes the grant whether or not it is still valid. */
  redeem(grant: string): GrantClaim {
    const key = digest(grant);
    const entry = this.grants.get(key);
    this.grants.delete(key);
    if (!entry || entry.expiresAt <= this.now()) throw new ProtectedHostError("grant-invalid");
    return { threadId: entry.threadId, tabId: entry.tabId, agentSessionId: entry.agentSessionId };
  }
}

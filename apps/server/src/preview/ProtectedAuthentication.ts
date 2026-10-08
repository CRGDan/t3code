// @effect-diagnostics nodeBuiltinImport:off globalDate:off globalTimers:off - Plain Node and Playwright code shared with the socket API.
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

import type { ElementHandle, Frame, Page, Request } from "playwright-core";

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

/** A CSS selector, inside the iframe `frame` selects in the top-level document when set. */
export interface ProtectedFormTarget {
  readonly selector: string;
  readonly frame?: string | undefined;
}

export type ProtectedTargetState =
  | { readonly present: false }
  | {
      readonly present: true;
      readonly frameUrl: string;
      readonly editable: boolean;
      readonly inputType?: string;
    };

export interface ProtectedPageState {
  readonly url: string;
  /** Changes whenever any frame of the tab commits a navigation. */
  readonly pageVersion: number;
  /** Top-level first. */
  readonly frames: ReadonlyArray<{ readonly url: string }>;
  readonly targets: ReadonlyArray<ProtectedTargetState>;
}

export interface ProtectedInterval {
  /** Stable for the tab's browser context; popups share their opener's. */
  readonly contextId: string;
  readonly inspect: (targets: ReadonlyArray<ProtectedFormTarget>) => Promise<ProtectedPageState>;
  readonly fill: (
    target: ProtectedFormTarget,
    value: string,
    expected: { readonly pageVersion: number },
  ) => Promise<void>;
  readonly submit: (
    target: ProtectedFormTarget,
    expected: { readonly pageVersion: number },
  ) => Promise<void>;
  readonly clear: (targets: ReadonlyArray<ProtectedFormTarget>) => Promise<void>;
  readonly readText: (target: ProtectedFormTarget) => Promise<string | undefined>;
  readonly fetchText: (url: string) => Promise<{ readonly status: number; readonly body: string }>;
  /** Clears what was filled, releases the lock and resumes observation. Idempotent. */
  readonly end: () => Promise<void>;
}

/** The browser side of the private host API. */
export interface ProtectedHost {
  /** Redeems the grant, which is consumed whatever the outcome, and locks its tab's context. */
  readonly begin: (input: {
    readonly grant: string;
    readonly tabId?: string | undefined;
    readonly deadline: number;
  }) => Promise<ProtectedInterval>;
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

/** Inputs that take no typed value. */
const NON_TEXT_INPUTS = new Set([
  "submit",
  "button",
  "hidden",
  "checkbox",
  "radio",
  "file",
  "image",
  "reset",
  "range",
  "color",
]);
/** How long a submit waits for its navigation to start before treating it as in-page. */
const SUBMIT_SETTLE_MS = 1_500;
const CLEAR_TIMEOUT_MS = 2_000;
const FETCH_BODY_LIMIT = 1024 * 1024;

const dispose = (handles: ReadonlyArray<ElementHandle>) =>
  Promise.all(handles.map((handle) => handle.dispose().catch(() => undefined)));

/** Exactly one match, or nothing. Selectors are CSS only. */
const single = async (frame: Frame, selector: string) => {
  const handles = await frame.$$(`css=${selector}`);
  if (handles.length === 1) return handles[0]!;
  await dispose(handles);
  return null;
};

export const resolveTarget = async (page: Page, target: ProtectedFormTarget) => {
  let frame: Frame | null = page.mainFrame();
  if (target.frame !== undefined) {
    const element = await single(frame, target.frame);
    frame = (await element?.contentFrame()) ?? null;
    await element?.dispose().catch(() => undefined);
  }
  if (!frame) return null;
  const handle = await single(frame, target.selector);
  return handle ? { frame, handle } : null;
};

const describe = (handle: ElementHandle) =>
  handle.evaluate(
    (node, nonText) => {
      // Runs in the page; the server has no DOM types.
      const element = node as unknown as {
        readonly tagName: string;
        readonly type?: string;
        readonly disabled?: boolean;
        readonly readOnly?: boolean;
      };
      const tag = element.tagName.toLowerCase();
      const type = tag === "input" ? String(element.type).toLowerCase() : undefined;
      return {
        editable:
          (tag === "textarea" || (type !== undefined && !nonText.includes(type))) &&
          element.disabled !== true &&
          element.readOnly !== true,
        ...(type === undefined ? {} : { inputType: type }),
      };
    },
    [...NON_TEXT_INPUTS],
  );

export const targetState = async (
  page: Page,
  target: ProtectedFormTarget,
): Promise<ProtectedTargetState> => {
  const found = await resolveTarget(page, target);
  if (!found) return { present: false };
  try {
    return { present: true, frameUrl: found.frame.url(), ...(await describe(found.handle)) };
  } finally {
    await found.handle.dispose().catch(() => undefined);
  }
};

/** Resolves an editable target and hands it to `run`. */
export const withEditableTarget = async <A>(
  page: Page,
  target: ProtectedFormTarget,
  run: (handle: ElementHandle) => Promise<A>,
): Promise<A> => {
  const found = await resolveTarget(page, target);
  if (!found) throw new ProtectedHostError("target-missing");
  try {
    if (!(await describe(found.handle)).editable)
      throw new ProtectedHostError("target-not-editable");
    return await run(found.handle);
  } finally {
    await found.handle.dispose().catch(() => undefined);
  }
};

/** Empties every present, editable target. Never fails. */
export const clearTargets = async (page: Page, targets: ReadonlyArray<ProtectedFormTarget>) => {
  for (const target of targets) {
    await withEditableTarget(page, target, (handle) =>
      handle.fill("", { timeout: CLEAR_TIMEOUT_MS }),
    ).catch(() => undefined);
  }
};

/** Clicks the target, then waits for the navigation it starts, if any, to load. */
export const submitTarget = async (
  page: Page,
  target: ProtectedFormTarget,
  pageVersion: () => number,
  timeout: () => number,
) => {
  const found = await resolveTarget(page, target);
  if (!found) throw new ProtectedHostError("target-missing");
  const before = pageVersion();
  // A navigation request in flight keeps the wait going past the settle window.
  const navigation = { inFlight: false };
  const onRequest = (request: Request) => {
    if (request.isNavigationRequest()) navigation.inFlight = true;
  };
  const onSettled = (request: Request) => {
    if (request.isNavigationRequest()) navigation.inFlight = false;
  };
  page.on("request", onRequest);
  page.on("requestfailed", onSettled);
  try {
    await found.handle.click({ timeout: Math.max(1, timeout()) });
    const settleBy = Date.now() + SUBMIT_SETTLE_MS;
    while (pageVersion() === before && (navigation.inFlight || Date.now() < settleBy)) {
      if (timeout() <= 0) throw new ProtectedHostError("timeout");
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    await page.waitForLoadState("load", { timeout: Math.max(1, timeout()) });
  } finally {
    page.off("request", onRequest);
    page.off("requestfailed", onSettled);
    await found.handle.dispose().catch(() => undefined);
  }
};

export const readTargetText = async (page: Page, target: ProtectedFormTarget) => {
  const found = await resolveTarget(page, target);
  if (!found) return undefined;
  try {
    return ((await found.handle.textContent()) ?? "").trim();
  } finally {
    await found.handle.dispose().catch(() => undefined);
  }
};

/** A GET from the page's browser context, with its cookies. */
export const fetchFromContext = async (page: Page, url: string, timeout: number) => {
  const parsed = URL.parse(url);
  if (!parsed || (parsed.protocol !== "https:" && parsed.protocol !== "http:"))
    throw new ProtectedHostError("failed");
  const response = await page
    .context()
    .request.get(parsed.href, { failOnStatusCode: false, maxRedirects: 10, timeout });
  try {
    const body = await response.body();
    return {
      status: response.status(),
      body: body.subarray(0, FETCH_BODY_LIMIT).toString("utf8"),
    };
  } finally {
    await response.dispose().catch(() => undefined);
  }
};

/** Maps any failure inside an interval to a code. */
export const toHostError = (
  cause: unknown,
  state: { readonly open: boolean; readonly closed: boolean },
) =>
  cause instanceof ProtectedHostError
    ? cause
    : new ProtectedHostError(
        !state.open
          ? "timeout"
          : state.closed
            ? "tab-closed"
            : cause instanceof Error && cause.name === "TimeoutError"
              ? "timeout"
              : "failed",
      );

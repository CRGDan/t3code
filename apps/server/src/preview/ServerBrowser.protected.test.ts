// @effect-diagnostics nodeBuiltinImport:off globalDate:off globalTimers:off - Drives a real browser against a local HTTP site.
import * as NodeFS from "node:fs";
import * as NodeHttp from "node:http";
import type * as NodeNet from "node:net";
import * as NodePath from "node:path";

import * as NodeServices from "@effect/platform-node/NodeServices";
import { it } from "@effect/vitest";
import {
  EnvironmentId,
  PreviewTabId,
  ProviderInstanceId,
  ThreadId,
  type PreviewAutomationAuthenticationGrant,
  type PreviewAutomationSnapshot,
  type PreviewAutomationStatus,
} from "@t3tools/contracts";
import { HostProcessEnvironment } from "@t3tools/shared/hostProcess";
import * as Clock from "effect/Clock";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Stream from "effect/Stream";
import { chromium } from "playwright-core";
import { afterAll, beforeAll, expect } from "vite-plus/test";

import * as ServerConfig from "../config.ts";
import * as ServerEnvironment from "../environment/ServerEnvironment.ts";
import * as Broker from "../mcp/PreviewAutomationBroker.ts";
import * as DesktopChannel from "./DesktopBrowserChannel.ts";
import * as Manager from "./Manager.ts";
import * as PreviewBrowser from "./PreviewBrowser.ts";
import type { ProtectedHostError } from "./ProtectedAuthentication.ts";
import * as ServerBrowser from "./ServerBrowser.ts";

// Real headless Chromium against a local site: these properties live in the page.
const PASSWORD = "sentinel-password-7Hq2";
const TOTP = "424242";

/** The headless shell Playwright installed for this playwright-core, else full Chromium. */
const executable = () => {
  const full = chromium.executablePath();
  const shell = full
    .replace(/chromium-(\d+)/, "chromium_headless_shell-$1")
    .replace("chrome-linux64/chrome", "chrome-headless-shell-linux64/chrome-headless-shell");
  return NodeFS.existsSync(shell) ? shell : full;
};

const page = (title: string, body: string) =>
  `<!doctype html><html><head><title>${title}</title></head><body><h1>${title}</h1>${body}</body></html>`;

const loginForm = (extra = "") => `${extra}
<form method="post" action="/login">
<input id="username" name="username" type="email">
<input id="password" name="password" type="password">
<button id="sign-in" type="submit">Sign in</button>
</form>`;

let site: NodeHttp.Server;
let origin = "";
const posts: Array<Record<string, string>> = [];

beforeAll(async () => {
  site = NodeHttp.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://site.invalid");
    const cookies = request.headers.cookie ?? "";
    const html = (body: string) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(body);
    };
    const redirect = (location: string, cookie?: string) => {
      response.writeHead(303, { location, ...(cookie ? { "set-cookie": cookie } : {}) });
      response.end();
    };
    const form = (then: (fields: Record<string, string>) => void) => {
      let body = "";
      request.on("data", (chunk) => (body += String(chunk)));
      request.on("end", () => {
        const fields = Object.fromEntries(new URLSearchParams(body));
        posts.push(fields);
        then(fields);
      });
    };
    switch (`${request.method} ${url.pathname}`) {
      case "GET /login":
        return html(page("Sign in", loginForm()));
      case "GET /logging-login":
        // Logs every keystroke and the value on change, as careless sites do.
        return html(
          page(
            "Sign in",
            loginForm(`<script>
addEventListener("input", (e) => console.log("typed " + e.target.value));
addEventListener("change", (e) => console.log("changed " + e.target.value));
</script>`),
          ),
        );
      case "GET /navigating-login":
        return html(
          page(
            "Sign in",
            loginForm(
              `<script>setTimeout(() => { location.href = "/login?moved=1"; }, 200);</script>`,
            ),
          ),
        );
      case "GET /popup-login":
        return html(
          page(
            "Sign in",
            loginForm(
              `<script>addEventListener("input", () => { window.open("/login?popup=1"); alert(document.getElementById("password").value); });</script>`,
            ),
          ),
        );
      case "GET /forms/owners":
        // Named controls shadow form.action and form.method, as older login forms do.
        return html(
          page(
            "Forms",
            `<form id="post-form" method="post" action="session">
<input type="hidden" name="action" value="login">
<input type="hidden" name="method" value="password">
<input id="post-user" name="username">
<button id="post-go" type="submit">Go</button>
<button id="override-go" type="submit" formmethod="get" formaction="/elsewhere">Elsewhere</button>
</form>
<form method="GET" action="/search"><input id="query" name="q"></form>
<form method="post" action="https://collector.example/collect"><input id="cross" name="c"></form>
<input id="remote" name="remote" form="post-form">
<input id="loose" name="loose">
<div id="plain">plain</div>`,
          ),
        );
      case "POST /login":
        return form((fields) =>
          fields.password === PASSWORD
            ? redirect("/mfa", "mfa=1; Path=/")
            : redirect("/login?error=1"),
        );
      case "GET /mfa":
        return html(
          page(
            "Two-factor",
            `<form method="post" action="/mfa"><input id="totp" name="totp" type="text"><button id="verify" type="submit">Verify</button></form>`,
          ),
        );
      case "POST /mfa":
        return form((fields) =>
          fields.totp === TOTP && cookies.includes("mfa=1")
            ? redirect("/account", "session=ok; Path=/")
            : redirect("/mfa?error=1"),
        );
      case "GET /account":
        return cookies.includes("session=ok")
          ? html(
              page(
                "Account",
                `<p>Signed in as <span id="account">synthetic@example.test</span></p>`,
              ),
            )
          : redirect("/login");
      case "GET /api/account":
        response.writeHead(cookies.includes("session=ok") ? 200 : 401, {
          "content-type": "application/json",
        });
        response.end(
          JSON.stringify(
            cookies.includes("session=ok") ? { account: "synthetic@example.test" } : {},
          ),
        );
        return;
      default:
        response.writeHead(404);
        response.end();
    }
  });
  await new Promise<void>((resolve) => site.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${String((site.address() as NodeNet.AddressInfo).port)}`;
});

afterAll(async () => {
  site.closeAllConnections();
  await new Promise((resolve) => site.close(resolve));
});

const testThread = {
  threadId: ThreadId.make("protected-auth-thread"),
  providerSessionId: "agent-a",
  providerInstanceId: ProviderInstanceId.make("codex"),
};
const scope = {
  environmentId: EnvironmentId.make("protected-auth-environment"),
  thread: testThread,
  client: undefined,
  requestNamespace: "protected-auth-test",
  capabilities: new Set(["preview"] as const),
  issuedAt: 1,
};

const layer = ServerBrowser.layer.pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      Broker.layer,
      Manager.layer,
      Layer.succeed(ServerEnvironment.ServerEnvironment, {
        getEnvironmentId: Effect.succeed(scope.environmentId),
        getDescriptor: Effect.die("unused descriptor"),
      }),
      Layer.succeed(PreviewBrowser.PreviewBrowser, {
        executable: Effect.sync(executable),
        installed: Effect.sync(() => Option.some(executable())),
      }),
      Layer.succeed(DesktopChannel.DesktopBrowserChannel, {
        available: false,
        awaitAttached: () => Effect.succeed(false),
        detached: Stream.never,
        isAttached: () => Effect.succeed(false),
        endpoint: () => Effect.die("no desktop"),
        pointer: () => Effect.void,
      }),
      // Like ServerBrowserPage.test.ts, run unsandboxed: test hosts lack T3's AppArmor profile.
      Layer.succeed(HostProcessEnvironment, {
        ...process.env,
        T3CODE_SERVER_BROWSER_SANDBOX: "0",
      }),
    ).pipe(
      Layer.provideMerge(
        ServerConfig.layerTest(NodePath.resolve("."), { prefix: "t3-protected-auth-" }),
      ),
      Layer.provideMerge(NodeServices.layer),
    ),
  ),
);

const login = { selector: "#username" };
const password = { selector: "#password" };
const signIn = { selector: "#sign-in" };

/** Opens an agent tab on `path` and mints a grant for it. */
const openWithGrant = (path: string) =>
  Effect.gen(function* () {
    const browser = yield* ServerBrowser.ServerBrowser;
    const broker = yield* Broker.PreviewAutomationBroker;
    yield* Effect.yieldNow;
    const opened = yield* broker.invoke<PreviewAutomationStatus>({
      scope,
      operation: "open",
      input: { url: `${origin}${path}`, reuseExistingTab: false, show: false },
      timeoutMs: 30_000,
    });
    const tabId = PreviewTabId.make(opened.tabId!);
    const { grant } = yield* broker.invoke<PreviewAutomationAuthenticationGrant>({
      scope,
      tabId,
      operation: "authenticationGrant",
      input: {},
    });
    return { browser, broker, tabId, grant };
  });

/** Begins an interval on a grant, ending `ms` from now. */
const begin = (grant: string, ms: number, tabId?: PreviewTabId) =>
  Effect.gen(function* () {
    const browser = yield* ServerBrowser.ServerBrowser;
    const deadline = (yield* Clock.currentTimeMillis) + ms;
    return yield* Effect.promise(() =>
      browser.protectedHost.begin({ grant, deadline, ...(tabId ? { tabId } : {}) }),
    );
  });

const hostError = (promise: Promise<unknown>) =>
  Effect.promise(() =>
    promise.then(
      () => null,
      (error: ProtectedHostError) => error.code,
    ),
  );

it.live(
  "fills a password then a TOTP, submits each step and confirms the signed-in account",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { grant } = yield* openWithGrant("/login");
        const interval = yield* begin(grant, 30_000);
        expect(interval.contextId).toMatch(/\S/);
        const first = yield* Effect.promise(() => interval.inspect([login, password, signIn]));
        expect(first.url).toBe(`${origin}/login`);
        expect(first.targets[1]).toMatchObject({
          present: true,
          editable: true,
          inputType: "password",
        });
        expect(first.targets[2]).toMatchObject({ present: true, editable: false });
        yield* Effect.promise(() =>
          interval.fill(login, "synthetic@example.test", { pageVersion: first.pageVersion }),
        );
        yield* Effect.promise(() =>
          interval.fill(password, PASSWORD, { pageVersion: first.pageVersion }),
        );
        yield* Effect.promise(() => interval.submit(signIn, { pageVersion: first.pageVersion }));
        const mfa = yield* Effect.promise(() => interval.inspect([{ selector: "#totp" }]));
        expect(mfa.url).toBe(`${origin}/mfa`);
        expect(mfa.pageVersion).not.toBe(first.pageVersion);
        yield* Effect.promise(() => interval.fill({ selector: "#totp" }, TOTP, mfa));
        yield* Effect.promise(() => interval.submit({ selector: "#verify" }, mfa));
        expect(yield* Effect.promise(() => interval.readText({ selector: "#account" }))).toBe(
          "synthetic@example.test",
        );
        expect(yield* Effect.promise(() => interval.readText({ selector: "#missing" }))).toBe(
          undefined,
        );
        const api = yield* Effect.promise(() => interval.fetchText(`${origin}/api/account`));
        expect(api).toEqual({
          status: 200,
          body: JSON.stringify({ account: "synthetic@example.test" }),
        });
        yield* Effect.promise(() => interval.end());
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "consumes a grant on first use and refuses a reused, wrong-tab or concurrent one",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { browser, broker, tabId, grant } = yield* openWithGrant("/login");
        const deadline = (yield* Clock.currentTimeMillis) + 30_000;
        expect(
          yield* hostError(browser.protectedHost.begin({ grant: "t3pa_forged", deadline })),
        ).toBe("grant-invalid");
        const wrongTab = yield* broker.invoke<PreviewAutomationAuthenticationGrant>({
          scope,
          tabId,
          operation: "authenticationGrant",
          input: {},
        });
        expect(
          yield* hostError(
            browser.protectedHost.begin({ grant: wrongTab.grant, tabId: "other-tab", deadline }),
          ),
        ).toBe("grant-invalid");
        // The mismatched redemption still consumed that grant.
        expect(
          yield* hostError(browser.protectedHost.begin({ grant: wrongTab.grant, deadline })),
        ).toBe("grant-invalid");
        const second = yield* broker.invoke<PreviewAutomationAuthenticationGrant>({
          scope,
          tabId,
          operation: "authenticationGrant",
          input: {},
        });
        const interval = yield* Effect.promise(() =>
          browser.protectedHost.begin({ grant, tabId, deadline }),
        );
        expect(yield* hostError(browser.protectedHost.begin({ grant, deadline }))).toBe(
          "grant-invalid",
        );
        expect(
          yield* hostError(browser.protectedHost.begin({ grant: second.grant, deadline })),
        ).toBe("busy");
        yield* Effect.promise(() => interval.end());
        yield* Effect.promise(() => interval.end());
        expect(yield* hostError(interval.inspect([password]))).toBe("timeout");
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "refuses snapshots, evaluation, recording, dialogs and close on the tab while it is protected",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { broker, tabId, grant } = yield* openWithGrant("/login");
        const interval = yield* begin(grant, 30_000);
        const first = yield* Effect.promise(() => interval.inspect([password]));
        yield* Effect.promise(() => interval.fill(password, PASSWORD, first));
        for (const [operation, input] of [
          ["snapshot", {}],
          ["evaluate", { expression: "document.getElementById('password').value" }],
          ["recordingStart", {}],
          ["dialog", { accept: true }],
          ["close", {}],
          ["type", { text: "x" }],
          ["authenticationGrant", {}],
        ] as const) {
          const refused = yield* broker
            .invoke<void>({ scope, tabId, operation, input })
            .pipe(Effect.flip);
          expect(refused, operation).toMatchObject({
            _tag: "PreviewAutomationControlInterruptedError",
            reason: "protected",
          });
        }
        const status = yield* broker.invoke<PreviewAutomationStatus>({
          scope,
          tabId,
          operation: "status",
          input: {},
        });
        expect(status.title).toBe(null);
        yield* Effect.promise(() => interval.end());
        // Ending cleared the field, so observation resumes without the value.
        const after = yield* broker.invoke<PreviewAutomationSnapshot>({
          scope,
          tabId,
          operation: "evaluate",
          input: { expression: "document.getElementById('password').value" },
        });
        expect(JSON.stringify(after)).not.toContain(PASSWORD);
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "reports the form submission each target belongs to",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { grant } = yield* openWithGrant("/forms/owners");
        const interval = yield* begin(grant, 30_000);
        const selectors = [
          "#post-user",
          "#post-go",
          "#override-go",
          "#query",
          "#cross",
          "#remote",
          "#loose",
          "#plain",
        ];
        const state = yield* Effect.promise(() =>
          interval.inspect(selectors.map((selector) => ({ selector }))),
        );
        yield* Effect.promise(() => interval.end());
        const post = { method: "post", action: `${origin}/forms/session` };
        expect(state.targets.map((target) => (target.present ? target.form : "absent"))).toEqual([
          post,
          post,
          { method: "get", action: `${origin}/elsewhere` },
          { method: "get", action: `${origin}/search` },
          { method: "post", action: "https://collector.example/collect" },
          post,
          null,
          null,
        ]);
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

/** What an agent's evaluate sees in a field once observation resumes. */
const readValue = (tabId: PreviewTabId, selector: string) =>
  Effect.gen(function* () {
    const broker = yield* Broker.PreviewAutomationBroker;
    return yield* broker.invoke<unknown>({
      scope,
      tabId,
      operation: "evaluate",
      input: { expression: `document.querySelector(${JSON.stringify(selector)})?.value` },
    });
  });

it.live(
  "keeps values a page logs to its console out of the evidence, during and after the interval",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { broker, tabId, grant } = yield* openWithGrant("/logging-login");
        const interval = yield* begin(grant, 30_000);
        const first = yield* Effect.promise(() => interval.inspect([login, password]));
        yield* Effect.promise(() => interval.fill(login, "synthetic@example.test", first));
        yield* Effect.promise(() => interval.fill(password, PASSWORD, first));
        yield* Effect.promise(() => interval.submit(signIn, first));
        yield* Effect.promise(() => interval.end());
        const snapshot = yield* broker.invoke<PreviewAutomationSnapshot>({
          scope,
          tabId,
          operation: "snapshot",
          input: {},
          timeoutMs: 30_000,
        });
        const evidence = JSON.stringify(snapshot);
        expect(evidence).not.toContain(PASSWORD);
        expect(evidence).not.toContain("typed synthetic");
        // The page that logged is gone; the MFA page it led to is observable again.
        expect(snapshot.url).toBe(`${origin}/mfa`);
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "refuses a fill after the page navigated and leaves the earlier fields empty",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { tabId, grant } = yield* openWithGrant("/navigating-login");
        const interval = yield* begin(grant, 30_000);
        const first = yield* Effect.promise(() => interval.inspect([login, password]));
        yield* Effect.promise(() => interval.fill(login, "synthetic@example.test", first));
        // The page's own script moves it to /login?moved=1.
        yield* Effect.sleep("600 millis");
        expect(yield* hostError(interval.fill(password, PASSWORD, first))).toBe("navigated");
        expect(yield* hostError(interval.submit(signIn, first))).toBe("navigated");
        const moved = yield* Effect.promise(() => interval.inspect([password]));
        expect(moved.url).toBe(`${origin}/login?moved=1`);
        expect(moved.pageVersion).toBeGreaterThan(first.pageVersion);
        yield* Effect.promise(() => interval.fill(password, PASSWORD, moved));
        expect(yield* hostError(interval.fill({ selector: "#nope" }, PASSWORD, moved))).toBe(
          "target-missing",
        );
        expect(yield* hostError(interval.fill(signIn, PASSWORD, moved))).toBe(
          "target-not-editable",
        );
        yield* Effect.promise(() => interval.end());
        expect(yield* readValue(tabId, "#password")).toBe("");
        expect(yield* readValue(tabId, "#username")).toBe("");
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "closes popups and dismisses dialogs a page opens during the interval",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { broker, tabId, grant } = yield* openWithGrant("/popup-login");
        const interval = yield* begin(grant, 30_000);
        const first = yield* Effect.promise(() => interval.inspect([password]));
        yield* Effect.promise(() => interval.fill(password, PASSWORD, first));
        yield* Effect.promise(() => interval.end());
        const status = yield* broker.invoke<PreviewAutomationStatus>({
          scope,
          tabId,
          operation: "status",
          input: {},
        });
        expect(status.dialog ?? null).toBe(null);
        expect(status.tabs?.map((tab) => tab.tabId)).toEqual([tabId]);
        expect(JSON.stringify(status)).not.toContain(PASSWORD);
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "locks every tab sharing the browser context, not just the one authenticating",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { broker, tabId, grant } = yield* openWithGrant("/login");
        yield* broker.invoke({
          scope,
          tabId,
          operation: "evaluate",
          input: { expression: "void window.open('/login?popup=1')" },
        });
        let popupId: string | undefined;
        while (popupId === undefined) {
          const status = yield* broker.invoke<PreviewAutomationStatus>({
            scope,
            tabId,
            operation: "status",
            input: {},
          });
          popupId = status.tabs?.find((tab) => tab.openerTabId === tabId)?.tabId;
          if (popupId === undefined) yield* Effect.sleep("50 millis");
        }
        const popup = PreviewTabId.make(popupId);
        const interval = yield* begin(grant, 30_000);
        const refused = yield* broker
          .invoke<void>({ scope, tabId: popup, operation: "evaluate", input: { expression: "1" } })
          .pipe(Effect.flip);
        expect(refused).toMatchObject({ reason: "protected" });
        const popupGrant = yield* broker
          .invoke<void>({ scope, tabId: popup, operation: "authenticationGrant", input: {} })
          .pipe(Effect.flip);
        expect(popupGrant).toMatchObject({ reason: "protected" });
        yield* Effect.promise(() => interval.end());
        const allowed = yield* broker.invoke<unknown>({
          scope,
          tabId: popup,
          operation: "evaluate",
          input: { expression: "1 + 1" },
        });
        expect(allowed).toBe(2);
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

it.live(
  "clears filled fields and releases the tab when the deadline passes",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const { tabId, grant } = yield* openWithGrant("/login");
        const interval = yield* begin(grant, 1_500);
        const first = yield* Effect.promise(() => interval.inspect([password]));
        yield* Effect.promise(() => interval.fill(password, PASSWORD, first));
        yield* Effect.sleep("2500 millis");
        expect(yield* hostError(interval.inspect([password]))).toBe("timeout");
        expect(yield* readValue(tabId, "#password")).toBe("");
      }),
    ).pipe(Effect.provide(layer)),
  60_000,
);

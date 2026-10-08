// @effect-diagnostics nodeBuiltinImport:off globalDate:off globalTimers:off - Exercises a plain Node socket server.
import * as NodeFSP from "node:fs/promises";
import * as NodeNet from "node:net";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  ProtectedHostError,
  type ProtectedHost,
  type ProtectedInterval,
} from "./ProtectedAuthentication.ts";
import { loadProtectedSocketConfig, serveProtectedHost } from "./ProtectedAuthenticationSocket.ts";

const SECRET = "s".repeat(40);
const GOOD_GRANT = "t3pa_good";

let dir = "";
let socketPath = "";
let served: { close: () => Promise<void> } | null = null;
const calls: Array<string> = [];
const filledValues: Array<string> = [];
let ended = 0;

/** Records what the host was asked to do; values go to `filledValues` only. */
const fakeHost: ProtectedHost = {
  begin: async ({ grant, deadline }) => {
    if (grant !== GOOD_GRANT) throw new ProtectedHostError({ code: "grant-invalid" });
    calls.push(`begin ${String(deadline)}`);
    const interval: ProtectedInterval = {
      contextId: "context-1",
      inspect: async (targets) => {
        calls.push(`inspect ${targets.map((t) => t.selector).join(",")}`);
        return {
          url: "https://site.test/login",
          pageVersion: 3,
          frames: [],
          targets: [
            {
              present: true,
              frameUrl: "https://site.test/login",
              editable: true,
              inputType: "password",
              form: { method: "post", action: "https://site.test/session" },
            },
            { present: true, frameUrl: "https://site.test/login", editable: false, form: null },
            { present: false },
          ],
        };
      },
      fill: async (target, value, expected) => {
        if (expected.pageVersion !== 3) throw new ProtectedHostError({ code: "navigated" });
        calls.push(`fill ${target.selector}`);
        filledValues.push(value);
      },
      submit: async (target) => void calls.push(`submit ${target.selector}`),
      clear: async (targets) => void calls.push(`clear ${targets.length}`),
      readText: async (target) => (target.selector === "#account" ? "someone" : undefined),
      fetchText: async () => ({ status: 200, body: "{}" }),
      end: async () => {
        ended += 1;
      },
    };
    return interval;
  },
};

/** A line-oriented client for the socket. */
const connect = async () => {
  const socket = NodeNet.createConnection(socketPath);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.setEncoding("utf8");
  const lines: Array<Record<string, unknown>> = [];
  const waiters: Array<(line: Record<string, unknown>) => void> = [];
  let buffered = "";
  socket.on("data", (chunk: string) => {
    buffered += chunk;
    let newline = buffered.indexOf("\n");
    while (newline >= 0) {
      const line = JSON.parse(buffered.slice(0, newline)) as Record<string, unknown>;
      buffered = buffered.slice(newline + 1);
      const waiter = waiters.shift();
      if (waiter) waiter(line);
      else lines.push(line);
      newline = buffered.indexOf("\n");
    }
  });
  const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
  let id = 0;
  const request = (message: Record<string, unknown>) => {
    id += 1;
    socket.write(`${JSON.stringify({ id, ...message })}\n`);
    return new Promise<Record<string, unknown>>((resolve) => {
      const queued = lines.shift();
      if (queued) resolve(queued);
      else waiters.push(resolve);
    });
  };
  return { socket, request, closed };
};

beforeEach(async () => {
  dir = await NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-protected-socket-"));
  socketPath = NodePath.join(dir, "host.sock");
  calls.length = 0;
  filledValues.length = 0;
  ended = 0;
  served = await serveProtectedHost(fakeHost, { socketPath, secret: SECRET });
});

afterEach(async () => {
  await served?.close();
  await NodeFSP.rm(dir, { recursive: true, force: true });
});

describe("serveProtectedHost", () => {
  it("creates a socket only its owner can use", async () => {
    expect((await NodeFSP.stat(socketPath)).mode & 0o777).toBe(0o600);
  });

  it("will not replace a file that is not a socket", async () => {
    const occupied = NodePath.join(dir, "occupied");
    await NodeFSP.writeFile(occupied, "keep me");
    await expect(
      serveProtectedHost(fakeHost, { socketPath: occupied, secret: SECRET }),
    ).rejects.toMatchObject({ _tag: "ProtectedSocketStartError", problem: "path-occupied" });
    expect(await NodeFSP.readFile(occupied, "utf8")).toBe("keep me");
  });

  it("refuses a client without the secret and hangs up", async () => {
    const client = await connect();
    expect(await client.request({ op: "begin", grant: GOOD_GRANT, deadline: 1 })).toMatchObject({
      ok: false,
      code: "unauthorized",
    });
    await client.closed;
    const wrong = await connect();
    expect(await wrong.request({ op: "hello", secret: "x".repeat(40) })).toMatchObject({
      ok: false,
      code: "unauthorized",
    });
    await wrong.closed;
    expect(calls).toEqual([]);
  });

  it("drives one interval from begin to end and passes values only to fill", async () => {
    const client = await connect();
    expect(await client.request({ op: "hello", secret: SECRET })).toMatchObject({
      ok: true,
      result: { protocol: "t3-protected-auth/2" },
    });
    const begun = await client.request({ op: "begin", grant: GOOD_GRANT, deadline: 5_000 });
    expect(begun).toMatchObject({ ok: true, result: { contextId: "context-1" } });
    const interval = (begun.result as { interval: string }).interval;
    expect(
      await client.request({ op: "inspect", interval, targets: [{ selector: "#password" }] }),
    ).toEqual({
      id: 3,
      ok: true,
      result: {
        url: "https://site.test/login",
        pageVersion: 3,
        frames: [],
        targets: [
          {
            present: true,
            frameUrl: "https://site.test/login",
            editable: true,
            inputType: "password",
            form: { method: "post", action: "https://site.test/session" },
          },
          { present: true, frameUrl: "https://site.test/login", editable: false, form: null },
          { present: false },
        ],
      },
    });
    const filled = await client.request({
      op: "fill",
      interval,
      target: { selector: "#password" },
      value: "hunter2-synthetic",
      pageVersion: 3,
    });
    expect(filled).toEqual({ id: 4, ok: true, result: {} });
    expect(
      await client.request({
        op: "fill",
        interval,
        target: { selector: "#password" },
        value: "again",
        pageVersion: 2,
      }),
    ).toEqual({ id: 5, ok: false, code: "navigated" });
    expect(
      await client.request({ op: "submit", interval, target: { selector: "#go" }, pageVersion: 3 }),
    ).toMatchObject({ ok: true });
    expect(
      await client.request({ op: "readText", interval, target: { selector: "#account" } }),
    ).toMatchObject({ ok: true, result: { text: "someone" } });
    expect(
      await client.request({ op: "readText", interval, target: { selector: "#none" } }),
    ).toMatchObject({ ok: true, result: { text: null } });
    expect(
      await client.request({ op: "fetchText", interval, url: "https://site.test/me" }),
    ).toMatchObject({ ok: true, result: { status: 200, body: "{}" } });
    expect(await client.request({ op: "end", interval })).toMatchObject({ ok: true });
    expect(await client.request({ op: "inspect", interval, targets: [] })).toMatchObject({
      ok: false,
      code: "bad-request",
    });
    expect(calls).toEqual(["begin 5000", "inspect #password", "fill #password", "submit #go"]);
    expect(filledValues).toEqual(["hunter2-synthetic"]);
    expect(ended).toBe(1);
    client.socket.end();
  });

  it("reports host and request failures by code only", async () => {
    const client = await connect();
    await client.request({ op: "hello", secret: SECRET });
    expect(await client.request({ op: "begin", grant: "t3pa_bad", deadline: 1 })).toMatchObject({
      ok: false,
      code: "grant-invalid",
    });
    expect(await client.request({ op: "begin", deadline: 1 })).toMatchObject({
      ok: false,
      code: "bad-request",
    });
    expect(await client.request({ op: "teleport" })).toMatchObject({
      ok: false,
      code: "bad-request",
    });
    client.socket.end();
  });

  it("ends a connection's open intervals when the client goes away", async () => {
    const client = await connect();
    await client.request({ op: "hello", secret: SECRET });
    await client.request({ op: "begin", grant: GOOD_GRANT, deadline: 5_000 });
    client.socket.destroy();
    await client.closed;
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(ended).toBe(1);
  });
});

describe("loadProtectedSocketConfig", () => {
  const write = async (name: string, content: string, mode: number) => {
    const path = NodePath.join(dir, name);
    await NodeFSP.writeFile(path, content, { mode });
    await NodeFSP.chmod(path, mode);
    return path;
  };

  it("is off without a config file", async () => {
    expect(
      await loadProtectedSocketConfig({
        configPath: NodePath.join(dir, "absent.json"),
        baseDir: dir,
      }),
    ).toBe(null);
  });

  it("reads an owner-only secret and defaults the socket into the base dir", async () => {
    const secretFile = await write("secret", `${SECRET}\n`, 0o600);
    const configPath = await write("config.json", JSON.stringify({ secretFile }), 0o600);
    expect(await loadProtectedSocketConfig({ configPath, baseDir: dir })).toEqual({
      socketPath: NodePath.join(dir, "protected-auth.sock"),
      secret: SECRET,
    });
  });

  it("refuses a secret others can read, or one too short to guess", async () => {
    const shared = await write("shared", SECRET, 0o640);
    const sharedConfig = await write("a.json", JSON.stringify({ secretFile: shared }), 0o600);
    await expect(
      loadProtectedSocketConfig({ configPath: sharedConfig, baseDir: dir }),
    ).rejects.toMatchObject({
      _tag: "ProtectedSocketConfigError",
      problem: "secret-file-exposed",
      message: expect.stringMatching(/group or others/),
    });
    const short = await write("short", "too-short", 0o600);
    const shortConfig = await write("b.json", JSON.stringify({ secretFile: short }), 0o600);
    await expect(
      loadProtectedSocketConfig({ configPath: shortConfig, baseDir: dir }),
    ).rejects.toMatchObject({ problem: "secret-too-short" });
  });

  it("refuses a config that is not JSON or names a missing secret file", async () => {
    const garbled = await write("c.json", "{ secretFile:", 0o600);
    await expect(
      loadProtectedSocketConfig({ configPath: garbled, baseDir: dir }),
    ).rejects.toMatchObject({ _tag: "ProtectedSocketConfigError", problem: "config-not-json" });
    const missing = await write(
      "d.json",
      JSON.stringify({ secretFile: NodePath.join(dir, "absent-secret") }),
      0o600,
    );
    await expect(
      loadProtectedSocketConfig({ configPath: missing, baseDir: dir }),
    ).rejects.toMatchObject({ problem: "secret-file-unreadable", cause: { code: "ENOENT" } });
  });
});

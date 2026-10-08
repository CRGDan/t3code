// @effect-diagnostics nodeBuiltinImport:off globalDate:off globalTimers:off - A plain Node socket server for a local credential service.
/**
 * The private host API for protected authentication: newline-delimited JSON
 * over a unix socket, off unless configured. A local credential service
 * authenticates with a shared secret, redeems a grant an agent obtained from
 * `preview_authentication_grant`, and drives one protected interval. See
 * docs/agent-credentials/protected-authentication.md for the protocol.
 */
import * as NodeCrypto from "node:crypto";
import * as NodeFSP from "node:fs/promises";
import * as NodeNet from "node:net";
import * as NodePath from "node:path";

import { HostProcessEnvironment } from "@t3tools/shared/hostProcess";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";

import * as ServerConfig from "../config.ts";
import {
  isProtectedHostError,
  type ProtectedFormTarget,
  type ProtectedHost,
  type ProtectedInterval,
} from "./ProtectedAuthentication.ts";
import * as ServerBrowser from "./ServerBrowser.ts";

export const PROTOCOL = "t3-protected-auth/2";
export const CONFIG_ENV = "T3CODE_PROTECTED_AUTH_CONFIG";
export const CONFIG_FILE = "protected-auth.json";
const SOCKET_FILE = "protected-auth.sock";
const MIN_SECRET_LENGTH = 32;
const MAX_LINE_BYTES = 1024 * 1024;

export interface ProtectedSocketConfig {
  readonly socketPath: string;
  readonly secret: string;
}

/** A protocol failure; `code` is all the client learns. */
class RequestError extends Schema.TaggedError<RequestError>()("ProtectedSocketRequestError", {
  code: Schema.Literals(["bad-request", "unavailable"]),
}) {
  override get message(): string {
    return `Protected authentication request failed: ${this.code}`;
  }
}

const isRequestError = Schema.is(RequestError);
const badRequest = () => new RequestError({ code: "bad-request" });

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const string = (value: unknown) => {
  if (typeof value !== "string" || value.length === 0) throw badRequest();
  return value;
};

const integer = (value: unknown) => {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw badRequest();
  return value;
};

const target = (value: unknown): ProtectedFormTarget => {
  if (!isRecord(value)) throw badRequest();
  return {
    selector: string(value.selector),
    ...(value.frame === undefined ? {} : { frame: string(value.frame) }),
  };
};

const targets = (value: unknown) => {
  if (!Array.isArray(value) || value.length > 32) throw badRequest();
  return value.map(target);
};

const secretsMatch = (expected: string, given: unknown) =>
  typeof given === "string" &&
  NodeCrypto.timingSafeEqual(
    NodeCrypto.createHash("sha256").update(expected).digest(),
    NodeCrypto.createHash("sha256").update(given).digest(),
  );

/**
 * Serves `host` on a unix socket readable only by this user. Each connection
 * says hello with the secret first; intervals belong to their connection and
 * end when it closes.
 */
export const serveProtectedHost = async (
  host: ProtectedHost,
  config: ProtectedSocketConfig,
): Promise<{ readonly close: () => Promise<void> }> => {
  const stale = await NodeFSP.lstat(config.socketPath).catch(() => null);
  if (stale?.isSocket()) await NodeFSP.rm(config.socketPath);
  else if (stale) throw new Error(`${config.socketPath} exists and is not a socket.`);
  const connections = new Set<NodeNet.Socket>();
  const server = NodeNet.createServer((socket) => {
    connections.add(socket);
    socket.on("close", () => connections.delete(socket));
    handleConnection(host, config.secret, socket);
  });
  // Created owner-only, so no other user can connect between listen and chmod.
  const umask = process.umask(0o177);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.socketPath, () => {
        server.off("error", reject);
        resolve();
      });
    });
  } finally {
    process.umask(umask);
  }
  await NodeFSP.chmod(config.socketPath, 0o600);
  return {
    close: async () => {
      for (const socket of connections) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await NodeFSP.rm(config.socketPath, { force: true });
    },
  };
};

const handleConnection = (host: ProtectedHost, secret: string, socket: NodeNet.Socket) => {
  const intervals = new Map<string, ProtectedInterval>();
  let authenticated = false;
  let sequence = 0;
  let buffered = "";

  const send = (message: Record<string, unknown>) => {
    if (!socket.destroyed) socket.write(`${JSON.stringify(message)}\n`);
  };
  const intervalOf = (request: Record<string, unknown>) => {
    const interval = intervals.get(string(request.interval));
    if (!interval) throw badRequest();
    return interval;
  };

  const dispatch = async (request: Record<string, unknown>): Promise<unknown> => {
    switch (request.op) {
      case "begin": {
        const interval = await host.begin({
          grant: string(request.grant),
          ...(request.tabId === undefined ? {} : { tabId: string(request.tabId) }),
          deadline: integer(request.deadline),
        });
        if (socket.destroyed) {
          await interval.end();
          throw new RequestError({ code: "unavailable" });
        }
        const id = `i${String(++sequence)}`;
        intervals.set(id, interval);
        return { interval: id, contextId: interval.contextId };
      }
      case "inspect":
        return intervalOf(request).inspect(targets(request.targets));
      case "fill": {
        const interval = intervalOf(request);
        if (typeof request.value !== "string") throw badRequest();
        await interval.fill(target(request.target), request.value, {
          pageVersion: integer(request.pageVersion),
        });
        return {};
      }
      case "submit":
        await intervalOf(request).submit(target(request.target), {
          pageVersion: integer(request.pageVersion),
        });
        return {};
      case "clear":
        await intervalOf(request).clear(targets(request.targets));
        return {};
      case "readText":
        return { text: (await intervalOf(request).readText(target(request.target))) ?? null };
      case "fetchText":
        return intervalOf(request).fetchText(string(request.url));
      case "end": {
        const id = string(request.interval);
        const interval = intervals.get(id);
        intervals.delete(id);
        await interval?.end();
        return {};
      }
      default:
        throw badRequest();
    }
  };

  const handleLine = (line: string) => {
    let request: unknown;
    try {
      request = JSON.parse(line);
    } catch {
      request = null;
    }
    const id =
      isRecord(request) && (typeof request.id === "number" || typeof request.id === "string")
        ? request.id
        : null;
    if (!authenticated) {
      if (isRecord(request) && request.op === "hello" && secretsMatch(secret, request.secret)) {
        authenticated = true;
        send({ id, ok: true, result: { protocol: PROTOCOL } });
      } else {
        send({ id, ok: false, code: "unauthorized" });
        socket.end();
      }
      return;
    }
    if (!isRecord(request) || id === null) {
      send({ id, ok: false, code: "bad-request" });
      return;
    }
    void (async () => {
      try {
        send({ id, ok: true, result: await dispatch(request) });
      } catch (cause) {
        const code = isProtectedHostError(cause) || isRequestError(cause) ? cause.code : "failed";
        send({ id, ok: false, code });
      }
    })();
  };

  socket.setEncoding("utf8");
  socket.on("data", (chunk: string) => {
    buffered += chunk;
    if (Buffer.byteLength(buffered) > MAX_LINE_BYTES && !buffered.includes("\n")) {
      send({ id: null, ok: false, code: "bad-request" });
      socket.destroy();
      return;
    }
    let newline = buffered.indexOf("\n");
    while (newline >= 0) {
      const line = buffered.slice(0, newline).trim();
      buffered = buffered.slice(newline + 1);
      if (line.length > 0) handleLine(line);
      newline = buffered.indexOf("\n");
    }
  });
  socket.on("error", () => socket.destroy());
  // A client that goes away cancels its intervals: fields clear and the lock releases.
  socket.on("close", () => {
    for (const interval of intervals.values()) void interval.end().catch(() => undefined);
    intervals.clear();
  });
};

/**
 * Reads the opt-in config. Absent means off. A config that is present but
 * unsafe or malformed is an error, so the operator hears about it.
 */
export const loadProtectedSocketConfig = async (input: {
  readonly configPath: string;
  readonly baseDir: string;
}): Promise<ProtectedSocketConfig | null> => {
  const raw = await NodeFSP.readFile(input.configPath, "utf8").catch((cause: unknown) => {
    if ((cause as { code?: unknown }).code === "ENOENT") return null;
    throw cause;
  });
  if (raw === null) return null;
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed) || typeof parsed.secretFile !== "string")
    throw new Error(`${input.configPath} must name a secretFile.`);
  if (parsed.socketPath !== undefined && typeof parsed.socketPath !== "string")
    throw new Error(`${input.configPath} has an invalid socketPath.`);
  const secretFile = parsed.secretFile;
  if (!NodePath.isAbsolute(secretFile)) throw new Error("secretFile must be an absolute path.");
  const stat = await NodeFSP.stat(secretFile);
  if (!stat.isFile()) throw new Error("secretFile must be a regular file.");
  if ((stat.mode & 0o077) !== 0)
    throw new Error("secretFile must not be readable or writable by group or others (chmod 600).");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid())
    throw new Error("secretFile must belong to the user running T3.");
  const secret = (await NodeFSP.readFile(secretFile, "utf8")).trim();
  if (secret.length < MIN_SECRET_LENGTH)
    throw new Error(`The secret must be at least ${String(MIN_SECRET_LENGTH)} characters.`);
  const socketPath = parsed.socketPath ?? NodePath.join(input.baseDir, SOCKET_FILE);
  if (!NodePath.isAbsolute(socketPath)) throw new Error("socketPath must be an absolute path.");
  return { socketPath, secret };
};

/** Starts the socket when configured; logs and stays off when not or when unsafe. */
export const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const config = yield* ServerConfig.ServerConfig;
    const env = yield* HostProcessEnvironment;
    const browser = yield* ServerBrowser.ServerBrowser;
    const configPath = env[CONFIG_ENV] ?? NodePath.join(config.baseDir, CONFIG_FILE);
    const loaded = yield* Effect.tryPromise(() =>
      loadProtectedSocketConfig({ configPath, baseDir: config.baseDir }),
    ).pipe(
      Effect.catch((cause) =>
        Effect.logWarning("Protected authentication socket stays off: invalid config.", {
          configPath,
          cause: cause.cause instanceof Error ? cause.cause.message : String(cause.cause),
        }).pipe(Effect.as(null)),
      ),
    );
    if (loaded === null) return;
    yield* Effect.acquireRelease(
      Effect.tryPromise(() => serveProtectedHost(browser.protectedHost, loaded)),
      (served) => Effect.promise(() => served.close()),
    ).pipe(
      Effect.tap(() =>
        Effect.logInfo("Protected authentication socket listening.", {
          socketPath: loaded.socketPath,
        }),
      ),
      Effect.catch((cause) =>
        Effect.logWarning("Protected authentication socket failed to start.", {
          socketPath: loaded.socketPath,
          cause: String(cause.cause),
        }),
      ),
    );
  }),
);

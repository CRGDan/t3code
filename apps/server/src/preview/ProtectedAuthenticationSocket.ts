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

const ProtectedSocketConfigProblem = Schema.Literals([
  "config-unreadable",
  "config-not-json",
  "secret-file-unnamed",
  "secret-file-relative",
  "secret-file-unreadable",
  "secret-file-not-regular",
  "secret-file-exposed",
  "secret-file-foreign",
  "secret-too-short",
  "socket-path-invalid",
]);
type ProtectedSocketConfigProblem = typeof ProtectedSocketConfigProblem.Type;

const CONFIG_PROBLEMS: Record<ProtectedSocketConfigProblem, string> = {
  "config-unreadable": "the config file could not be read.",
  "config-not-json": "the config file is not JSON.",
  "secret-file-unnamed": "the config must name a secretFile.",
  "secret-file-relative": "secretFile must be an absolute path.",
  "secret-file-unreadable": "secretFile could not be read.",
  "secret-file-not-regular": "secretFile must be a regular file.",
  "secret-file-exposed":
    "secretFile must not be readable or writable by group or others (chmod 600).",
  "secret-file-foreign": "secretFile must belong to the user running T3.",
  "secret-too-short": `the secret must be at least ${String(MIN_SECRET_LENGTH)} characters.`,
  "socket-path-invalid": "socketPath must be an absolute path.",
};

/** A present but unsafe or malformed opt-in config; the socket stays off. */
class ProtectedSocketConfigError extends Schema.TaggedError<ProtectedSocketConfigError>()(
  "ProtectedSocketConfigError",
  {
    configPath: Schema.String,
    problem: ProtectedSocketConfigProblem,
    cause: Schema.optional(Schema.Defect()),
  },
) {
  override get message(): string {
    return `Invalid protected authentication config ${this.configPath}: ${CONFIG_PROBLEMS[this.problem]}`;
  }
}

const isProtectedSocketConfigError = Schema.is(ProtectedSocketConfigError);

/** The socket could not be served at its path. */
class ProtectedSocketStartError extends Schema.TaggedError<ProtectedSocketStartError>()(
  "ProtectedSocketStartError",
  {
    socketPath: Schema.String,
    problem: Schema.Literals(["path-occupied", "listen-failed"]),
    cause: Schema.optional(Schema.Defect()),
  },
) {
  override get message(): string {
    return this.problem === "path-occupied"
      ? `${this.socketPath} exists and is not a socket.`
      : `Failed to serve the protected authentication socket at ${this.socketPath}.`;
  }
}

const isProtectedSocketStartError = Schema.is(ProtectedSocketStartError);

/** A Node errno code such as ENOENT; safe to log, unlike an error's message. */
const errnoCode = (cause: unknown) => {
  const code = typeof cause === "object" && cause !== null && "code" in cause ? cause.code : null;
  return typeof code === "string" ? code : undefined;
};

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
  else if (stale)
    throw new ProtectedSocketStartError({
      socketPath: config.socketPath,
      problem: "path-occupied",
    });
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
  const fail = (problem: ProtectedSocketConfigProblem, cause?: unknown) =>
    new ProtectedSocketConfigError({
      configPath: input.configPath,
      problem,
      ...(cause === undefined ? {} : { cause }),
    });
  const raw = await NodeFSP.readFile(input.configPath, "utf8").catch((cause: unknown) => {
    if (errnoCode(cause) === "ENOENT") return null;
    throw fail("config-unreadable", cause);
  });
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw fail("config-not-json", cause);
  }
  if (!isRecord(parsed) || typeof parsed.secretFile !== "string") throw fail("secret-file-unnamed");
  if (parsed.socketPath !== undefined && typeof parsed.socketPath !== "string")
    throw fail("socket-path-invalid");
  const secretFile = parsed.secretFile;
  if (!NodePath.isAbsolute(secretFile)) throw fail("secret-file-relative");
  const stat = await NodeFSP.stat(secretFile).catch((cause: unknown) => {
    throw fail("secret-file-unreadable", cause);
  });
  if (!stat.isFile()) throw fail("secret-file-not-regular");
  if ((stat.mode & 0o077) !== 0) throw fail("secret-file-exposed");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid())
    throw fail("secret-file-foreign");
  const secret = (
    await NodeFSP.readFile(secretFile, "utf8").catch((cause: unknown) => {
      throw fail("secret-file-unreadable", cause);
    })
  ).trim();
  if (secret.length < MIN_SECRET_LENGTH) throw fail("secret-too-short");
  const socketPath = parsed.socketPath ?? NodePath.join(input.baseDir, SOCKET_FILE);
  if (!NodePath.isAbsolute(socketPath)) throw fail("socket-path-invalid");
  return { socketPath, secret };
};

/** Starts the socket when configured; logs and stays off when not or when unsafe. */
export const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const config = yield* ServerConfig.ServerConfig;
    const env = yield* HostProcessEnvironment;
    const browser = yield* ServerBrowser.ServerBrowser;
    const configPath = env[CONFIG_ENV] ?? NodePath.join(config.baseDir, CONFIG_FILE);
    const loaded = yield* Effect.tryPromise({
      try: () => loadProtectedSocketConfig({ configPath, baseDir: config.baseDir }),
      catch: (cause) =>
        isProtectedSocketConfigError(cause)
          ? cause
          : new ProtectedSocketConfigError({ configPath, problem: "config-unreadable", cause }),
    }).pipe(
      Effect.catchTags({
        ProtectedSocketConfigError: (error) =>
          Effect.logWarning("Protected authentication socket stays off: invalid config.", {
            configPath,
            cause: error.message,
          }).pipe(Effect.as(null)),
      }),
    );
    if (loaded === null) return;
    yield* Effect.acquireRelease(
      Effect.tryPromise({
        try: () => serveProtectedHost(browser.protectedHost, loaded),
        catch: (cause) =>
          isProtectedSocketStartError(cause)
            ? cause
            : new ProtectedSocketStartError({
                socketPath: loaded.socketPath,
                problem: "listen-failed",
                cause,
              }),
      }),
      (served) => Effect.promise(() => served.close()),
    ).pipe(
      Effect.tap(() =>
        Effect.logInfo("Protected authentication socket listening.", {
          socketPath: loaded.socketPath,
        }),
      ),
      Effect.catchTags({
        ProtectedSocketStartError: (error) =>
          Effect.logWarning("Protected authentication socket failed to start.", {
            socketPath: loaded.socketPath,
            cause: String(error.cause ?? error.message),
          }),
      }),
    );
  }),
);

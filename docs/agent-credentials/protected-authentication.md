# Protected browser authentication (agent-credentials fork patch)

This fork lets a local credential service sign an agent's server-browser tab in
without the agent, or T3, learning which credential was used. The agent only
gets a grant. The credential service redeems the grant over a private socket
and drives one _protected interval_. During the interval T3 performs the
mechanical steps (inspect, fill, submit) and locks the tab's browser storage
against observation.

This is the T3 side of [CRGDan/agent-credentials#9](https://github.com/CRGDan/agent-credentials/issues/9).
Its interface follows that repository's ADR 0004 (browser auth policy and host
interface). The credential service client is not part of this patch.

## Flow

1. The agent opens a tab with `preview_open`, which makes the tab the agent's
   own.
2. The agent calls `preview_authentication_grant({ tabId })` and passes the
   grant to the credential service's authentication tool.
3. The credential service connects to the socket and says `hello` with the
   shared secret.
4. It calls `begin` with the grant and a deadline, which locks the tab's
   browser context.
5. It runs `inspect`, `fill`, `submit` and so on as many times as the login
   needs.
6. It ends the interval with `end`.
7. The tab is released, observation resumes, and every field filled during
   the interval is cleared.

## The grant tool

`preview_authentication_grant` is in both the full and the standard preview
toolkits. It acts as the calling agent session.

|         | Schema                                                                                                                                                                       |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Input   | `{ "tabId": string }`. Required; trimmed, non-empty, at most 128 characters. It must be a collaborative tab the caller owns, from `preview_open` or `preview_status`.        |
| Output  | `{ "grant": string, "tabId": string, "expiresAt": string }`. `grant` is opaque (`t3pa_` plus 256 random bits, base64url) and `expiresAt` is ISO-8601.                        |
| Failure | The usual preview tool failure. A tab another agent owns, a missing tab, a tab a human controls, a desktop-rendered tab or a locked tab is refused before a grant is minted. |

Properties of a grant:

- Bound to the tab and to the agent session that minted it.
- Valid for 60 seconds.
- Single use: redeeming it consumes it, whether or not `begin` succeeds.
- T3 keeps only a SHA-256 digest of the grant.

## Enabling the socket

The socket is off unless configured. T3 reads
`$T3CODE_PROTECTED_AUTH_CONFIG`, or `<base dir>/protected-auth.json` (by
default `~/.t3/protected-auth.json`):

```json
{ "secretFile": "/absolute/path/to/secret", "socketPath": "/optional/absolute/path.sock" }
```

The secret file must:

- be a regular file owned by the user running T3;
- have mode `0600` (no group or other bits);
- hold at least 32 characters (surrounding whitespace is trimmed).

`socketPath` defaults to `<base dir>/protected-auth.sock`. The socket is
created with mode `0600`. A stale socket file is replaced, but any other file
at that path stops startup of the socket.

If the config is present but unsafe or malformed, T3 logs a warning and keeps
the socket off. The rest of the server starts normally.

## Socket protocol `t3-protected-auth/2`

Version 2 added the required `form` key to each present `inspect` target.

The protocol is newline-delimited JSON (NDJSON) over a unix stream socket. Each
line carries one JSON object and may be at most 1 MiB.

**Authentication.** The first line must be:

```json
{ "id": 1, "op": "hello", "secret": "…" }
```

- On success the reply is `{"id":1,"ok":true,"result":{"protocol":"t3-protected-auth/2"}}`.
- Anything else gets `{"id":…,"ok":false,"code":"unauthorized"}` and the
  connection closes.
- The secret comparison is constant time.

**Requests and replies.**

- A request is `{"id": number|string, "op": string, ...fields}`.
- A success reply is `{"id", "ok": true, "result"}`.
- A failure reply is `{"id", "ok": false, "code"}`. It carries a code only,
  never page content or values.
- Requests may be pipelined. Operations on one interval run in order.

**Interval ownership.** Intervals belong to their connection. If the
connection closes, each of its open intervals ends: fields are cleared and the
lock is released.

A _target_ is `{"selector": css, "frame"?: css}`.

- `selector` is a CSS selector that must match exactly one element.
- `frame`, when set, selects an iframe in the top-level document that contains
  the element.

### Operations

| op          | fields                                       | result                                                    |
| ----------- | -------------------------------------------- | --------------------------------------------------------- |
| `begin`     | `grant`, `deadline` (epoch ms), `tabId`?     | `{ interval, contextId }`                                 |
| `inspect`   | `interval`, `targets` (at most 32)           | `{ url, pageVersion, frames: [{url}], targets: [state] }` |
| `fill`      | `interval`, `target`, `value`, `pageVersion` | `{}`                                                      |
| `submit`    | `interval`, `target`, `pageVersion`          | `{}`                                                      |
| `clear`     | `interval`, `targets`                        | `{}`                                                      |
| `readText`  | `interval`, `target`                         | `{ text: string \| null }`                                |
| `fetchText` | `interval`, `url` (http or https)            | `{ status, body }` (body capped at 1 MiB)                 |
| `end`       | `interval`                                   | `{}`; idempotent                                          |

**`begin`**

- The deadline is capped at 3 minutes from now.
- `tabId`, when given, must equal the grant's tab.
- `contextId` is stable for the tab's browser storage. Popups share their
  opener's context.

**`inspect`**

- A target state is `{present:false}` or
  `{present:true, frameUrl, editable, inputType?, form}`.
- `form` is `null` when the element has no form owner (a `div`, or an input
  outside any form and without a `form=` attribute). Otherwise it is
  `{method, action}`, where the submission would go:
  - `method` is the lowercased method as the DOM normalizes it: `get`, `post`
    or `dialog`.
  - `action` is the absolute URL, resolved against the document's base URL. An
    empty or missing action resolves to the document URL. A cross-origin
    action is reported as it is.
  - The owner is the element's `form`, so a `form=` attribute counts. For a
    submit button (`<button type=submit>`, `<input type=submit|image>`), a
    `formmethod` or `formaction` attribute overrides the form's value.
- T3 only reports `form`. The credential service decides whether to fill,
  for example refusing a `get` method or an action outside its allowed
  origins.
- `pageVersion` changes whenever any frame of the tab navigates.

**`fill`** refuses with `navigated` if `pageVersion` is stale. It accepts only
text-like inputs and textareas that are neither disabled nor read-only.

**`submit`**

1. Clicks the target.
2. Waits for the navigation it starts, if any. It waits up to 1.5 s for one to
   start, longer while a navigation request is in flight.
3. Waits for the `load` state.

**`readText`** returns the target's trimmed `textContent`, or `null` when the
target is absent.

**`fetchText`** issues a GET with the tab's cookies and follows redirects.

### Error codes

| code                  | meaning                                                                                                     |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `unauthorized`        | Missing or wrong secret. The connection closes.                                                             |
| `bad-request`         | Malformed line, unknown op, missing or invalid field, or unknown interval.                                  |
| `grant-invalid`       | Unknown, expired, already used, or for a different `tabId`. The client should report it as `tab-not-owned`. |
| `tab-not-found`       | Reserved. A tab that no longer exists reports `tab-closed`.                                                 |
| `tab-closed`          | The tab is closed or closing.                                                                               |
| `tab-not-owned`       | The minting agent session no longer owns the tab.                                                           |
| `busy`                | The context is already in an interval, a human is controlling one of its tabs, or a dialog is open.         |
| `navigated`           | `pageVersion` is stale.                                                                                     |
| `target-missing`      | The selector matched zero or more than one element, or the frame is missing.                                |
| `target-not-editable` | The target is not a text-like input or textarea, or is disabled or read-only.                               |
| `timeout`             | The deadline passed, the interval ended, or a step exceeded the time left.                                  |
| `unavailable`         | Desktop-rendered tab, or the client disconnected during `begin`.                                            |
| `failed`              | Any other failure.                                                                                          |

## What the lock does

While an interval is open, the lock covers the tab and every tab sharing its
browser context.

**Refused or suppressed:**

- **Agent tools.** Preview tools on the locked tabs fail with
  `PreviewAutomationControlInterruptedError` and reason `protected`. This
  includes snapshot, evaluate, screenshots, type and click, navigation,
  `recordingStart` and `recordingStop`, dialog, close, and another
  `preview_authentication_grant`. They are refused up front, so they do not
  queue behind the lock.
- **Viewers.** Screencasts pause, and frames that arrive anyway are
  acknowledged and dropped. Still images are not pushed. Human take-control is
  refused.
- **Recordings.** An active recording pauses for the interval.
- **Status.** `preview_status` omits the page title.
- **Console and network capture.** Console entries, failed requests and
  responses from these tabs are not recorded, so they are never replayed into
  later snapshots.
- **Dialogs** that the page opens are dismissed.
- **Popups** are closed as soon as they open.
- **Idle cleanup** skips locked tabs.

**When the interval ends.** On `end`, the deadline, a failed `fill` or
`submit`, a client disconnect or tab close:

1. In-flight steps are given up to 2 s to finish.
2. Every field filled during the interval is cleared (best effort).
3. The lock is released.
4. Observation and recordings resume.

## Isolation limit

The browser host runs as the same OS user as the agents. The lock stops T3's
own tools and viewers from observing the tab. It does not stop a process
running as that user from reading the browser's memory, its profile, or
`/proc`. Separating the browser host into its own container or user (docker
or lxd) was considered and deferred; Dan accepted this gap for the pilot.

The protected-auth socket and secret file are owner-only for the same reason.
They defend against other users, not against the agents.

## Known risks

- A hostile page can copy entered values into its own JavaScript state and
  expose them to a later `preview_evaluate` or snapshot after the interval. The
  host clears fields but cannot clear page memory. Use protected
  authentication only with sites you trust.
- A login form that submits with GET puts values into the URL, and the URL
  then appears in history, status and snapshots after the interval. `inspect`
  reports each target's `form` so the credential service can refuse such a
  form, or one that posts to an origin it does not allow.
- `form` describes the page when `inspect` ran. Page script can change a
  form's `method` or `action`, or submit the values itself with `fetch`, after
  inspection and before or during `submit`. `pageVersion` does not change for
  that, so T3 does not detect it.
- Target inspection runs a small function in the page's main world, so a page
  can detect it or interfere with it.
- On hosts without the `t3-chrome-headless-shell` AppArmor profile, T3's
  browser runs without Chrome's sandbox (`T3CODE_SERVER_BROWSER_SANDBOX=0`).
  The pilot ran this way. `t3 browser setup` installs the profile.

## Pinned build, install and rollback

The fork ships as `0.0.46-nightly.20261008.2833+ac.<n>`, which is upstream
`v0.0.46-nightly.20261008.2833` plus this patch. A server whose version
carries `+ac.` refuses update requests from clients. The version only moves
through these scripts, or through an explicit `t3 update` on the host.

| Script                                  | What it does                                                                                                                                                                                                            |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/agent-credentials/build.sh`    | Packs HEAD into a release-layout archive at the label. It runs in a temporary worktree and uses a checksum-verified user-local SEA Node. It reuses the active runtime's resource monitor and refuses migration changes. |
| `scripts/agent-credentials/install.sh`  | Unpacks the archive into `~/.t3/runtime/versions/<label>/`. It saves `service-state.json` under `~/.t3/runtime/agent-credentials/history/` and sets `activeVersion`. `--restart` restarts `t3code.service`.             |
| `scripts/agent-credentials/rollback.sh` | Restores the newest saved state, which puts back the previous `activeVersion`.                                                                                                                                          |

All three print their plan first and accept `--dry-run`.

Release builds bake in T3 Connect relay config. Pass `T3CODE_RELAY_URL`,
`T3CODE_CLERK_PUBLISHABLE_KEY`, `T3CODE_CLERK_JWT_TEMPLATE` and
`T3CODE_CLERK_CLI_OAUTH_CLIENT_ID` to `build.sh`. Without them it refuses
unless you pass `--without-relay`, and that build has no T3 Connect.

Upstream's release workflow (`relay_public_config` in
`.github/workflows/release.yml`) reads these from the production environment
and exports them to the bundle build. The server bundle bakes in the relay
URL, publishable key and CLI OAuth client id. The web client bakes in all
four as `VITE_*` values. They are public client identifiers, not secrets.

For `+ac.2` and later, the values were taken from the installed release
build: `~/.t3/runtime/versions/0.0.46-nightly.20261008.2833/`. Read them
from the `buildTimeRelayUrl`, `buildTimeClerkPublishableKey` and
`buildTimeClerkCliOAuthClientId` assignments in `t3`. Read
`VITE_CLERK_JWT_TEMPLATE` from the env object in `client/assets/*.js`. Pass
them to `build.sh` as environment variables. They are not committed here.

Release builds also bake in a relay tracing ingest token
(`T3CODE_RELAY_CLIENT_OTLP_TRACES_*`). It is not a public identifier, so the
pinned build leaves it out and sends no relay traces.

Installing does not enable the socket. Creating `~/.t3/protected-auth.json` is
a separate, deliberate step.

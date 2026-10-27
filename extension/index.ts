/**
 * kwallet-broker
 *
 * Lets the agent USE credentials stored in KWallet without ever seeing their
 * values. The agent calls tools; the tools fetch secrets server-side, perform
 * the real work, and return only the non-secret result.
 *
 * Tools:
 *   - kwallet_api  : make an HTTPS request authenticated by a KWallet entry
 *   - kwallet_list : list KWallet entry names (names only, never values)
 *   - kwallet_run  : run a bash command with a KWallet secret interpolated
 *                    (secret exported as $KWALLET_SECRET for the command;
 *                    never on argv; output scrubbed of the secret value)
 *
 * Commands (user-facing, run in extension context — typed values never enter
 * the agent conversation):
 *   - /kwallet-set <entry>            store a secret (prompted)
 *   - /kwallet-get <entry>            print a secret to the user's terminal
 *                                     ONLY (never returned to agent)
 *   - /kwallet-list                   list entries in the pi-agent folder
 *   - /kwallet-delete <entry>         remove an entry
 *
 * Defense-in-depth:
 *   - tool_call hook rewrites any bash command that references kwallet-query,
 *     secret-tool, kwalletcli, or the kwalletd data dir into a no-op, so the
 *     agent cannot exfiltrate secrets via the shell.
 *   - kwallet_run refuses to execute commands matching the same pattern (the
 *     run happens server-side, outside the bash tool, so it must enforce its
 *     own copy of the block) and redacts the literal secret from any output
 *     it returns, so the agent can USE the secret but never SEE it. Note this
 *     is not cryptographic: an encoded secret (base64, hex, ...) or an outbound
 *     network request could still carry the value out, exactly as with
 *     kwallet_api. It is a tool-boundary guard, not a sandbox.
 *
 * Folder handling:
 *   - Credentials live in folder "pi-agent" of wallet "kdewallet" by default.
 *   - This extension does NOT create the folder programmatically; the user must
 *     create it ONCE in KWalletManager. If /kwallet-set is run before the
 *     folder exists, the error includes a WARNING with the instructions.
 *   - Writes use a two-step: qdbus writePassword("", empty, not a secret) to
 *     create the entry, then kwallet-query -w via stdin to set the real value.
 *     (kwallet-query -w alone silently fails to CREATE new entries in KWallet6;
 *     it only overwrites.) The real secret never touches any command line.
 *
 * Config (env vars, read once at load — pi does NOT inject settings.json env into
 * extensions, so set these in your shell, not settings.json):
 *   KWALLET_NAME    default "kdewallet"
 *   KWALLET_FOLDER  default "pi-agent"
 *   KWALLET_MAX_BODY default "5242880"  (bytes returned to agent per call, 5 MiB)
 *
 * Security notes:
 *   - Pi has no sandbox. This extension is a tool-boundary guard, not a
 *     cryptographic one. An attacker who can load a malicious extension or
 *     modify this file can still reach the wallet.
 *   - KWallet entry NAMES and folder are treated as non-sensitive.
 *   - For untrusted agents, run pi in a container and do not mount
 *     ~/.local/share/kwalletd.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { URL } from "node:url";

const execFileP = promisify(execFile);

const WALLET = process.env.KWALLET_NAME ?? "kdewallet";
const FOLDER = process.env.KWALLET_FOLDER ?? "pi-agent";
const MAX_BODY = parseInt(process.env.KWALLET_MAX_BODY ?? "5242880", 10);
const APPID = "pi"; // label shown in KWallet permission prompts / entry owner

// Commands the agent must never run against the wallet itself. Applied BOTH to
// the agent's bash tool (tool_call hook) and to kwallet_run's command (which
// executes server-side and would otherwise bypass that hook).
const BLOCK_RE =
  /\b(kwallet-query|kwalletcli|secret-tool)\b|\.local\/share\/kwalletd|kwalletd5?\b/i;

// KWallet6 uses org.kde.kwalletd6 @ /modules/kwalletd6; KWallet5 uses d5.
const KWALLET_SERVICES = ["org.kde.kwalletd6", "org.kde.kwalletd5"] as const;
const KWALLET_PATHS: Record<string, string> = {
  "org.kde.kwalletd6": "/modules/kwalletd6",
  "org.kde.kwalletd5": "/modules/kwalletd5",
};

// Resolve a qdbus binary once at load (Qt6 first, then Qt5 fallback). Required
// for reliable entry creation (kwallet-query -w is broken for new entries) and
// for reliable folder/entry existence checks (kwallet-query -l exit code lies).
let QBIN = "";
for (const c of ["qdbus6", "qdbus-qt6", "qdbus"]) {
  try {
    require("node:child_process").execFileSync(c, ["--version"], { stdio: "ignore" });
    QBIN = c;
    break;
  } catch {
    /* try next */
  }
}

// ---------------------------------------------------------------------------
// KWallet access helpers
// ---------------------------------------------------------------------------

async function kwallet(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileP("kwallet-query", args, {
    maxBuffer: 4 * 1024 * 1024,
    timeout: 15_000,
  });
}

/** Read a secret value from KWallet. NEVER put the return value into agent content. */
async function readSecret(entry: string): Promise<string> {
  const { stdout } = await kwallet(["-r", entry, "-f", FOLDER, WALLET]);
  // kwallet-query prints the secret followed by a trailing newline; strip it.
  return stdout.replace(/\r?\n$/, "");
}

async function listEntries(): Promise<string[]> {
  try {
    const { stdout } = await kwallet(["-l", "-f", FOLDER, WALLET]);
    return stdout
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

// --- qdbus (D-Bus) helpers -------------------------------------------------

async function qdbus(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileP(QBIN, args, { timeout: 15_000, maxBuffer: 1024 * 1024 });
}

async function detectService(): Promise<string | null> {
  for (const svc of KWALLET_SERVICES) {
    try {
      const { stdout } = await qdbus([svc]);
      if (stdout.trim()) return svc;
    } catch {
      /* service not registered */
    }
  }
  return null;
}

/** Open the wallet over D-Bus and return a valid handle (>=0). */
async function openWallet(): Promise<{ service: string; handle: number }> {
  if (!QBIN) {
    throw new Error(
      `No qdbus binary found (tried qdbus6, qdbus-qt6, qdbus). Install 'qdbus-qt6' ` +
        `or create folder '${FOLDER}' manually in KWalletManager before /kwallet-set.`,
    );
  }
  const service = await detectService();
  if (!service) {
    throw new Error(
      `KWallet D-Bus service not reachable (neither org.kde.kwalletd6 nor d5). ` +
        `Is KWallet running? Start it, or create folder '${FOLDER}' manually in KWalletManager.`,
    );
  }
  const path = KWALLET_PATHS[service];
  const { stdout, stderr } = await qdbus([
    service, path, "org.kde.KWallet.open", WALLET, "0", APPID,
  ]);
  const handle = parseInt((stdout || "").trim(), 10);
  if (!Number.isFinite(handle) || handle < 0) {
    throw new Error(
      `KWallet.open('${WALLET}') failed (handle=${stdout.trim()}). ` +
        `Unlock the wallet and retry. stderr: ${stderr.trim()}`,
    );
  }
  return { service, handle };
}

/** Reliable folder-existence check via qdbus hasFolder. */
async function folderExists(): Promise<boolean> {
  try {
    const { service, handle } = await openWallet();
    const path = KWALLET_PATHS[service];
    const has = (await qdbus([
      service, path, "org.kde.KWallet.hasFolder", String(handle), FOLDER, APPID,
    ])).stdout.trim().toLowerCase();
    return has === "true" || has === "1";
  } catch {
    return false;
  }
}

/** List entry names via qdbus entryList (authoritative). */
async function qdbusEntryList(): Promise<string[]> {
  const { service, handle } = await openWallet();
  const path = KWALLET_PATHS[service];
  const { stdout } = await qdbus([
    service, path, "org.kde.KWallet.entryList", String(handle), FOLDER, APPID,
  ]);
  return stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

/** Human-readable instructions for creating the folder manually. */
function folderMissingWarning(): string {
  return (
    `WARNING: KWallet folder '${FOLDER}' not found in wallet '${WALLET}'. ` +
    `Create it ONCE in KWalletManager: open KWalletManager -> wallet ` +
    `'${WALLET}' -> right-click the folder list -> New Folder -> name it ` +
    `'${FOLDER}'. Then retry /kwallet-set. (This extension does not create ` +
    `folders programmatically.)`
  );
}

/**
 * Write a secret to KWallet. Two-step, to keep the value OFF the command line:
 *   1. qdbus writePassword with EMPTY value — creates the entry. (kwallet-query
 *      -w silently fails to CREATE new entries in KWallet6; only overwrite works.)
 *      The empty value is not a secret, so putting it on the qdbus cmdline is OK.
 *   2. kwallet-query -w (stdin = real secret) — overwrites the empty entry with
 *      the real value. stdin keeps the secret off the cmdline / ps / history.
 * Verifies the write by reading back and comparing; errors loudly on mismatch
 * rather than exposing the secret via any fallback.
 */
async function writeSecret(entry: string, value: string): Promise<void> {
  if (!(await folderExists())) {
    throw new Error(folderMissingWarning());
  }
  const { service, handle } = await openWallet();
  const path = KWALLET_PATHS[service];

  // step 1: ensure the entry exists (create empty if missing)
  const exists = (await qdbusEntryList()).includes(entry);
  if (!exists) {
    const created = (await qdbus([
      service, path, "org.kde.KWallet.writePassword", String(handle), FOLDER, entry, "", APPID,
    ])).stdout.trim().toLowerCase();
    if (created !== "0" && created !== "true" && created !== "1") {
      throw new Error(`KWallet.writePassword(create empty '${entry}') returned '${created}'`);
    }
  }

  // step 2: overwrite with the real value via stdin (secret never on cmdline)
  await new Promise<void>((resolve, reject) => {
    const child = spawn("kwallet-query", ["-w", entry, "-f", FOLDER, WALLET], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let err = "";
    child.stderr.on("data", (c) => (err += c.toString()));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(err || `kwallet-query -w exited ${code}`))));
    child.stdin.end(value);
  });

  // verify
  const back = await readSecret(entry);
  if (back !== value) {
    throw new Error(
      `writeSecret verify failed for '${entry}': read-back mismatch. ` +
        `The entry may be empty — retry /kwallet-set, or inspect in KWalletManager.`,
    );
  }
}

async function deleteEntry(entry: string): Promise<void> {
  // Real deletion via qdbus removeEntry (kwallet-query has no delete flag).
  if (!(await folderExists())) {
    throw new Error(folderMissingWarning());
  }
  const { service, handle } = await openWallet();
  const path = KWALLET_PATHS[service];
  const removed = (await qdbus([
    service, path, "org.kde.KWallet.removeEntry", String(handle), FOLDER, entry, APPID,
  ])).stdout.trim().toLowerCase();
  if (removed !== "true" && removed !== "1" && removed !== "0") {
    throw new Error(`KWallet.removeEntry('${entry}') returned '${removed}'`);
  }
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

type AuthMode = "bearer" | "basic" | "header" | "apikey-query" | "none";

interface HttpOpts {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  authMode: AuthMode;
  authHeader?: string; // for "header" mode: header name to hold the secret
  authQuery?: string;  // for "apikey-query" mode: query param name
  basicUser?: string;  // for "basic" mode: username paired with secret
  timeoutMs?: number;
}

function doRequest(opts: HttpOpts, secret: string): Promise<{ status: number; headers: Record<string, string | string[]>; body: string; truncated: boolean }> {
  return new Promise((resolve, reject) => {
    const u = new URL(opts.url);
    const isTls = u.protocol === "https:";
    const lib = isTls ? httpsRequest : httpRequest;

    // Apply auth.
    const headers: Record<string, string> = { ...opts.headers };
    let path = u.pathname + u.search;
    switch (opts.authMode) {
      case "bearer":
        headers["Authorization"] = `Bearer ${secret}`;
        break;
      case "basic": {
        const raw = `${opts.basicUser ?? ""}:${secret}`;
        headers["Authorization"] = `Basic ${Buffer.from(raw).toString("base64")}`;
        break;
      }
      case "header":
        if (!opts.authHeader) throw new Error("authHeader required for mode='header'");
        headers[opts.authHeader] = secret;
        break;
      case "apikey-query": {
        if (!opts.authQuery) throw new Error("authQuery required for mode='apikey-query'");
        const sp = new URLSearchParams(u.searchParams);
        sp.set(opts.authQuery, secret);
        path = `${u.pathname}?${sp.toString()}`;
        break;
      }
      case "none":
        break;
    }

    const reqOpts = {
      method: opts.method,
      hostname: u.hostname,
      port: u.port || (isTls ? 443 : 80),
      path,
      headers,
    };

    const req = lib(reqOpts, (res) => {
      let body = "";
      let truncated = false;
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        if (truncated) return;
        size += chunk.length;
        if (size > MAX_BODY) {
          truncated = true;
          body += chunk.slice(0, MAX_BODY - (size - chunk.length)).toString("utf8");
          return;
        }
        body += chunk.toString("utf8");
      });
      res.on("end", () => {
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers as Record<string, string | string[]>,
          body,
          truncated,
        });
      });
    });

    req.on("error", reject);
    if (opts.timeoutMs) req.setTimeout(opts.timeoutMs, () => req.destroy(new Error(`request timed out after ${opts.timeoutMs}ms`)));
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Run helper (bash command with a KWallet secret in its environment)
// ---------------------------------------------------------------------------

const RUN_MAX_OUTPUT = MAX_BODY; // per-stream output cap returned to the agent
const RUN_MAX_TIMEOUT_MS = 120_000;

interface RunResult {
  code: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

/**
 * Run `bash -c <command>` with the secret exported as an environment variable.
 * The secret travels via the child's environment (spawn env option), never
 * argv, so it cannot appear in `ps`. The command string itself only ever
 * contains the placeholder ($KWALLET_SECRET or the --envName name), which bash
 * expands internally. Returns the result plus a `redact` function the caller
 * MUST apply to any output before returning it to the agent.
 */
async function runWithSecret(
  entry: string,
  command: string,
  envName: string,
  timeoutMs: number,
): Promise<{ result: RunResult; redact: (s: string) => string }> {
  if (!command.trim()) {
    throw new Error("command is required");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) {
    throw new Error(`envName '${envName}' is not a valid shell variable name`);
  }
  // Same block as the bash tool_call hook: the run executes server-side, so
  // without this the agent could read ANY wallet folder via kwallet-query and
  // defeat the extension's whole purpose.
  if (BLOCK_RE.test(command)) {
    throw new Error(
      "blocked by kwallet-broker: command may not access the wallet directly; " +
        "credentials may only be used via the interpolated env var",
    );
  }
  const secret = await readSecret(entry);
  if (!secret) {
    throw new Error(`KWallet entry '${entry}' (folder '${FOLDER}') is empty — nothing to interpolate`);
  }
  // Literal (non-regex) split/join so secret contents can't break the scrub.
  const redact = (s: string): string => s.split(secret).join("[REDACTED]");

  const result = await new Promise<RunResult>((resolve, reject) => {
    const child = spawn("bash", ["-c", command], {
      env: { ...process.env, [envName]: secret },
    });
    const state = { timedOut: false, truncated: false };
    let out: Buffer = Buffer.alloc(0);
    let err: Buffer = Buffer.alloc(0);
    const collect = (buf: Buffer, chunk: Buffer): Buffer => {
      if (buf.length >= RUN_MAX_OUTPUT) {
        state.truncated = true;
        return buf;
      }
      const room = RUN_MAX_OUTPUT - buf.length;
      if (chunk.length > room) {
        state.truncated = true;
        return Buffer.concat([buf, chunk.slice(0, room)]);
      }
      return Buffer.concat([buf, chunk]);
    };
    child.stdout.on("data", (c: Buffer) => {
      out = collect(out, c);
    });
    child.stderr.on("data", (c: Buffer) => {
      err = collect(err, c);
    });
    const timer = setTimeout(() => {
      state.timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        timedOut: state.timedOut,
        stdout: out.toString("utf8"),
        stderr: err.toString("utf8"),
        truncated: state.truncated,
      });
    });
  });
  return { result, redact };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const AuthModeSchema = Type.Union(
  [
    Type.Literal("bearer"),
    Type.Literal("basic"),
    Type.Literal("header"),
    Type.Literal("apikey-query"),
    Type.Literal("none"),
  ],
  { description: "How to attach the KWallet secret to the request. bearer=Authorization: Bearer <secret>; basic=Authorization: Basic base64(user:secret) (set basicUser); header=put secret in header named authHeader; apikey-query=put secret in query param authQuery; none=don't attach." },
);

export function register(pi: ExtensionAPI) {
  // --- kwallet_api --------------------------------------------------------
  pi.registerTool({
    name: "kwallet_api",
    label: "KWallet HTTPS call",
    description:
      "Make an HTTPS (or HTTP) request authenticated by a secret stored in " +
      "KWallet. The secret is read from KWallet inside the tool and used for " +
      "the request; it is NEVER returned. Use this instead of fetching the " +
      "credential yourself. Set authMode to control how the secret is attached.",
    parameters: Type.Object({
      credEntry: Type.String({ description: "KWallet entry name holding the secret (in the configured folder)." }),
      url: Type.String({ description: "Full URL including scheme and path, e.g. https://api.openai.com/v1/models" }),
      method: Type.Optional(Type.String({ description: "HTTP method. Default GET." })),
      headers: Type.Optional(Type.Record(Type.String(), Type.String(), { description: "Extra request headers." })),
      body: Type.Optional(Type.String({ description: "Request body (string)." })),
      authMode: Type.Optional(AuthModeSchema),
      authHeader: Type.Optional(Type.String({ description: "Header name for mode='header'." })),
      authQuery: Type.Optional(Type.String({ description: "Query param name for mode='apikey-query'." })),
      basicUser: Type.Optional(Type.String({ description: "Username for mode='basic'." })),
      timeoutMs: Type.Optional(Type.Number({ description: "Per-request timeout in ms. Default 30000." })),
    }),
    async execute(_toolCallId, p) {
      const secret = await readSecret(p.credEntry);
      try {
        const res = await doRequest(
          {
            method: (p.method ?? "GET").toUpperCase(),
            url: p.url,
            headers: p.headers ?? {},
            body: p.body,
            authMode: (p.authMode ?? "bearer") as AuthMode,
            authHeader: p.authHeader,
            authQuery: p.authQuery,
            basicUser: p.basicUser,
            timeoutMs: p.timeoutMs ?? 30_000,
          },
          secret,
        );
        const note = res.truncated ? ` [body truncated at ${MAX_BODY} bytes]` : "";
        return {
          content: [
            {
              type: "text",
              text: `HTTP ${res.status}${note}\n${res.body}`,
            },
          ],
          details: { status: res.status, truncated: res.truncated },
        };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return {
          content: [{ type: "text", text: `kwallet_api error: ${msg}` }],
          isError: true,
          details: { status: 0, truncated: false },
        };
      }
    },
  });

  // --- kwallet_list -------------------------------------------------------
  pi.registerTool({
    name: "kwallet_list",
    label: "List KWallet entries",
    description:
      "List the names of KWallet entries in the configured folder. " +
      "Returns entry names only — never secret values.",
    parameters: Type.Object({}),
    async execute() {
      const entries = await listEntries();
      return {
        content: [
          {
            type: "text",
            text: entries.length
              ? `KWallet entries in folder '${FOLDER}' of wallet '${WALLET}':\n${entries.map((e) => `- ${e}`).join("\n")}`
              : `No entries found in folder '${FOLDER}' of wallet '${WALLET}'. ` +
                `If the folder does not exist, create it in KWalletManager first.`,
          },
        ],
        details: { entries },
      };
    },
  });

  // --- kwallet_run -------------------------------------------------------
  pi.registerTool({
    name: "kwallet_run",
    label: "Run command with KWallet secret",
    description:
      "Run a bash command with a KWallet secret interpolated into it, for " +
      "commands kwallet_api cannot express (CLIs, docker login, etc). The " +
      "command string is executed by bash with the secret exported as an " +
      "environment variable, so reference the secret as '$KWALLET_SECRET' (or " +
      "the name given in envName) — bash expands it at run time. The secret is " +
      "never on any process's command line, and it is scrubbed from the output " +
      "before anything is returned. Returns the exit code plus stdout/stderr. " +
      "Commands that access the wallet directly (kwallet-query etc.) are blocked.",
    parameters: Type.Object({
      credEntry: Type.String({ description: "KWallet entry name holding the secret (in the configured folder)." }),
      command: Type.String({
        description:
          "Bash command string; reference the secret as $KWALLET_SECRET. " +
          "Example: 'docker login -u alice -p \"$KWALLET_SECRET\" registry.example.com'. " +
          "Do NOT try to read the wallet itself — such commands are blocked.",
      }),
      envName: Type.Optional(Type.String({ description: "Environment variable name holding the secret. Default KWALLET_SECRET." })),
      timeoutMs: Type.Optional(Type.Number({ description: "Timeout in ms, capped at 120000. Default 30000." })),
    }),
    async execute(_toolCallId, p) {
      try {
        const timeoutMs = Math.min(Math.max(p.timeoutMs ?? 30_000, 1), RUN_MAX_TIMEOUT_MS);
        const { result, redact } = await runWithSecret(
          p.credEntry,
          p.command,
          p.envName ?? "KWALLET_SECRET",
          timeoutMs,
        );
        const parts: string[] = [
          `exit code: ${result.code ?? "none"}` +
            (result.signal ? ` (signal ${result.signal})` : "") +
            (result.timedOut ? ` [timed out after ${timeoutMs}ms]` : ""),
        ];
        if (result.stdout) parts.push("--- stdout ---", redact(result.stdout));
        if (result.stderr) parts.push("--- stderr ---", redact(result.stderr));
        if (result.truncated) {
          parts.push(`[output truncated at ${RUN_MAX_OUTPUT} bytes per stream]`);
        }
        return {
          content: [{ type: "text", text: parts.join("\n") }],
          details: {
            code: result.code,
            signal: result.signal,
            timedOut: result.timedOut,
            truncated: result.truncated,
          },
        };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return {
          content: [{ type: "text", text: `kwallet_run error: ${msg}` }],
          isError: true,
          details: { code: null, signal: null, timedOut: false, truncated: false },
        };
      }
    },
  });

  // ---------------------------------------------------------------------------
  // Commands (user-side; typed/pasted values never reach the agent)
  // ---------------------------------------------------------------------------

  pi.registerCommand("kwallet-set", {
    description: "Store a secret in KWallet (prompts for the value; value is never sent to the agent)",
    handler: async (args, ctx) => {
      const entry = (args ?? "").trim();
      if (!entry) {
        ctx.ui.notify("Usage: /kwallet-set <entry>", "warning");
        return;
      }
      const value = await ctx.ui.input(`Secret value for KWallet entry '${entry}'`, "");
      if (value == null) {
        ctx.ui.notify("Cancelled", "info");
        return;
      }
      // Proactive folder check: warn loudly BEFORE attempting the write so the
      // user always sees the instruction if the folder is missing. The notify
      // is transient; the stderr line is persistent in the terminal scrollback.
      if (!(await folderExists())) {
        const warn = folderMissingWarning();
        process.stderr.write(`\n${warn}\n\n`);
        ctx.ui.notify(warn, "warning");
        return;
      }
      try {
        await writeSecret(entry, value);
        ctx.ui.notify(`Stored KWallet entry '${entry}'`, "info");
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        ctx.ui.notify(msg, "error");
      }
    },
  });

  pi.registerCommand("kwallet-get", {
    description: "Print a KWallet secret to the terminal (operator only; not returned to the agent)",
    handler: async (args, ctx) => {
      const entry = (args ?? "").trim();
      if (!entry) {
        ctx.ui.notify("Usage: /kwallet-get <entry>", "warning");
        return;
      }
      try {
        const value = await readSecret(entry);
        // Print to stderr of the pi process, not as a tool result.
        // This is operator-side only; the agent does not see command output.
        process.stderr.write(`\n[kwallet-get] ${entry} = ${value}\n\n`);
        ctx.ui.notify(`Printed ${entry} to terminal (operator view)`, "info");
      } catch (e) {
        ctx.ui.notify(`Failed: ${e instanceof Error ? e.message : String(e)}`, "error");
      }
    },
  });

  pi.registerCommand("kwallet-list", {
    description: "List KWallet entries in the configured folder",
    handler: async (_args, ctx) => {
      const entries = await listEntries();
      ctx.ui.notify(
        entries.length
          ? `Entries: ${entries.join(", ")}`
          : `No entries in folder '${FOLDER}' (create it in KWalletManager first)`,
        "info",
      );
    },
  });

  pi.registerCommand("kwallet-delete", {
    description: "Clear a KWallet entry (overwrites with empty; full deletion needs qdbus)",
    handler: async (args, ctx) => {
      const entry = (args ?? "").trim();
      if (!entry) {
        ctx.ui.notify("Usage: /kwallet-delete <entry>", "warning");
        return;
      }
      try {
        await deleteEntry(entry);
        ctx.ui.notify(`Cleared KWallet entry '${entry}'`, "info");
      } catch (e) {
        ctx.ui.notify(`Failed: ${e instanceof Error ? e.message : String(e)}`, "error");
      }
    },
  });

  // ---------------------------------------------------------------------------
  // Defense-in-depth: block the agent from reading the wallet via bash
  // ---------------------------------------------------------------------------

  const BLOCK_MESSAGE =
    "blocked by kwallet-broker: credentials may only be used via the kwallet_api / kwallet_run / kwallet_list tools";

  pi.on("tool_call", async (event) => {
    if (!isToolCallEventType("bash", event)) return;
    const cmd = event.input?.command ?? "";
    if (BLOCK_RE.test(cmd)) {
      // Rewrite to a no-op so the agent's attempt fails loudly without exfil.
      event.input.command = `echo '${BLOCK_MESSAGE}'`;
    }
  });
}

export default function (pi: ExtensionAPI) {
  register(pi);
}
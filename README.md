# kwallet-broker

A small shell CLI that lets you **use** credentials stored in [KWallet](https://docs.kde.org/stable5/en/kwalletmanager/kwalletmanager/index.html) from the command line **without exposing their values** — secrets are read from KWallet inside the tool and fed to `curl` via a mode-`0600` curl config file (`-K`), so they never appear on the command line, in `ps`, or in shell history.

## Requirements

- `kwallet-query` (KWallet CLI; `kwallet6` package on Debian/Ubuntu) — used for reads/list/overwrite
- `curl`
- `qdbus6` (or `qdbus-qt6` / `qdbus`) — required for `ensure-folder`, `set` (entry creation), and `delete`

## Install

```bash
chmod +x kwallet-broker
# option A: link into ~/.local/bin (assumes it's on PATH)
ln -sf "$PWD/kwallet-broker" ~/.local/bin/kwallet-broker
# option B: copy to /usr/local/bin
sudo install -m755 kwallet-broker /usr/local/bin/kwallet-broker
```

## Quick start

```bash
# 1. create the pi-agent folder once (idempotent)
kwallet-broker ensure-folder

# 2. store a secret (value via stdin so it never hits the cmdline/history)
printf '%s' "$API_KEY" | kwallet-broker set agent-openai --stdin

# 3. use it — secret is attached by the tool, never printed
kwallet-broker api --entry agent-openai --url https://api.openai.com/v1/models

# 3b. or run any bash command with the secret interpolated as an env var
kwallet-broker run --entry gh -- 'curl -sS -H "Authorization: Bearer $KWALLET_SECRET" https://api.github.com/user'

# 4. list entry names (names only, never values)
kwallet-broker list
```

> The folder is fixed to `pi-agent`; this tool cannot access any other folder in the wallet.
```

## Commands

Run `kwallet-broker --help` or `kwallet-broker <command> --help`.

| command | description |
|---|---|
| `api` | HTTPS/HTTP call authenticated by a KWallet entry |
| `run` | run a bash command with the secret interpolated — exported as `$KWALLET_SECRET` (or `--env NAME`) for an inner `bash -c`, never on argv |
| `list` | list KWallet entry **names** in a folder (never values) |
| `set` | store a secret in `pi-agent` (reads value from stdin via `--stdin`); two-step create-empty-then-overwrite so the value never hits the cmdline |
| `get` | print a secret to stdout (**operator only**) |
| `delete` | clear an entry (overwrites with empty) |
| `ensure-folder` | create a KWallet folder if missing (uses qdbus) |
| `help` | show top-level help |

## Auth modes (`api --mode`)

| mode | attachment |
|---|---|
| `bearer` (default) | `Authorization: Bearer <secret>` |
| `basic` | `Authorization: Basic base64(--user : <secret>)` |
| `header` | header named `--header-name` set to the secret |
| `apikey-query` | query param `--query-name` set to the secret (in the config URL, not argv) |
| `none` | don't attach |

## Config (env vars)

| var | default | meaning |
|---|---|---|
| `KWALLET_NAME` | `kdewallet` | wallet to open |

The folder is **hardcoded to `pi-agent`** and cannot be changed — there is no `--folder` flag and `KWALLET_FOLDER` is not honored. The tool can only ever access the `pi-agent` folder.

Override the wallet per-invocation: `KWALLET_NAME=other-wallet kwallet-broker list`

## Security model

- Secrets are read from KWallet with `kwallet-query -r` (stdout, captured) and written to a `mktemp` file with `umask 077`, passed to `curl -K`, then deleted. The value is never on `curl`'s argv.
- `set` uses a two-step write: (1) `qdbus writePassword` with an **empty** value to create the entry (`kwallet-query -w` silently fails to create new entries in KWallet6 — it only overwrites), then (2) `kwallet-query -w` (stdin) to overwrite with the real value. The empty string is not a secret, so step 1 putting it on the qdbus cmdline is safe; the real secret only ever travels via stdin. The write is verified by read-back.
- `set`'s value is read via stdin; `--stdin` is required and the tool refuses to read from a TTY prompt so it can't hang or echo the value.
- `ensure-folder` creates the `pi-agent` folder via `qdbus createFolder` and then `close()`s the wallet handle to flush to disk (without the flush, KWallet6 keeps the folder in-memory only and it vanishes on the next open).
- `get` prints the secret to stdout — **operator only**. Don't pipe it into an AI agent.
- `run` executes the command via `bash -c` in a subshell with the secret exported as an environment variable (`KWALLET_SECRET` by default, or `--env NAME`). The secret never appears on any process's argv — `bash -c`'s argv contains only the placeholder command, and bash expands the variable internally. The command string should be single-quoted so your own shell doesn't expand the placeholder. The child process's *environment* does contain the secret (same-user/root readable via `/proc`), as does anything the command spawns — like `get`, this is an operator command; don't use it to hand secrets to untrusted processes.
- This is a tool-boundary guard, not a sandbox. Anyone who can run this script or read the wallet can still reach the secrets. For untrusted automation, run in a container and don't mount `~/.local/share/kwalletd`.

## Differences from the pi extension

This repo also ships a pi extension (`~/.pi/agent/extensions/kwallet-broker/`) that exposes the same concept to the pi coding agent as `kwallet_api` / `kwallet_list` tools plus `/kwallet-*` commands, and blocks the agent's `bash` from calling `kwallet-query` directly. This CLI is the standalone, non-agent surface for the same workflow.
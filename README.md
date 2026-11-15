# rc-gateway-proxy

`gwproxy` is a small local proxy for Claude Code. It sends Claude Code's model calls to an
Anthropic-compatible gateway of your choice and leaves the rest of its traffic to Anthropic alone.
Claude Code itself is not modified and stays signed in to your own Claude account, so Remote
Control (driving a session from the Claude app or claude.ai/code, and starting sessions from
there) keeps working.

It is one file with no dependencies, `plugin/gwproxy.mjs`. This repository is also a Claude Code
plugin marketplace with one plugin that installs and checks it.

## Read this first

- **Anthropic documents Remote Control as unavailable when Claude Code uses a gateway.** Claude Code
  turns it off when `ANTHROPIC_BASE_URL` points anywhere but Anthropic. This tool gets the
  combination anyway, by leaving that setting alone and redirecting model calls at the network
  layer. That is not a supported configuration. The account you are signed in with is the one
  exposed if Anthropic objects, and a Claude Code update can stop it working at any time.
  The technique is not new: see [Prior art](#prior-art).
- **It reads your Claude sign-in token.** To tell model calls from everything else, it decrypts
  Claude Code's traffic to `api.anthropic.com` on your own machine, using a certificate authority
  it creates locally and that only Claude Code is told to trust. Read the code before you run it.
- **It is new and lightly tested**: macOS and Linux, two Claude Code versions, days of use. See
  [What has and has not been tested](#what-has-and-has-not-been-tested).
- Not affiliated with or endorsed by Anthropic.

## How it works

Claude Code is given two ordinary network settings, in the `env` block of
`~/.claude/settings.json`: `HTTPS_PROXY`, pointing at the proxy on `127.0.0.1`, and
`NODE_EXTRA_CA_CERTS`, naming the proxy's CA. It still believes it is talking to Anthropic.

For `api.anthropic.com` the proxy decides per request:

| Request | Goes to |
|---|---|
| `/v1/messages` and below (model calls, token counts) | Your gateway, with the gateway key in place of your login |
| A "continue" of a server-side conversation thread | Refused with Anthropic's own error, so Claude Code resends the conversation in full |
| A path on the pass list | Anthropic, unchanged, with your own login |
| The same, with a JSON body that has a `model` and `messages`, `prompt` or `input` | Refused, and logged as `TRIPWIRE` |
| The same, with a JSON or text body over 32 MB, or one that cannot be decompressed | Refused: it cannot be checked |
| Any other path | Refused by the proxy with 404, and logged as `unlisted`; it reaches neither side |

The pass list is `/api`, `/mcp-registry`, `/v1/code`, `/v1/environments`, `/v1/sessions`,
`/v1/mcp_servers`, `/v1/oauth`, `/v1/session_ingress`, `/v2/session_ingress`, `/v2/ccr-sessions`:
what Claude Code needs to sign in, load its configuration and run Remote Control. WebSockets are
relayed only on those paths.

Every other host is tunnelled and never read.

The default is to refuse. A model call on a path this proxy has not heard of fails at the proxy; it
does not run on your Claude plan. The price is that a Claude Code feature using some other
`/v1/...` path gets a 404 until its prefix is added as `"passPrefixes"` in
`~/.config/gwproxy/config.json`. `status` lists what has been refused that way.

## Install

You need macOS or Linux, Node.js 20 or later, `openssl`, Claude Code signed in to a paid Claude plan
(`claude auth login`), and a gateway file: a text file with two lines,

```
ANTHROPIC_BASE_URL=https://your-gateway.example
ANTHROPIC_API_KEY=your-gateway-key
```

Remove any `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or `apiKeyHelper`
from `~/.claude/settings.json` and from your shell first; `install` stops if it finds one.

**From the file:**

```sh
node plugin/gwproxy.mjs install --gateway-env /path/to/gateway.env
```

**As a plugin,** inside Claude Code:

```
/plugin marketplace add oadirt/rc-gateway-proxy
/plugin install gwproxy@gwproxy
/gwproxy:setup /path/to/gateway.env
```

Either way the same things happen, once per machine:

1. The gateway file and the script are copied into `~/.config/gwproxy/`, and a CA and a
   certificate for `api.anthropic.com` are made there. The CA's private key is deleted as soon as
   the certificate is signed.
2. A login service is registered. It runs the proxy on `127.0.0.1:3457`, starts at each login and
   is restarted if it stops.
   - macOS: a launchd agent, `local.gwproxy`; log in `~/Library/Logs/gwproxy.log`.
   - Linux: a systemd user unit, `gwproxy.service`; log with `journalctl --user -u gwproxy`. It
     runs while you are logged in. To keep it running after you log out and start it at boot,
     run `loginctl enable-linger $USER` once.
3. The two settings lines are added to `~/.claude/settings.json`, with a backup beside it.

After that a plain `claude`, `claude --remote-control` or `claude remote-control`, in any folder,
uses the gateway for model calls. There is no wrapper command and nothing to run per folder. Every
Claude Code session of that user goes through the proxy, including ones already running.

If the proxy is down, model calls fail; they do not fall back to your Claude plan.

Where there is no systemd user session (many containers), `install` makes the configuration and
certificates and then stops, saying so. Keep `node ~/.config/gwproxy/gwproxy.mjs serve` running by
whatever means you have, then run `node ~/.config/gwproxy/gwproxy.mjs settings enable`.

Windows is not supported. WSL counts as Linux.

## Commands

| | From a shell | As a plugin |
|---|---|---|
| Install, or update after a change | `node gwproxy.mjs install [--gateway-env FILE] [--port N]` | `/gwproxy:setup [FILE]` |
| See whether it runs and where requests went | `node ~/.config/gwproxy/gwproxy.mjs status` | `/gwproxy:status` |
| Stop using it | `node ~/.config/gwproxy/gwproxy.mjs uninstall` | `/gwproxy:uninstall` |

Running `install` again is safe: the proxy is restarted only if something it uses has changed. A
restart interrupts running sessions for a few seconds; they carry on by themselves.

Run `install` again when the gateway key changes, when you change or remove the Node.js version it
was installed with, or after updating this repository or the plugin.

The certificate lasts 397 days. To renew it: `node ~/.config/gwproxy/gwproxy.mjs setup --renew`,
then `install`, then restart your Claude Code sessions.

What the plugin adds over the file: `/plugin update` brings a new version, and a check at the start
of each session says so if the proxy is not set up, not answering, not what Claude Code is pointed
at, or older than the plugin's copy. The plugin never runs the proxy itself; the login service does.

`uninstall` removes the settings lines and the service, and Claude Code then runs on your own
Claude plan again; restart sessions that were already running. It leaves `~/.config/gwproxy/` in
place, so `install` with no arguments brings everything back. Disabling the plugin in `/plugin`
does not do this: the settings lines and the service stay.

## What to know before relying on it

- Any process on your machine can reach the proxy on loopback, make model calls on your gateway
  key, and open tunnels through it. There is no proxy password.
- Your gateway receives, besides the conversation, Claude Code's other request headers and your
  account's ID inside `metadata.user_id`. Only the login, API key and cookies are removed.
- Everything that is not a model call reaches Anthropic under your login, telemetry included.
- A model call sent to some other Anthropic hostname would be tunnelled unread. `status` lists the
  Anthropic and Claude hosts that were tunnelled.
- The tripwire is a guess at what a model call looks like. Uploads that are not JSON or text are
  sent on without being read.
- Commands that Claude Code runs inherit `HTTPS_PROXY`. They are tunnelled, except that a tool
  calling `api.anthropic.com` itself will not trust the proxy's certificate.
- Which account your gateway uses for a call is the gateway's business. If it can pick the account
  you are signed in with, that account's quota is still used.
- The log has one line per request to Anthropic's host: method, path and status. No headers, bodies
  or query strings.

## What has and has not been tested

**Against local stand-ins** (`node test/run.mjs`, 28 checks, about three minutes). The proxy is run
against a stand-in for `api.anthropic.com` and one for a gateway, and what each of them received
is checked. It covers every rule in the table above; that the login never reaches the gateway and
the gateway key never reaches Anthropic, across the whole run; gzip, streaming, keep-alive,
requests written back to back, `Expect: 100-continue`, bodiless responses; a 200 MB upload and a
200 MB download without the proxy holding them in memory; an upgraded (WebSocket-style) connection
carrying bytes both ways; an event stream held open for 150 seconds; 200 requests at once; a client
that goes away; a response dropped half way; oversized and undecodable bodies; malformed tunnel
requests; and the gateway being down. Six faults planted in the proxy one at a time (login sent to
the gateway, unlisted paths passed on, no tripwire, no thread refusal, upgrades allowed anywhere,
gateway cookies kept) were each caught.

The test listens on port 443 on this machine, because the proxy always connects to
`api.anthropic.com` on that port. macOS allows that without root; on Linux it needs root or
`net.ipv4.ip_unprivileged_port_start` at 443 or lower. Nothing leaves the machine. All 28 pass on
macOS and on Ubuntu 24.04.

**With Claude Code itself on macOS** (Claude Code 2.1.325, November 2026), against a real gateway:

- `claude -p` with a tool call, and `claude remote-control` with prompts sent to its session. Model
  calls were matched one for one against the gateway's own records.
- From claude.ai/code in a browser: a session started from the new-session page ran in the server's
  folder; an approval prompt answered with "Allow once" let the command run; a file attached to a
  message was fetched by Claude Code and read.
- With the proxy stopped, `claude -p` gave no answer and nothing reached the gateway in the 30
  seconds it was watched.
- `install` and `uninstall` on an empty home folder. The plugin installed from this repository on
  GitHub: its three commands, `/gwproxy:setup` with and without a file, and the
  session-start message as an interactive session shows it.

**On Linux:**

- Ubuntu 24.04 (arm64): `install` with a made-up gateway registered the systemd unit; the proxy
  passed, refused and tunnelled requests as it should; it was restarted after `kill -9`; after a
  reboot it was running five seconds after boot, before anyone logged in (lingering was on);
  `uninstall` and a second `install` with no arguments worked.
- Debian 12 in a container, with a real Claude sign-in and a real gateway, Claude Code 2.1.322, the
  proxy started by hand: `claude -p` with a tool call, and `claude remote-control` with a prompt
  sent to its session. Model calls went to the gateway and nothing was refused.
- Not done on Linux: the plugin commands, a browser-driven session, x86_64.

**Not tested:** the phone and desktop apps; a real WebSocket session from a Claude app (only the
stand-in's); anything on Windows. The proxy has run for about a day at a stretch in ordinary use
on one Mac; event streams in that time never lasted more than an hour before Claude Code
reconnected.

**Known gap.** Claude Code has features on `/v1/...` paths outside the pass list, and they get a
404 here. One seen in ordinary use is `/v1/ultrareview` (a quota lookup). See `status` for what
your own use runs into.

One independent read-only review was done before the tests above existed; its main finding (unknown
requests used to go to Anthropic) led to the refuse-by-default rule. The changes made after it have
not been reviewed. Not taken from it: a proxy password, a header allowlist for the gateway,
forwarding trailers, and replacing the three certificate files as one step.

## Prior art

Putting a local TLS-intercepting proxy in front of Claude Code, with `ANTHROPIC_BASE_URL` left
unset so that Remote Control stays on, is an established approach. This project is a small,
single-purpose take on it.

- [teamclaude](https://github.com/KarpelesLab/teamclaude) pools several accounts and backends
  behind one proxy. Its default mode is the same kind of forward proxy with a local CA, it passes
  the Remote Control paths through with the client's own login, and it can send model calls to a
  third-party Anthropic-compatible backend. See its
  [proxy modes](https://github.com/KarpelesLab/teamclaude/blob/master/docs/proxy-modes.md).
- [claude-code-cache-fix](https://github.com/cnighswonger/claude-code-cache-fix/releases/tag/v4.3.0)
  added an opt-in forward-proxy mode in 4.3.0, described as "Remote Control through the proxy".
- [A mitmproxy recipe](https://gist.github.com/foxy82/10eae1bbf5683a680e9f20a45b6ea6c5) routes
  `/v1/messages` to a local compression proxy and passes everything else through, to keep Remote
  Control working.
- [How to get Remote Control back in Claude Code when you run through a proxy](https://apfelbaum.io/remote-control-claude-code/)
  describes the problem and the fix that went into teamclaude.

The two settings this relies on are documented by Anthropic for networks that inspect TLS:
[Enterprise network configuration](https://code.claude.com/docs/en/network-config) covers
`HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS`.

What Anthropic has not agreed to is the result. The
[Remote Control requirements](https://code.claude.com/docs/en/remote-control#requirements) list a
gateway as unsupported, a request to allow it behind a transparent proxy was
[closed as not planned](https://github.com/anthropics/claude-code/issues/72749), and a request for
a second provider beside the subscription is
[still open](https://github.com/anthropics/claude-code/issues/95744). That others do this is
precedent, not permission.

Where this project differs from the ones above: it does one thing, in one file with no
dependencies, and it refuses whatever it does not recognise.

## License

MIT. See [LICENSE](LICENSE).

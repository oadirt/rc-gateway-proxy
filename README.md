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
- **It reads your Claude sign-in token.** To tell model calls from everything else, it decrypts
  Claude Code's traffic to `api.anthropic.com` on your own machine, using a certificate authority
  it creates locally and that only Claude Code is told to trust. Read the code before you run it.
- **It is new and lightly tested**: macOS only, one Claude Code version, days of use. See
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

You need macOS, Node.js 20 or later, `openssl`, Claude Code signed in to a paid Claude plan
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
2. A login service, `local.gwproxy`, is registered. It runs the proxy on `127.0.0.1:3457`, starts
   at each login and is restarted if it stops. Its log is `~/Library/Logs/gwproxy.log`.
3. The two settings lines are added to `~/.claude/settings.json`, with a backup beside it.

After that a plain `claude`, `claude --remote-control` or `claude remote-control`, in any folder,
uses the gateway for model calls. There is no wrapper command and nothing to run per folder. Every
Claude Code session of that user goes through the proxy, including ones already running.

If the proxy is down, model calls fail; they do not fall back to your Claude plan.

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

`uninstall` removes the settings lines and the service. It leaves `~/.config/gwproxy/` in place.

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

On macOS with Claude Code 2.1.325, in November 2026:

- Each rule in the table above, through `curl`, including gzip bodies and streaming.
- `claude -p` with a tool call; `claude remote-control` with prompts sent to its session; a session
  started from the new-session page at claude.ai/code that ran in the server's folder. Model calls
  were matched one for one against the gateway's own records.
- With the proxy stopped, `claude -p` gave no answer and nothing reached the gateway or ran
  elsewhere in the 30 seconds it was watched.
- `install` and `uninstall` on an empty home folder, and the plugin loaded for one session.

Not tested: a real WebSocket session (only the handshake relay), the phone app, attachments,
approval prompts, sessions lasting hours, installing the plugin from a marketplace, how Claude Code
displays the session-start check's message, and anything on Linux or Windows.

One independent read-only review was done; its main finding (unknown requests used to go to
Anthropic) led to the refuse-by-default rule above. The changes made after it have not been
reviewed. Not taken from it: a proxy password, a header allowlist for the gateway, forwarding
trailers, and replacing the three certificate files as one step.

## License

MIT. See [LICENSE](LICENSE).

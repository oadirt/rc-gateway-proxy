---
description: Install or update the gateway proxy on this machine
argument-hint: "[path to your gateway .env file]"
allowed-tools: Bash(node:*)
disable-model-invocation: true
---

Install the gateway proxy by running one command, then show the user its output as it is.

The user's argument, if any, is the path of their gateway `.env` file: `$ARGUMENTS`

- With a path: `node "${CLAUDE_PLUGIN_ROOT}/gwproxy.mjs" install --gateway-env "<that path>"`
- With no path: `node "${CLAUDE_PLUGIN_ROOT}/gwproxy.mjs" install`

Rules:

- Do not open, read or print the `.env` file. It holds a key. Pass only its path.
- Run nothing else. If the command fails, show its message and stop; do not try to repair
  anything yourself.
- If the output says the proxy was restarted, tell the user that other running Claude Code
  sessions were interrupted for a few seconds and carry on by themselves.

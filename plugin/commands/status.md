---
description: Show whether the gateway proxy is running and where requests went
allowed-tools: Bash(node:*)
disable-model-invocation: true
---

Run `node "${CLAUDE_PLUGIN_ROOT}/gwproxy.mjs" status` and show the user its output as it is.

If it lists paths as "unlisted", say that Claude Code asked for something the proxy does not pass
on, and that this is only a problem if a feature the user needs stopped working. Do not change any
configuration yourself.

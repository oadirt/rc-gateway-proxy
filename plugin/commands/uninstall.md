---
description: Stop using the gateway proxy on this machine
allowed-tools: Bash(node:*)
disable-model-invocation: true
---

Ask the user to confirm first: after this, Claude Code on this machine runs on their own Claude
plan again, not on the gateway.

If they confirm, run `node "${CLAUDE_PLUGIN_ROOT}/gwproxy.mjs" uninstall` and show its output as it
is. Run nothing else.

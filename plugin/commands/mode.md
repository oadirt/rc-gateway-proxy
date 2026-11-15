---
description: Show whether model calls go to the gateway or to your own Claude plan
allowed-tools: Bash(node:*)
disable-model-invocation: true
---

<!-- Normally the plugin's UserPromptSubmit hook handles this command and it never reaches a model.
     This text is only used if that hook did not run. -->

Run `node "${CLAUDE_PLUGIN_ROOT}/gwproxy.mjs" mode` and show the user its output as it is.
Run nothing else.

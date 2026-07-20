# Contract snapshots

`defender-hunt-mcp.v1.json` is the versioned adapter-facing snapshot of MCP tool and resource contracts. It contains names, descriptions, input/output JSON schemas, and behavioral annotations.

Regenerate it after intentional contract changes:

```bash
uv run python export_contracts.py
```

Contract tests must review snapshot changes. Breaking changes require a new major schema filename/version and a documented migration window.

This directory intentionally excludes KQL implementation text, Microsoft Graph endpoint details, Redis internals, credentials, rate-limit thresholds, Security Copilot workspace/SCU configuration, and plugin manifests. A future Security Copilot adapter belongs in a separate repository and consumes these contracts.

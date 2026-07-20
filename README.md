# Defender Hunt MCP

A Model Context Protocol (MCP) server for **Microsoft Defender Advanced Hunting** and **Microsoft Entra ID** identity investigation. It exposes 31 read-oriented security operations tools and seven resources over stateless Streamable HTTP for MCP-compatible clients.

> [!IMPORTANT]
> This project is currently intended for analyst-assisted investigation in a controlled environment. Review [Security](docs/security.md) and [known functional limitations](docs/security.md#known-functional-limitations) before production deployment or use as an unattended detection control.

## Capabilities

| Area | Description |
|---|---|
| **KQL Hunting** | Execute Advanced Hunting KQL and perform a basic known-table reference check. |
| **Alert Management** | List, filter, and inspect Microsoft Defender security alerts with severity/status filtering and statistical summaries. |
| **Threat Intelligence** | Query Defender Threat Intelligence profiles, enrich Indicators of Compromise (IoCs), and hunt for IoCs in Defender telemetry. |
| **Identity Investigation** | Query Entra ID sign-in logs, audit logs, risky users, risky sign-ins, Conditional Access policies, and build comprehensive user risk profiles. |
| **Security Posture** | Generate environment summaries, device lookups, Secure Score records, and user logon investigations. |
| **Advanced Threat Hunting** | Pre-built detection modules covering ransomware indicators, suspicious PowerShell, LOLBIN abuse, lateral movement, credential access/dumping, persistence mechanisms, suspicious child processes, remote access tools/RATs, defense evasion, threat intel feed matching, data exfiltration, and ASR rule events. |

## Tools (31)

### Core Hunting
| Tool | Description |
|---|---|
| `run_hunting_query` | Execute a KQL query against Microsoft Defender Advanced Hunting (up to 10,000 rows / 30 days). |
| `validate_kql_query` | Check locally whether a query references a known hunting table; this is not syntax validation. |

### Alerts
| Tool | Description |
|---|---|
| `get_security_alerts` | Retrieve security alerts with optional severity and status filters. |
| `get_alert_details` | Get full details for a specific alert by ID. |
| `get_alert_statistics` | Statistical summary of alerts over a configurable time range. |

### Threat Intelligence
| Tool | Description |
|---|---|
| `get_threat_indicators` | List Defender Threat Intelligence profiles; profile indicator traversal is not yet implemented. |
| `enrich_ioc` | Enrich an IoC (IP, domain, URL, hash) with Defender telemetry. |
| `hunt_by_ioc` | Hunt for an IoC across all relevant Defender tables. |

### Security Posture
| Tool | Description |
|---|---|
| `get_security_recommendations` | Retrieve Microsoft Secure Score records (historical tenant/control scores). |
| `get_device_info` | Get detailed information about a device by name or ID. |
| `investigate_user_logon` | Comprehensive user logon activity investigation from `IdentityLogonEvents`. |
| `get_environment_dashboard` | Full security dashboard: alerts, auth, devices, and network overview. |
| `analyze_security_posture` | Analyse security posture with insights on identity, devices, network, and applications. |

### Microsoft Entra ID
| Tool | Description |
|---|---|
| `get_signin_logs` | Retrieve Entra ID sign-in logs with UPN, app, status, and risk filters. |
| `get_audit_logs` | Retrieve Entra ID audit/directory logs filtered by category, activity, or target. |
| `get_risky_users` | List users flagged by Entra ID Identity Protection. |
| `get_risky_signins` | Retrieve risky sign-in events from Identity Protection. |
| `get_conditional_access_policies` | List and inspect Conditional Access policies. |
| `analyze_user_risk_profile` | Comprehensive risk profile combining sign-in, risk, and audit data for a user. |

### Advanced Threat Hunting
| Tool | Description |
|---|---|
| `hunt_ransomware_indicators` | Detect ransomware file extensions, ransom notes, shadow copy deletion, double extensions. |
| `hunt_suspicious_powershell` | Detect encoded commands, web requests, Defender tampering, AMSI detections. |
| `hunt_lolbin_activity` | Detect LOLBIN abuse: certutil, mshta, regsvr32, rundll32, wmic, bitsadmin. |
| `hunt_lateral_movement` | Detect lateral movement: PsExec, SMB, WMI, RDP, DCOM. |
| `hunt_credential_access` | Detect credential dumping: LSASS, NTDS.dit, SAM, mimikatz, DCSync. |
| `hunt_persistence_mechanisms` | Detect persistence: registry run keys, scheduled tasks, services, startup folder, WMI subscriptions. |
| `hunt_suspicious_child_processes` | Detect suspicious child processes spawned by browsers, Office, explorer, Outlook. |
| `hunt_remote_access_tools` | Detect RATs, commercial RMM tools, and tunnelling utilities. |
| `hunt_defense_evasion` | Detect evasion: security tool tampering, log clearing, timestomping, process injection. |
| `hunt_threat_intel_feeds` | Match activity against public threat intel feeds (malicious domains, IPs, hashes). |
| `hunt_data_exfiltration` | Hunt for transfer, cloud storage, DNS tunnelling, and archive patterns; see documented schema limitations. |
| `get_asr_events` | Retrieve Attack Surface Reduction (ASR) rule events (blocked/audited). |

## Resources

| URI | Description |
|---|---|
| `defender://hunting/examples` | Example KQL queries for Advanced Hunting. |
| `defender://hunting/tables` | Reference of available Advanced Hunting tables. |
| `defender://hunting/ioc-queries` | IoC-based threat hunting query guide. |
| `defender://soc/playbooks` | SOC incident response playbooks and workflows. |
| `entra://identity/signin-investigation` | Sign-in investigation guide. |
| `entra://identity/risk-investigation` | Risky user/sign-in investigation guide. |
| `entra://identity/conditional-access` | Conditional Access policy reference. |

The complete behavioral reference, inputs, caveats, and result semantics are documented in [MCP tools and resources](docs/tools.md).

## Documentation

| Guide | Contents |
|---|---|
| [Configuration](docs/configuration.md) | Environment variables, Graph permissions, authentication boundaries, and health semantics. |
| [Development](docs/development.md) | `uv` workflow, quality checks, project layout, MCP smoke test, and KQL development rules. |
| [Deployment](docs/deployment.md) | Docker Compose, direct Docker, Azure Container Apps scripts, verification, and production hardening. |
| [Security](docs/security.md) | Trust model, secrets, query/input risks, third-party feeds, and known limitations. |
| [Tools and resources](docs/tools.md) | Current 31-tool and seven-resource reference derived from the live registry. |
| [Contributing](CONTRIBUTING.md) | Development workflow, required checks, and pull request guidance. |
| [Security policy](SECURITY.md) | Private vulnerability reporting and supported-version policy. |

## Architecture

```
┌──────────────────────┐        ┌──────────────────────────┐
│   MCP Client         │  HTTP  │  server_http.py          │
│  (Copilot, etc.)     │◄──────►│  Starlette + Uvicorn     │
│                      │        │  • API-key auth          │
└──────────────────────┘        │  • CORS                  │
                                │  • /health, /info        │
                                │  • /mcp (streamable-http)│
                                └─────────┬────────────────┘
                                          │
                                ┌─────────▼────────────────┐
                                │  server.py               │
                                │  FastMCP server          │
                                │  31 tools · 7 resources  │
                                └─────────┬────────────────┘
                                          │
                                ┌─────────▼────────────────┐
                                │  Microsoft Graph API     │
                                │ (Entra app credentials) │
                                └──────────────────────────┘
```

## Configuration

| Variable | Required | Description |
|---|---|---|
| `AZURE_TENANT_ID` | Yes | Microsoft Entra tenant ID. |
| `AZURE_CLIENT_ID` | Yes | App registration client ID. |
| `AZURE_CLIENT_SECRET` | Yes | App registration client secret. |
| `MCP_API_KEY` | Production: Yes | Shared key for MCP clients. If empty, `/mcp` is unauthenticated. |
| `LOG_LEVEL` | No | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Defaults to `INFO`. |
| `PORT` | No | HTTP listen port inside the container. Defaults to `8000`. |
| `HOST` | No | HTTP bind address. Defaults to `0.0.0.0`. |
| `DEBUG` | No | Starlette debug mode. Defaults to `false`; never enable in production. |
| `ALLOWED_ORIGINS` | No | Comma-separated browser origins allowed by CORS. CORS is disabled when empty. |

See [Configuration](docs/configuration.md) for `MCP_PORT`, authentication boundaries, health behavior, and secret handling.

## Required Microsoft Graph Permissions (Application)

- `SecurityEvents.Read.All` — Security alerts
- `ThreatHunting.Read.All` — Advanced Hunting queries
- `ThreatIntelligence.Read.All` — Defender Threat Intelligence profiles/indicators (license/add-on also required)
- `AuditLog.Read.All` — Sign-in and audit logs
- `IdentityRiskyUser.Read.All` — Risky users
- `Policy.Read.All` — Conditional Access policies

Grant application permissions with tenant-wide admin consent and apply least privilege. `SecurityEvents.Read.All` also covers the Secure Score endpoint currently used by `get_security_recommendations`.

## Quick start

Prerequisites: Python 3.12 and `uv`. Docker is optional for local Python execution.

```bash
# Create the environment and install exactly the locked dependencies
uv sync --frozen

# Configure Microsoft Graph credentials and a strong MCP API key
cp .env.example .env

# Run the server
uv run server_http.py
```

Dependency versions are declared in `pyproject.toml` and reproducibly pinned in `uv.lock`.
Use `uv add <package>` for runtime dependencies and `uv add --dev <package>` for development tools.

### Development checks

```bash
# Verify that the lockfile matches pyproject.toml
uv lock --check

# Lint and compile the Python sources
uv run ruff check config.py server.py server_http.py
uv run python -m py_compile config.py server.py server_http.py

# Run the test suite (currently no committed tests)
uv run pytest
```

The server listens on `http://0.0.0.0:8000` by default. The MCP endpoint is `/mcp`; `/health` and `/info` are public utility endpoints.

## Running in a container

Create the runtime environment file and replace every placeholder:

```bash
cp .env.example .env
```

Build and start with Docker Compose:

```bash
docker compose up --build -d
docker compose ps
curl --fail http://localhost:8000/health
```

Or use Docker directly:

```bash
docker build -t defender-hunt-mcp:local .
docker run --rm --name defender-hunt-mcp \
    --env-file .env \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -p 8000:8000 \
    defender-hunt-mcp:local
```

The health endpoint returns HTTP `503` until all required Graph credential variables are present. It does not test Graph connectivity, consent, or licensing. Do not bake `.env` or secrets into the image; `.dockerignore` excludes the local environment file from the build context.

To stop the Compose deployment:

```bash
docker compose down
```

## Transport

The FastMCP server uses **stateless Streamable HTTP**, allowing horizontal scaling without session affinity. Authentication is via `X-API-Key` or `Authorization: Bearer <key>` when `MCP_API_KEY` is configured.

Example initialize request:

```bash
curl --fail --silent \
    -X POST http://localhost:8000/mcp \
    -H 'X-API-Key: replace-with-your-key' \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke-test","version":"1.0"}}}'
```

## Deployment

The repository includes a hardened local container configuration and two Azure Container Apps deployment scripts:

- `deploy-full.ps1` provisions infrastructure and deploys the service.
- `deploy.ps1` updates an existing registry and Container App.

The current Azure scripts use ACR administrative credentials and plain Container App environment values for application secrets. Follow the production-hardening checklist in [Deployment](docs/deployment.md#current-azure-script-security-model) before production use.

## License

Defender Hunt MCP is available under the [MIT License](LICENSE).

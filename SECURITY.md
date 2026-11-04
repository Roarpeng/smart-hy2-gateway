# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| < 1.1 | Best-effort (please upgrade) |

## Threat model

Smart Hy2 Gateway runs as a **privileged host-network container** and can rewrite iptables / ip rules. It is intended for a **trusted workstation**, not as a public internet service.

- Node passwords are stored in plaintext under `/data/gateway_state.json` (mode `600`).
- The Web UI static assets are unauthenticated; **all `/api/*` routes require a Bearer token** (except `/api/health`).
- Default listen address is `127.0.0.1`. Set `ALLOW_LAN=1` only on trusted LANs.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository, or email the maintainer listed in the README. Include:

1. Affected version / commit
2. Reproduction steps
3. Impact assessment

Do not file public issues for unpatched remote code execution or credential disclosure.

## Hardening checklist

1. Keep `ALLOW_LAN=0` unless required
2. Rotate `GATEWAY_TOKEN` / `/data/api_token` after shared-console use
3. Never commit `data/gateway_state.json` or `data/api_token`
4. Prefer TLS-valid nodes (`insecure: false`)
5. `proxy-switch.sh off` restores direct connectivity if rules misbehave

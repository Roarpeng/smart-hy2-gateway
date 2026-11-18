# Changelog

## 1.1.1 — 2026-11-18

### Security & Hardening
- Prevent redacted `"***"` placeholder from overwriting stored node credentials in `/api/apply` and `PATCH /api/nodes/{id}`
- Harden subscription URL SSRF check against DNS rebinding and non-global IPv4/IPv6 targets
- Require authentication on temporary `diag-in` SOCKS diagnostic inbound and drop container `privileged: true` in favor of minimal `cap_add` (`NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`, `SETUID`, `SETGID`, `CHOWN`)

### Added
- `POST /api/reload` for zero-payload sing-box config verification and reload (used by `ruleset-update.sh` with Bearer token)
- `PATCH /api/settings` for updating dual-channel / whitelist settings without re-submitting redacted node credentials
- Full backend unit test suite (`tests/test_backend_app.py`) and shell syntax checks in CI

### Fixed
- Preserve protocol-specific fields (e.g. Shadowsocks `method`) when editing non-Hysteria2 nodes in WebUI and backend
- Bypass `100.64.0.0/10` (CGNAT / Tailscale) and `--dst-type LOCAL` in `HY2_PRE` / `HY2_OUT` to prevent local return packet self-hijacking
- Manage forward and NAT rules via dedicated atomic chains (`HY2_FWD` / `HY2_NAT`) in `proxy-switch.sh`

## 1.1.0 — 2026-11-04

### Security
- API Bearer token auth (`GATEWAY_TOKEN` or `/data/api_token`); `/api/health` remains public
- Default bind `127.0.0.1`; set `ALLOW_LAN=1` for LAN access
- Node passwords redacted in `/api/state` and `/api/nodes` responses by default

### Added
- Channel roles: any iface as Direct / Managed (not hard-wired RJ45/Wi-Fi)
- Virtual NIC enrichment and VMware bridge hints in `/api/interfaces`
- Multi-protocol outbounds: Hysteria 2, VLESS (Reality), Trojan, Shadowsocks
- GitHub Actions CI, SECURITY.md, pinned Python dependencies

### Changed
- Product docs no longer claim RJ45-always-direct / Wi-Fi-always-proxy

## 1.0.0

- Initial dual-channel Hysteria 2 TProxy gateway with Web console

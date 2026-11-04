# Changelog

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

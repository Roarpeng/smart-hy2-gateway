# Contributing

Thanks for helping improve Smart Hy2 Gateway.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest tests/ -q
```

Host-side scripts (`scripts/proxy-switch.sh`, NetworkManager dispatcher) need Ubuntu + root to exercise end-to-end.

## Pull requests

1. Keep changes focused; prefer small PRs
2. Add/adjust tests for `node_parser` and any new pure helpers
3. Do not commit `data/gateway_state.json`, `data/api_token`, or node passwords
4. Update CHANGELOG.md for user-visible changes

## Scope notes

- Dataplane is **sing-box**, not Clash Meta / mihomo
- Full Clash YAML compatibility is out of scope; share-link + sing-box JSON imports are preferred
- Dual-channel Direct/Managed roles are intentional; do not re-hardcode RJ45/Wi-Fi semantics

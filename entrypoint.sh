#!/bin/bash
# ===================================================================
# hy2-gateway 容器入口: 准备数据目录后启动 FastAPI 控制器
# (sing-box 由 backend_app.py 以 UID 999 spawn 并守护, 不在此启动)
# ===================================================================
set -euo pipefail

mkdir -p /data

exec python /app/backend_app.py

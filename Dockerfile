# ===================================================================
# Smart Hysteria 2 Gateway 镜像
# 阶段 1: 拉取官方 sing-box 稳定版二进制 (1.11.x, 支持 Hysteria2 端口跳跃,
#          同时保留 legacy DNS schema; 1.12 起 legacy DNS 弃用, 1.14 移除)
# 阶段 2: python:3.11-alpine 运行时 (FastAPI WebUI + TProxy 工具链)
# ===================================================================
ARG SINGBOX_VERSION=1.11.15

FROM golang:alpine AS sb-fetcher
ARG SINGBOX_VERSION
# sing-box 官方 release: ghfast 镜像优先 (国内网络), GitHub 直连为辅; 均带硬超时防爬行卡死
RUN apk add --no-cache curl tar \
    && { curl -fsSL --connect-timeout 8 -m 240 -o /tmp/sb.tar.gz \
         "https://ghfast.top/https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz" \
         || curl -fsSL --connect-timeout 8 -m 240 -o /tmp/sb.tar.gz \
            "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"; } \
    && tar -xzf /tmp/sb.tar.gz -C /tmp \
    && mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box" /usr/local/bin/sing-box \
    && chmod 755 /usr/local/bin/sing-box \
    && /usr/local/bin/sing-box version

FROM python:3.11-alpine
ARG SINGBOX_VERSION
LABEL org.opencontainers.image.title="hy2-gateway" \
      org.opencontainers.image.description="Smart Hysteria 2 TProxy Gateway (sing-box ${SINGBOX_VERSION} + FastAPI WebUI)"

# iptables/iproute2: TProxy 规则与策略路由; jq: 配置自检; libcap: setcap
RUN apk add --no-cache iptables iproute2 bash curl jq ca-certificates libcap

# sing-box 专用运行账户 UID/GID=930 (999 已被 alpine 自带 ping 组占用):
# iptables -m owner --uid-owner 930 可据此放行 sing-box 自身出站, 防回环劫持
RUN addgroup -g 930 singbox \
    && adduser -D -H -h /nonexistent -s /sbin/nologin -u 930 -G singbox singbox

COPY --from=sb-fetcher /usr/local/bin/sing-box /usr/local/bin/sing-box
# 地理分流规则集 (中国域名/IP 直连), 随仓库内置, 构建零外联
COPY ruleset/ /usr/local/share/sing-box/
# 文件级能力: 允许非 root 的 sing-box 进程执行 TPROXY 并绑定特权端口
# 注: 构建沙箱的能力边界集不含 NET_ADMIN, setcap 后不能直接执行该二进制验证,
#     用 getcap 校验能力位即可; 运行期容器已 cap_add NET_ADMIN, 可正常执行
RUN setcap cap_net_admin,cap_net_bind_service+ep /usr/local/bin/sing-box \
    && getcap /usr/local/bin/sing-box

WORKDIR /app

# 先装依赖再拷代码, 利用层缓存
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend_app.py /app/backend_app.py
COPY node_parser.py /app/node_parser.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh

# TProxy 切换脚本: 容器内 API 调用与宿主 dispatcher 共用同一逻辑
COPY scripts/proxy-switch.sh /usr/local/bin/proxy-switch.sh
RUN chmod 755 /usr/local/bin/proxy-switch.sh

# WebUI 静态控制台
COPY web /app/web

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/app/entrypoint.sh"]

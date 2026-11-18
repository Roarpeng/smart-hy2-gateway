# ===================================================================
# Smart Hysteria 2 Gateway 镜像 (python:3.11-alpine 运行时: FastAPI WebUI + TProxy 工具链)
# sing-box 1.11.x 稳定版 (支持 Hysteria2 端口跳跃, 保留 legacy DNS schema;
# 1.12 起 legacy DNS 弃用, 1.14 移除): 优先使用本地 vendor/sing-box 缓存,
# 无本地缓存时 (如 GitHub Actions CI) 自动按 TARGETARCH 从官方 Release 拉取。
# ===================================================================
ARG SINGBOX_VERSION=1.11.15
FROM python:3.11-alpine
ARG SINGBOX_VERSION=1.11.15
ARG TARGETARCH
ARG APK_MIRROR=""
ARG PIP_INDEX_URL=""
LABEL org.opencontainers.image.title="hy2-gateway" \
      org.opencontainers.image.description="Smart Hysteria 2 TProxy Gateway (sing-box ${SINGBOX_VERSION} + FastAPI WebUI)"

# iptables/iproute2: TProxy 规则与策略路由; jq: 配置自检; libcap: setcap;
# ipset: 内核层中国 IP 直连集 (容器 cap_add: NET_ADMIN 直写宿主内核, 宿主机无需安装)
RUN if [ -n "${APK_MIRROR}" ]; then \
        sed -i "s/dl-cdn.alpinelinux.org/${APK_MIRROR}/g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache iptables iproute2 bash curl jq ca-certificates libcap ipset tar

# sing-box 专用运行账户 UID/GID=930 (999 已被 alpine 自带 ping 组占用):
# iptables -m owner --uid-owner 930 可据此放行 sing-box 自身出站, 防回环劫持
RUN addgroup -g 930 singbox \
    && adduser -D -H -h /nonexistent -s /sbin/nologin -u 930 -G singbox singbox

# 优先使用本地 vendor/sing-box 离线缓存; 缺失时回退官方 GitHub Release 下载
# 文件级能力: 允许非 root 的 sing-box 进程执行 TPROXY 并绑定特权端口
COPY vendor/ /tmp/vendor/
RUN if [ -s /tmp/vendor/sing-box ]; then \
        cp /tmp/vendor/sing-box /usr/local/bin/sing-box; \
    else \
        ARCH="${TARGETARCH:-amd64}" \
        && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz" \
           | tar -xz -C /tmp \
        && mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${ARCH}/sing-box" /usr/local/bin/sing-box \
        && rm -rf "/tmp/sing-box-${SINGBOX_VERSION}-linux-${ARCH}"; \
    fi \
    && chmod 755 /usr/local/bin/sing-box \
    && rm -rf /tmp/vendor \
    && setcap cap_net_admin,cap_net_bind_service+ep /usr/local/bin/sing-box \
    && getcap /usr/local/bin/sing-box

# 地理分流规则集 (中国域名/IP 直连), 随仓库内置, 构建零外联
COPY ruleset/ /usr/local/share/sing-box/

WORKDIR /app

# 先装依赖再拷代码, 利用层缓存; 支持可选 PIP_INDEX_URL 加速
COPY requirements.txt /app/requirements.txt
RUN if [ -n "$PIP_INDEX_URL" ]; then \
        pip install --no-cache-dir -i "$PIP_INDEX_URL" -r /app/requirements.txt; \
    else \
        pip install --no-cache-dir -r /app/requirements.txt; \
    fi

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

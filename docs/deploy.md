# 部署运维手册（deploy.md）

本文面向运维人员，覆盖 Smart Hysteria 2 Gateway 在 Ubuntu 宿主机上的完整部署、验证、测试、排障与卸载流程。VMware 虚拟网络配置不在本文范围，见 [vmware-setup.md](vmware-setup.md)。

## 目录

1. [前置条件](#1-前置条件)
2. [部署步骤](#2-部署步骤)
3. [首次配置](#3-首次配置)
4. [验证清单](#4-验证清单)
5. [Wi-Fi 切换自动分流测试](#5-wi-fi-切换自动分流测试)
6. [故障排查表](#6-故障排查表)
7. [卸载](#7-卸载)

---

## 1. 前置条件

| 项目 | 要求 |
|------|------|
| 操作系统 | Ubuntu 22.04 / 24.04（宿主机，双网卡 enp3s0 + wlp2s0） |
| 容器环境 | Docker Engine + docker compose 插件 |
| 虚拟化 | VMware Workstation 17 |
| 系统工具 | `jq`、`ipset`、NetworkManager（`nmcli`） |

> **仅接管 IPv4**：TProxy 规则集只覆盖 iptables（IPv4），IPv6 流量不进隧道。双栈 Wi-Fi 环境下如需避免 IPv6 出口，建议对 Wi-Fi 连接禁用 IPv6：`nmcli connection modify "<连接名>" ipv6.method disabled`。

检查命令（全部可执行即满足）：

```bash
cat /etc/os-release | grep -E '22.04|24.04'
docker version && docker compose version
vmware --version
jq --version && ipset version && nmcli --version
```

## 2. 部署步骤

### 2.1 目录放置

仓库根目录即部署目录，必须位于 `/opt/hy2-gateway`（dispatcher 钩子与状态文件路径均已按此写死）：

```bash
git clone <仓库地址> /opt/hy2-gateway
# 或： sudo cp -r ./NetWork /opt/hy2-gateway

cd /opt/hy2-gateway
```

### 2.2 install.sh 做了什么

```bash
sudo ./install.sh
```

安装脚本完成五件事，全部幂等，可重复执行：

1. 安装 TProxy 开关脚本：`scripts/proxy-switch.sh` → `/usr/local/bin/proxy-switch.sh`（可执行）。
2. 安装 NetworkManager 钩子：`scripts/99-wifi-proxy.sh` → `/etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh`（可执行）。
3. 生成种子状态文件：`/opt/hy2-gateway/data/gateway_state.json`（不存在时写入初始骨架，含白名单、`wifi_policy: whitelist` 与节点占位），权限设为 600。
4. 安装规则集自动更新：`scripts/ruleset-update.sh` → `/usr/local/bin/ruleset-update.sh`，`scripts/systemd/` 下的 `hy2-ruleset-update.service` / `hy2-ruleset-update.timer` 一并安装并 `systemctl enable --now`（详见第 4 节「规则集每周自动更新」）。
5. 依赖检查与首跑：确认 `curl` / `jq` / `ipset` 可用；安装尾声 best-effort 立即执行一次规则集更新（失败仅告警，不影响安装结果）。

### 2.3 构建并启动容器

```bash
docker compose up -d --build
```

容器要点：

- 容器名 `hy2-gateway`，`network_mode: host` + `privileged` + `NET_ADMIN`，直接操作宿主网络栈。
- sing-box 1.11.x 以 TProxy `:12345` 接收透明代理流量，Hysteria 2 (QUIC) 出站；以 UID 930 + `setcap cap_net_admin` 运行。
- FastAPI WebUI 监听 `:8080`，托管 `web/index.html`，提供 `/api/state`、`/api/apply`、`/api/status`、`/api/proxy`、`/api/interfaces`（宿主网卡枚举，供下拉选择）、`/api/nettest`（宿主机视角分段连通性诊断），以及节点管理接口 `/api/nodes`、`/api/nodes/import`、`/api/nodes/{id}/activate`、`PATCH/DELETE /api/nodes/{id}`、`/api/nodes/test`。
- 挂载 `./data:/data`（状态与 sing-box 配置）。Wi-Fi 事件感知在宿主 dispatcher 侧完成，容器不挂载 dbus。

确认容器运行：

```bash
docker ps --filter name=hy2-gateway
docker logs hy2-gateway
```

## 3. 首次配置

1. 浏览器打开 `http://宿主IP:8080`。
2. **节点管理页（v2rayN 式）导入节点**，任选一种或组合使用：
   - 批量粘贴 `hy2://` / `hysteria2://` 分享链接，每行一条；空行与行首 `#` 注释行会被忽略；
   - 粘贴整段 base64 订阅内容（标准 / URL-safe / 无 padding 均可自动识别）；
   - 填写订阅 URL（仅 `http/https`，由后端拉取；私网、回环、链路本地地址会被拒绝，见「安全须知」）；
   - 粘贴 sing-box JSON（完整配置、单个 outbound 或 outbound 数组）。

   导入后在节点列表确认：
   - 多节点并列展示，输入内重复节点自动去重，标签冲突自动加后缀；
   - 点「启用」切换当前活跃节点；
   - 点节点行的「测试」或首屏「测试延迟」，发起真实 Hysteria 2 连通性测试（不是 ICMP ping）；
   - 可编辑、重命名、删除节点；编辑活跃节点后点「保存修改」会重新校验并重启 sing-box，非活跃节点可直接「保存并启用」。

   > Clash YAML 暂不支持，请先转换为分享链接或 sing-box JSON 再导入。
3. 「双通道」页 → 可信 Wi-Fi：添加可信 Wi-Fi 的 SSID（例如家庭、公司办公网）。
4. 「双通道」页 → 通道 B：选择无线通道策略（默认「走代理·白名单例外」，即 `wifi_policy=whitelist`；可切换「强制代理」`always_proxy` / 「强制直连」`always_direct`）。页面按双通道分组呈现：通道A（RJ45 有线）恒直连，通道B（Wi-Fi 无线）受 `wifi_policy` 控制。
5. 点「保存网卡配置」，或启用/保存节点。后端会：
   - 将启用节点、节点列表与其余配置写入 `/opt/hy2-gateway/data/gateway_state.json`；
   - 生成 sing-box 配置；
   - 执行 `sing-box check`，**校验通过后才重启 sing-box**；失败则返回错误信息且不重启、不改写状态文件，旧配置继续生效。
6. 后端离线（容器未启动）时，控制台自动进入演示模式：可查看与预填配置，但写操作不下发；后端恢复后控制台自动回到在线模式。
7. 控制台「当前 Wi-Fi」在线时可能显示「未感知」——SSID 感知在宿主 dispatcher 侧，容器内无 nmcli。真实 SSID 与切换记录以 `journalctl -t HY2_DISPATCH -t HY2_PROXY` 为准。

双通道策略/网卡变更后，TProxy 决策会在下一次 Wi-Fi 事件时自动生效；节点启用/保存会立即校验并重启 sing-box。需要立即切换可手动执行：

```bash
sudo /usr/local/bin/proxy-switch.sh on    # 开启 TProxy 透明代理
sudo /usr/local/bin/proxy-switch.sh off   # 清除规则，恢复直连
```

## 4. 验证清单

以下命令均在宿主机执行。假设 Wi-Fi 已连接一个**非白名单** SSID，且无线通道策略为默认 `whitelist`（此时代理应为 on 状态）。

**策略路由**——应看到 `fwmark 0x1 lookup 100`：

```bash
ip rule
```

**路由表 100**——应看到 `local default dev lo`：

```bash
ip route show table 100
```

**mangle 链 HY2_PRE**——应有私网 RETURN 规则、`-m set --match-set hy2_cn dst -j RETURN`（第 2 条，中国 IP 内核层直连、免进 TProxy）和 TCP/UDP TPROXY `:12345` 规则：

```bash
iptables -t mangle -S HY2_PRE
```

**mangle 链 HY2_OUT**——首规则应为 `-m owner --uid-owner 930 -j RETURN`（放行 sing-box 自身流量防回环），其后为私网 RETURN、`hy2_cn` 匹配 RETURN（第 3 条）与 MARK 规则：

```bash
iptables -t mangle -L HY2_OUT | head
```

**内核参数**——均应为 1：

```bash
sysctl net.ipv4.ip_forward net.ipv4.ip_nonlocal_bind
```

**分流日志**——应看到 dispatcher 判定与 proxy-switch 动作记录：

```bash
journalctl -t HY2_DISPATCH -t HY2_PROXY --since -10min
```

**容器日志**——sing-box 与 FastAPI 启动、配置重载记录：

```bash
docker logs hy2-gateway
```

**WebUI 后端健康**——应返回 JSON 状态：

```bash
curl http://127.0.0.1:8080/api/status
```

**网卡枚举与连通性诊断**——interfaces 返回宿主全部网卡（控制台下拉数据源），nettest 做 DNS/直连/节点分段探测：

```bash
curl http://127.0.0.1:8080/api/interfaces
curl -X POST http://127.0.0.1:8080/api/nettest -H 'Content-Type: application/json' -d '{"target":"www.google.com"}'
```

**节点管理 API**——应返回节点列表、启用状态与标签：

```bash
curl -s http://127.0.0.1:8080/api/nodes | jq
```

**批量导入与去重**——在控制台节点管理页依次验证：

- 粘贴多行分享链接 / 整段 base64 / 订阅 URL，列表节点数应正确增加；
- 再次导入同一批内容，节点总数不变（输入内去重）；
- 标签冲突自动加后缀，`direct`、`proxy-dns`、`tproxy-in` 等保留 tag 不被节点占用。

**活跃节点切换与延迟测试**：

```bash
# {id} 替换为 /api/nodes 返回的节点 id
curl -X POST http://127.0.0.1:8080/api/nodes/{id}/activate
curl -X POST http://127.0.0.1:8080/api/nodes/test | jq
```

预期：目标节点在 `/api/nodes` 中变为启用状态；延迟测试对节点发起真实 Hysteria 2 握手，不可达节点返回失败/超时，不依赖 ICMP。

**坏节点不下发（状态文件保护）**：

```bash
STATE=/opt/hy2-gateway/data/gateway_state.json
BEFORE=$(sha256sum "$STATE" | cut -d' ' -f1)

# 在控制台编辑活跃节点：改错密码，或把端口改成非法值，然后点「保存修改」或「保存并启用」
# 预期：/api/apply 返回 sing-box check 失败，旧配置继续生效

AFTER=$(sha256sum "$STATE" | cut -d' ' -f1)
[ "$BEFORE" = "$AFTER" ] && echo "state unchanged"
```

若哈希不变且容器未重启，说明坏节点未落盘、未下发，符合预期；修正节点后重新下发即可。

**虚拟机出口验证**——在虚拟机内执行；代理开启时因地理分流，国内与国外出口不同（国内直连、国外经节点）：

```bash
curl -s myip.ipip.net          # 国内服务: 应显示本地运营商出口 (直连)
curl -s https://api.ipify.org  # 国外服务: 应显示 Hysteria 2 节点 IP (隧道)
curl -s ifconfig.me && echo    # 同上对照
```

> 地理分流规则（geosite-cn / geoip-cn）随仓库 `ruleset/` 目录内置镜像，**首次启动零外联**；之后由 `hy2-ruleset-update.timer` 每周自动更新，无需手工替换，见下节。

### 规则集每周自动更新

地理分流的规则集（geosite-cn / geoip-cn）与内核直连 ipset `hy2_cn` 由 systemd 定时任务自动保鲜。为什么要定时更新：规则集镜像内置保证首次启动零外联，但 CN 域名/IP 列表随时间变化，需要每周刷新；且 `.srs` 投递 sing-box 与 CIDR 重建 ipset 来自**同一份 `geoip-cn.srs`**（单一数据源，内核层与用户态判定不会不一致）。

- **触发**：`hy2-ruleset-update.timer` 每周一 04:30（±10 分钟随机抖动，避免更新源扎堆；`Persistent=true`，宿主机关机错过后下次开机补跑）。
- **单次流程**：从 SagerNet 官方（[sing-geosite](https://gitlab.com/SagerNet/sing-geosite) / [sing-geoip](https://gitlab.com/SagerNet/sing-geoip) 的 rule-set 分支）下载 `geosite-cn.srs` / `geoip-cn.srs` → 尺寸校验 → 原子替换仓库 `ruleset/` → `docker cp` 投递容器 `/usr/local/share/sing-box/` → 用 `sing-box rule-set decompile` 从同一份 `geoip-cn.srs` 导出 CIDR、原子重建 ipset `hy2_cn`（swap 后既有 iptables 规则即时命中新数据，无需重载规则）→ 若代理在开则确保 `hy2_cn` match 规则在位 → 经后端 `/api/apply` 触发 sing-box 优雅重载。
- **fail-safe**：下载失败或尺寸校验不过则保留现有规则集、不动运行态；重载前先过 `sing-box check`，坏文件不会重启进程；`proxy-switch.sh` 绝不 create/destroy/flush `hy2_cn`，ipset 数据只由本更新脚本维护。

验证（宿主机执行）：

```bash
# 1. timer 已排程（NEXT 应指向下个周一 04:30 ±10 分钟）
systemctl list-timers hy2-ruleset-update.timer

# 2. 手动触发一次更新
sudo systemctl start hy2-ruleset-update.service

# 3. ipset 已载入（Name: hy2_cn，Header 为 hash:net，Members 非空）
ipset list hy2_cn | head

# 4. 更新日志（下载 / 校验 / 投递 / ipset 重建 / 重载各步骤）
journalctl -t HY2_RULESET -n 50
```

## 5. Wi-Fi 切换自动分流测试

目的：验证 dispatcher 能自动切换 on/off。以下主流程基于默认策略 `wifi_policy=whitelist`（白名单 SSID 直连、其余走代理）；`always_proxy` / `always_direct` 两种强制模式的验证见本节末尾「策略模式验证」。

```bash
# 1. 宿主机：实时观察分流日志
journalctl -f -t HY2_DISPATCH -t HY2_PROXY

# 2. 连接一个【白名单内】的 SSID
nmcli device wifi connect "Home-WiFi" password "<密码>"
# 期望日志（dispatcher 决策 + proxy-switch 动作）：
#   HY2_DISPATCH: 决策: proxy off (SSID 'Home-WiFi' 命中白名单, 走直连)
#   HY2_PROXY:    关闭代理, 恢复直连
# 此时 ip rule 不应有 fwmark 0x1 记录，虚拟机 curl 直连出网。

# 3. 切换到【非白名单】SSID
nmcli device wifi connect "CoffeeShop-Free" password "<密码>"
# 期望日志：
#   HY2_DISPATCH: 决策: proxy on (SSID 'CoffeeShop-Free' 不在白名单, 走 Hysteria 2 隧道)
#   HY2_PROXY:    代理已开启: 全量流量 (本机 + VMnet 192.168.100.0/24) -> TProxy :12345 (Hysteria 2)
# ip rule 重新出现 fwmark 0x1 lookup 100。

# 4. 关闭 Wi-Fi
nmcli radio wifi off
# 期望日志：
#   HY2_DISPATCH: 决策: proxy off (wlp2s0 down, 恢复直连)
#   （off 内部会补 MASQUERADE 直连通路）
nmcli radio wifi on   # 测试完恢复
```

每次切换后在虚拟机内用 `curl -s ifconfig.me` 对比出口 IP：直连态为本地运营商出口，代理态为节点出口。

### 策略模式验证（wifi_policy）

dispatcher 按顶层状态字段 `wifi_policy` 三态决策：`whitelist` 即上面主流程；`always_proxy` 在 Wi-Fi up / connectivity-change 时恒开代理、忽略白名单（Wi-Fi down 事件仍会关闭代理）；`always_direct` 恒关代理。切换方法：控制台「双通道」页修改通道 B 策略 →「保存网卡配置」→ 再切换一次 Wi-Fi 触发 dispatcher 重新决策。

```bash
# 宿主机：实时观察分流日志
journalctl -f -t HY2_DISPATCH -t HY2_PROXY

# 1. 「双通道」页切「强制代理」(always_proxy) 并保存后，连【白名单内】SSID —— 代理应仍为 on
nmcli device wifi connect "Home-WiFi" password "<密码>"
# 期望日志：HY2_DISPATCH: 决策: proxy on (SSID 'Home-WiFi' ...)（日志注明策略强制代理、白名单命中被忽略）
#   此时 ip rule 仍有 fwmark 0x1 lookup 100，虚拟机 curl -s ifconfig.me 出口为节点 IP

# 2. 「双通道」页切「强制直连」(always_direct) 并保存后，连【非白名单】SSID —— 代理应仍为 off
nmcli device wifi connect "CoffeeShop-Free" password "<密码>"
# 期望日志：HY2_DISPATCH: 决策: proxy off (SSID 'CoffeeShop-Free' ...)（日志注明策略强制直连、未命中白名单也不开代理）
#   此时 ip rule 无 fwmark 0x1 记录，虚拟机出口为本地运营商出口

# 3. 「双通道」页恢复「走代理·白名单例外」(whitelist) 并保存后，连另一【非白名单】SSID —— 回到主流程行为
nmcli device wifi connect "AnotherNet" password "<密码>"
# 期望日志：HY2_DISPATCH: 决策: proxy on (SSID 'AnotherNet' 不在白名单, 走 Hysteria 2 隧道)
```

## 6. 故障排查表

| 症状 | 原因 | 处置 |
|------|------|------|
| Wi-Fi 已连白名单，但 `ip rule` 仍有 fwmark 0x1，虚拟机流量仍走代理 | TProxy 规则残留（dispatcher 未触发或脚本执行中断）；若 `wifi_policy=always_proxy` 则属预期行为（见下一行） | 手动执行 `sudo /usr/local/bin/proxy-switch.sh off` 清除；再检查 `journalctl -t HY2_DISPATCH --since -10min` 是否有对应事件 |
| 切了白名单不生效 / 连白名单 SSID 仍走代理 | `wifi_policy` 处于 `always_proxy`（强制代理，忽略白名单） | 控制台「双通道」页切回「白名单例外」（whitelist）模式并点「保存网卡配置」；随后切换一次 Wi-Fi 触发 dispatcher 重新决策 |
| 国外站突然全打不开（如 YouTube 超时），国内正常 | TProxy 规则被第三方意外清除（容器重建/系统事件），流量全部直连被墙 | **rule-guard 会在 30 秒内自动恢复**，`docker logs hy2-gateway \| grep rule-guard` 可见恢复记录；若未恢复：手动 `sudo /usr/local/bin/proxy-switch.sh on`，并检查 `/opt/hy2-gateway/data/last_decision` 期望态文件 |
| 容器反复重启或起不来 | 镜像构建失败（sing-box 下载不通）或 privileged/权限不足 | `docker logs hy2-gateway` 查看具体报错；构建阶段下载 sing-box 失败时重跑 `docker compose up -d --build`，或修改 compose 的 `build.args.SINGBOX_VERSION`；确认 `privileged: true` 与 `cap_add: NET_ADMIN` 生效 |
| 代理关闭（off 态）时虚拟机无法上网 | `ip_forward` 未开启或 MASQUERADE 未生效，Host-Only 流量无人转发 | 重放 `sudo /usr/local/bin/proxy-switch.sh off`（脚本会确保 ip_forward=1 与 MASQUERADE）；检查 `iptables -t nat -S | grep MASQUERADE` 与 `sysctl net.ipv4.ip_forward` |
| 虚拟机 DNS 解析异常或缓慢 | TProxy 同时截获 UDP，DNS（UDP 53）查询也经 Hysteria 2 隧道由远端解析，属预期行为；若 DNS 服务器位于私网则直连 | 虚拟机 DNS 改用公共地址 `1.1.1.1`、`8.8.8.8`；确认节点侧可正常解析；私网 DNS 会命中 RETURN 规则直连，需保证该网段可达 |
| 订阅 URL 导入失败 / 拉取超时 | 地址命中 SSRF 防护（私网、回环、链路本地）；不是 http/https；目标站要求特定 UA 或宿主网络不通；内容实为 Clash YAML | 改用公网 http/https 订阅；确认宿主机 DNS 与出网；拉取 UA 固定为 `v2rayN/6.60`，服务端有额外校验时改用分享链接或 base64；Clash YAML 不支持，转换后导入 |
| 导入报 mport / 端口跳跃格式错误 | `mport` 既不是合法区间也不是合法列表，或起止倒置；或镜像内 sing-box < 1.11 | 使用 `20000:30000`（分享链接中的 `20000-30000` 会归一化）；多段用逗号 `443:443,8443:8443`；端口须在 1–65535 且起始不大于结束；本仓库默认 sing-box 1.11.15，端口跳跃需要 1.11+ |
| 认证失败，但链接能正常导入 | 口令含冒号，复制或百分号编码不完整；或 shell 中未加引号导致 `&` 之后的参数丢失 | 导入会整体解码 userinfo，`roar:pass` 与 `roar%3Apass` 都应还原为完整 `roar:pass`；从 v2rayN 重新导出并完整粘贴，命令行测试时用单引号包住链接 |
| 启用/保存节点后不生效 | 生成的 sing-box 配置未通过 `sing-box check`，后端拒绝重启 | 查看控制台 `/api/apply` 返回的错误信息定位字段（密码/SNI/端口）；`docker logs hy2-gateway` 查看 check 输出；修正后重新保存或启用 |
| 虚拟机完全无法连通宿主 192.168.100.1 | VMnet1 子网/掩码配置错误或虚拟机网卡未配置 | 按 [vmware-setup.md](vmware-setup.md) 核对 VMnet1 为 Host-Only 192.168.100.0/24；Linux 执行 `sudo netplan apply`，Windows 检查以太网 2 的静态 IP/网关后复查 |
| 虚拟机有 192.168.100.x 地址，但没有默认网关 / 浏览器打不开 | VMware Host-Only DHCP 默认不下发 `option routers`，或虚拟机默认路由仍指向 eth0 | 在虚拟机内把代理网卡设为静态：IP `192.168.100.50/24`、网关 `192.168.100.1`、DNS `223.5.5.5`；确认 `ip route` / `route print` 中存在 `default via 192.168.100.1` |
| 虚拟机可以上网，但出口 IP 不是 Hysteria 2 节点 | 代理网卡误设为 NAT/Bridged，流量绕过宿主 PREROUTING；或默认路由仍走 eth0 | 在 VMware 中把代理网卡改为 **Host-Only VMnet1**，不要用 NAT；虚拟机内把默认路由/跃点指向 `192.168.100.1`；宿主执行 `proxy-switch.sh status` 确认 `VMNET_IFACE=vmnet1`、`VMNET_SUBNET=192.168.100.0/24` |
| 开机后分流不自动生效 | dispatcher 脚本未安装或不可执行 | `ls -l /etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh` 确认存在且可执行；重跑 `sudo ./install.sh` |
| 代理开着，但国内站点/国内 CDN 打不开，`docker logs hy2-gateway` 里大量 `connection download closed: remote error: rejected` | `sniff_override_destination` 被打开时，目标地址被改写成域名，按 IP 匹配的 `geoip-cn` 规则永远不命中，中国 IP 被整体塞进隧道，而多数节点拒绝 CN 落地 | 确认 `/data/singbox.json` 中 `sniff_override_destination` 为 `false`（本仓库默认）；DNS 污染交给 `{"protocol":"dns","action":"hijack-dns"}` 的拆分解析，不要用覆盖目标地址的方式解决 |
| Windows 提示"无 Internet"但浏览器能打开部分站点 | 联网探测域名 `www.msftconnecttest.com` 被节点拒绝，Windows 据此把链路标记为无 Internet | 本仓库默认把 `.msftconnecttest.com` / `.msftncsi.com` 直连；若改了 route 规则需保留这两条；VM 内可运行 `netsh winhttp reset proxy` 后重试 |
| 白名单 SSID 命中后仍开代理（`journalctl -t HY2_DISPATCH` 显示 `SSID 为空, fail-secure`） | 系统 locale 为 `zh_CN` 时 `nmcli` 把 active 列输出成"是/否"，脚本按 `^yes:` 匹配会取到空 SSID | 已修复：`99-wifi-proxy.sh` 的 `current_ssid()` 强制 `LC_ALL=C`；升级后重跑 `sudo ./install.sh` 覆盖 `/etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh` |

## 7. 卸载

```bash
# 1. 清除 TProxy 规则，恢复宿主直连
sudo /usr/local/bin/proxy-switch.sh off

# 2. 停止并删除容器（--rmi local 同时删除本地构建的镜像）
cd /opt/hy2-gateway && docker compose down --rmi local

# 3. 删除宿主侧脚本
sudo rm -f /usr/local/bin/proxy-switch.sh
sudo rm -f /etc/NetworkManager/dispatcher.d/99-wifi-proxy.sh

# 4. 删除部署目录（含明文密码的状态文件，确认后执行）
sudo rm -rf /opt/hy2-gateway
```

卸载后重启 NetworkManager 或切换一次 Wi-Fi，确认 `journalctl` 中不再出现 `HY2_DISPATCH` 事件。

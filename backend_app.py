"""Smart Hysteria 2 Gateway - 容器内 FastAPI 控制器。

职责:
  1. 托管 /app/web 静态控制台与 /api/* 接口
  2. 维护 /data/gateway_state.json (原子写, chmod 600, 含节点密码)
  3. 按状态生成 /data/singbox.json, 以 UID/GID 930 守护 sing-box 子进程
  4. 代理 TProxy 规则切换脚本 (/usr/local/bin/proxy-switch.sh)

共享常量 (与其他 Agent 冻结一致):
  状态文件 /data/gateway_state.json | sing-box 配置 /data/singbox.json
  TPROXY_PORT=12345 FWMARK=1 TABLE=100 VMNET=192.168.100.0/24 UID/GID=930
"""

import atexit
import http.client
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from node_parser import (
    fetch_subscription,
    node_fingerprint,
    normalize_port_hopping,
    parse_import_text,
    sanitize_tag,
)

# ---------------- 冻结常量 ----------------
APP_VERSION = "1.0.0"
STATE_FILE = Path("/data/gateway_state.json")
SINGBOX_CONFIG_FILE = Path("/data/singbox.json")
WEB_DIR = Path("/app/web")
SINGBOX_BIN = "sing-box"
PROXY_SWITCH_SCRIPT = "/usr/local/bin/proxy-switch.sh"
RULE_SET_DIR = "/usr/local/share/sing-box"   # 地理分流规则集 (镜像构建时内置)
SINGBOX_UID = 930          # sing-box 进程专用账户 (iptables owner 匹配防回环)
SINGBOX_GID = 930
CHECK_TIMEOUT = 15         # sing-box check 超时 (秒)
SWITCH_TIMEOUT = 30        # proxy-switch.sh 执行超时 (秒)
STABLE_UPTIME = 60         # 存活超过该秒数则重置崩溃退避
LAST_DECISION_FILE = Path("/data/last_decision")  # proxy-switch on/off 落盘的期望态
CURRENT_SSID_FILE = Path("/data/current_ssid")    # 宿主 dispatcher 落盘的当前 SSID
GUARD_INTERVAL = 30        # 规则守护巡检周期 (秒)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
log = logging.getLogger("hy2-gateway")

app = FastAPI(title="Smart Hysteria 2 Gateway Daemon", version=APP_VERSION)


# ---------------- 数据模型 (pydantic v2) ----------------
class Hy2NodeModel(BaseModel):
    """Hysteria 2 出站节点参数。"""

    id: str = ""             # 节点唯一 ID (n_xxxxxxxx); 旧状态文件为空, 由 normalize 补齐
    tag: str = "hy2-out"
    # server/password 允许空: 无节点时 current_node 需要可校验的空占位,
    # 实际下发前由 _resolve_active_node 拦截 (抛 "未配置可用节点")
    server: str = ""
    port: int = Field(default=443, ge=1, le=65535)
    password: str = ""
    sni: str = ""
    insecure: bool = False
    obfs_type: str = ""      # 为空表示无混淆; 有值时通常为 salamander
    obfs_password: str = ""
    # 带宽仅显式指定时写入配置; None = 缺省 -> BBR 自适应 (v2rayN 导入语义)
    up_mbps: Optional[int] = Field(default=None, ge=0)
    down_mbps: Optional[int] = Field(default=None, ge=0)
    # v2rayN 的 mport/ports 参数 -> sing-box 端口跳跃, 如 "20000:30000" 或 "443:443,8443:8443"
    port_hopping: str = ""
    source: str = ""           # clipboard / subscription / json / legacy
    created_at: int = 0


class StateModel(BaseModel):
    """状态文件 schema (GET/POST /api/state 共用)。"""

    whitelist: list[str] = Field(default_factory=list)
    # current_node 保留为"活跃节点镜像", 兼容旧前端 (只传 current_node 也能工作)
    current_node: Hy2NodeModel = Field(default_factory=Hy2NodeModel)
    nodes: list[Hy2NodeModel] = Field(default_factory=list)
    active_node_id: str = ""
    wifi_iface: str = "wlp2s0"
    rj45_iface: str = "enp3s0"
    vmnet_iface: str = "vmnet1"
    vmnet_subnet: str = "192.168.100.0/24"
    # Wi-Fi 通道策略 (顶层, 双通道模型):
    #   whitelist     = 默认走代理, 白名单 SSID 例外直连
    #   always_proxy  = 强制代理 (忽略白名单)
    #   always_direct = 强制直连
    wifi_policy: Literal["whitelist", "always_proxy", "always_direct"] = "whitelist"
    tproxy_port: int = Field(default=12345, ge=1, le=65535)
    fwmark: int = 1
    table: int = 100


class NodePatchModel(BaseModel):
    """PATCH /api/nodes/{id} 请求体: 所有字段可选, 只更新显式传入的字段。"""

    tag: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    password: Optional[str] = None
    sni: Optional[str] = None
    insecure: Optional[bool] = None
    obfs_type: Optional[str] = None
    obfs_password: Optional[str] = None
    up_mbps: Optional[int] = Field(default=None, ge=0)
    down_mbps: Optional[int] = Field(default=None, ge=0)
    port_hopping: Optional[str] = None


class NodeImportModel(BaseModel):
    """POST /api/nodes/import 请求体: text 与 url 二选一。"""

    text: str = ""
    url: str = ""


class NodeTestModel(BaseModel):
    """POST /api/nodes/test 请求体: ids 为空表示测试全部节点。"""

    ids: list[str] = Field(default_factory=list)


class ProxyActionModel(BaseModel):
    """POST /api/proxy 请求体。"""

    action: str


class NetTestModel(BaseModel):
    """POST /api/nettest 请求体。target 为连通性测试的目标域名。"""

    target: str = "www.google.com"


# ---------------- 工具函数 ----------------
def atomic_write_json(path: Path, data: dict, mode: int = 0o600, gid: Optional[int] = None) -> None:
    """tmp + rename 原子落盘; 创建即带目标权限, 避免半成品文件暴露密码。"""
    tmp = path.with_name(path.name + ".tmp")
    # O_CREAT 即带 mode, 不经过 644 中间态; chmod 兜底清理历史残留的同名 tmp
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2, ensure_ascii=False))
    if gid is not None:
        # 容器内以 root 运行: 授权 singbox 组读取 (sing-box 以 UID 930 运行);
        # 非 root 环境 (本机自测) 无法 chown, 保留当前属组即可
        try:
            os.chown(tmp, 0, gid)
        except PermissionError:
            log.warning("chown gid=%s failed (non-root?), keep current owner: %s", gid, path)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ---------------- 多节点状态归一化 ----------------
NODE_FIELDS = (
    "tag", "server", "port", "password", "sni", "insecure",
    "obfs_type", "obfs_password", "up_mbps", "down_mbps", "port_hopping",
)
_NODE_DEFAULTS = {
    "tag": "", "server": "", "port": 443, "password": "", "sni": "",
    "insecure": False, "obfs_type": "", "obfs_password": "",
    "up_mbps": None, "down_mbps": None, "port_hopping": "",
}

# 延迟测试结果缓存 (仅内存, 不落盘)
_latency_cache: dict[str, dict] = {}
_latency_lock = threading.Lock()


def _empty_current_node() -> dict:
    return {"tag": "hy2-out", "server": "", "port": 443, "password": ""}


def _new_node_id(used: set[str]) -> str:
    while True:
        nid = "n_" + secrets.token_hex(4)
        if nid not in used:
            return nid


def normalize_state_dict(data: dict) -> dict:
    """归一化状态文件: 兼容单节点旧格式, 补齐 id/tag/active 并回填 current_node 镜像。

    - nodes 为空且 current_node 有 server/password -> 包装为单节点 (生成 id)
    - 缺失/重复 id 重新生成; active_node_id 非法则取第一个节点
    - 逐个 sanitize_tag, 避免与内置出站标签冲突或重名
    - 不修改节点顺序
    """
    src = data if isinstance(data, dict) else {}
    out = dict(src)

    raw_nodes = src.get("nodes")
    nodes: list[dict] = []
    if isinstance(raw_nodes, list):
        for item in raw_nodes:
            if isinstance(item, dict):
                nodes.append(dict(item))
            elif isinstance(item, Hy2NodeModel):
                nodes.append(item.model_dump())

    raw_current = src.get("current_node")
    if isinstance(raw_current, dict):
        current = dict(raw_current)
    elif isinstance(raw_current, Hy2NodeModel):
        current = raw_current.model_dump()
    else:
        current = {}

    # 旧状态文件: current_node 即唯一节点
    if not nodes and str(current.get("server") or "").strip() and str(current.get("password") or ""):
        wrapped = {key: current[key] for key in NODE_FIELDS if key in current}
        wrapped["source"] = str(current.get("source") or "")
        try:
            wrapped["created_at"] = int(current.get("created_at") or 0)
        except (TypeError, ValueError):
            wrapped["created_at"] = 0
        nodes = [wrapped]

    # 补齐 / 去重 id
    used_ids: set[str] = set()
    for node in nodes:
        node["source"] = str(node.get("source") or "")
        try:
            node["created_at"] = int(node.get("created_at") or 0)
        except (TypeError, ValueError):
            node["created_at"] = 0
        # 缺字段按模型默认值补齐 (tag 缺失时交给 sanitize_tag 生成 hy2-node)
        for key, default in _NODE_DEFAULTS.items():
            if key not in node:
                node[key] = default
        nid = str(node.get("id") or "").strip()
        if not nid or nid in used_ids:
            nid = _new_node_id(used_ids)
        node["id"] = nid
        used_ids.add(nid)

    # active_node_id 必须指向现存节点
    active = str(src.get("active_node_id") or "").strip()
    if nodes:
        if active not in used_ids:
            active = str(nodes[0]["id"])
    else:
        active = ""

    # 标签清洗 (保留顺序; 冲突自动追加 -2/-3)
    used_tags: set[str] = set()
    for node in nodes:
        node["tag"] = sanitize_tag(str(node.get("tag") or ""), used_tags)
        used_tags.add(node["tag"])

    if nodes:
        active_node = next(n for n in nodes if n["id"] == active)
        out["current_node"] = dict(active_node)  # 活跃节点完整镜像
    else:
        if not current:
            current = _empty_current_node()
        mirror = dict(current)
        for key in NODE_FIELDS:
            if key not in mirror:
                mirror[key] = Hy2NodeModel.model_fields[key].default
        mirror["tag"] = sanitize_tag(str(mirror.get("tag") or ""))
        out["current_node"] = mirror

    out["nodes"] = nodes
    out["active_node_id"] = active
    return out


def _load_state_dict(persist: bool = True) -> dict:
    """读取并归一化状态文件; persist=True 时把旧格式回写, 保证生成的节点 id 稳定。

    写操作接口传 persist=False: 归一化结果由后续事务统一落盘, 避免校验失败时
    提前改写状态文件。
    """
    if not STATE_FILE.exists():
        return normalize_state_dict({})
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"state file corrupted: {exc}")
    data = normalize_state_dict(raw)
    if persist and data != raw:
        # 旧状态文件 (无 nodes/id) 或标签需清洗: 立即落盘, 否则每次请求都会生成新 id
        try:
            atomic_write_json(STATE_FILE, data, mode=0o600)
        except Exception as exc:
            log.warning("persist normalized state failed: %s", exc)
    return data


def _resolve_active_node(state: StateModel) -> Optional[Hy2NodeModel]:
    """按 active_node_id 取活跃节点; 均不可用时回落 current_node。"""
    for node in state.nodes:
        if node.id == state.active_node_id and node.server.strip() and node.password.strip():
            return node
    for node in state.nodes:
        if node.server.strip() and node.password.strip():
            return node
    node = state.current_node
    if node.server.strip() and node.password.strip():
        return node
    return None


def _public_node(node: dict) -> dict:
    """节点对外视图 + 内存延迟测试结果。"""
    out = dict(node)
    with _latency_lock:
        cached = _latency_cache.get(str(node.get("id") or ""))
    if cached:
        out["latency_ms"] = cached.get("latency_ms")
        out["latency_ok"] = cached.get("ok")
        out["latency_error"] = cached.get("error", "")
        out["rtt_ms"] = cached.get("rtt_ms")
        out["tested_at"] = cached.get("tested_at", 0)
    else:
        out["latency_ms"] = None
        out["latency_ok"] = None
        out["latency_error"] = ""
        out["rtt_ms"] = None
        out["tested_at"] = 0
    return out


def build_hy2_outbound(node: Hy2NodeModel) -> dict:
    """单个 hysteria2 出站 (主配置与延迟测试临时配置共用)。"""
    outbound: dict = {
        "type": "hysteria2",
        "tag": node.tag,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
        "tls": {
            "enabled": True,
            "server_name": node.sni if node.sni else node.server,  # SNI 为空则回退 server
            "insecure": node.insecure,
        },
    }
    if node.obfs_type:
        outbound["obfs"] = {"type": node.obfs_type, "password": node.obfs_password}
    # 带宽仅显式指定时写入: 缺省 = BBR (v2rayN 语义: 链接不带 upmbps/downmbps 即不指定)
    if node.up_mbps:
        outbound["up_mbps"] = node.up_mbps
    if node.down_mbps:
        outbound["down_mbps"] = node.down_mbps
    if node.port_hopping:
        # v2rayN mport/ports -> sing-box >=1.11 端口跳跃
        # sing-box 1.11 的 server_ports 要求冒号区间 (如 "20000:30000");
        # 内部已由 normalize_port_hopping 统一为冒号格式
        outbound["server_ports"] = [
            seg.strip()
            for seg in node.port_hopping.split(",")
            if seg.strip()
        ]
        outbound["hop_interval"] = "30s"
    return outbound


def build_singbox_config(state: StateModel) -> dict:
    """按状态中的活跃节点生成 sing-box 1.11.x (legacy DNS schema) 运行配置。"""
    node = _resolve_active_node(state)
    if node is None:
        raise ValueError("未配置可用节点")
    hy2_outbound = build_hy2_outbound(node)

    import ipaddress as _ipaddress

    # DNS 规则: 国内域名走国内 DNS; 劫持进来的国外域名必须走隧道内 DNS。
    # 注意不要用 "outbound: any" 做节点自解析 —— 它会连带捕获 hijack 进来的
    # 客户端查询, 把国外域名也交给 223.5.5.5 (其递归缓存对被墙域名是污染的,
    # gemini/chatgpt 因此解析到假 IP)。节点自解析只在"节点是域名"时按域名窄化:
    # 走直连国内 DNS, 避免鸡生蛋 (经节点隧道解析节点自身)。
    # Google 域族优先于 geosite-cn 判定: geosite-cn 按后缀/用途收录了部分
    # google 域名 (adservice/clientservices/googlevideo 等), 但其 A 记录指向
    # 被墙的全球 IP —— 送国内 DNS 会拿到污染缓存 (AliDNS 对 Google 域名
    # 的递归结果长期被注入), 送直连路由则必超时。路由与 DNS 两层都必须
    # 先于 geosite-cn 规则命中。
    _google_keywords = ["google", "gstatic"]

    dns_rules: list[dict] = [
        {"domain_keyword": _google_keywords, "server": "proxy-dns"},
        {"rule_set": ["geosite-cn"], "server": "cn-dns"},
    ]
    node_host = str(node.server or "").strip()
    try:
        _ipaddress.ip_address(node_host)   # 字面量 IP: 无需自解析规则
    except ValueError:
        dns_rules.append({"domain": [node_host], "server": "cn-dns"})

    return {
        "log": {"level": "info", "timestamp": True},
        # DNS 拆分: 国内域名用国内 DNS (CDN 调度友好), 其余经隧道解析 (防污染)
        "dns": {
            "servers": [
                {"tag": "cn-dns", "address": "udp://223.5.5.5", "detour": "direct"},
                # 国外域名经隧道 DoH 解析: 本链路实测 UDP 53 会出现 5-10s
                # 超时 (丢包后重传不可控), 而 DoH 走 TCP 443 有重传保障,
                # 冷启动约 0.5-0.8s, 命中缓存后约 1 RTT; TCP 443 也几乎不被节点封。
                {"tag": "proxy-dns", "address": "https://1.1.1.1/dns-query", "detour": node.tag},
            ],
            "rules": dns_rules,
            "final": "proxy-dns",
        },
        "inbounds": [
            {
                "type": "tproxy",
                "tag": "tproxy-in",
                "listen": "::",                 # 双栈监听, 端口由状态文件驱动
                "listen_port": state.tproxy_port,
                "sniff": True,
                # 只嗅探、不覆盖目标地址。覆盖会把 metadata.Destination 变成域名,
                # 导致 geoip-cn 规则(按 IP 匹配)永远不命中, 中国 IP 全被塞进隧道
                # (实测 5k+ 次被节点 rejected)。DNS 污染改由下面的 hijack-dns
                # 拆分解析解决, 客户端拿到的一定是干净 IP。
                "sniff_override_destination": False,
            }
        ],
        "outbounds": [hy2_outbound, {"type": "direct", "tag": "direct"},
                      # dns-out 出站: 把 protocol=dns 的包移交上方拆分 DNS 模块应答。
                      # 必须用本 legacy 形态 —— 1.11 的 action:"hijack-dns" 在 legacy
                      # DNS schema 下不生效, DNS 包会被地理规则当普通流量分流:
                      # 发往国内 DNS(如 223.5.5.5)直连取污染缓存, 发往国外 DNS 走隧道,
                      # 表现为"不同上游拿到不同答案"且被污染域名永远解析到假 IP
                      {"type": "dns", "tag": "dns-out"}],
        # 地理分流 (v2rayN 式"绕过大陆"): 中国域名/IP 直连, 其余走 Hysteria 2 隧道;
        # 规则集为镜像内置本地文件, 运行时零下载依赖
        "route": {
            "auto_detect_interface": True,
            "rules": [
                # DNS 劫持双保险 —— 端口级强制 + 协议嗅探兜底:
                # 1) port:53 规则不依赖载荷嗅探, 直接命中, 杜绝 UDP DNS
                #    "嗅探竞态漏网后被 geoip 规则当普通流量转发"的污染路径
                #    (实测表现为: 查询已被劫持记录, 但 gemini 等域名仍解析到
                #    轮换假 IP, 且 POSTROUTING 计数器抓到明文 53 端口包出主机)
                # 2) protocol:dns 兜底非 53 端口的 DNS 形态
                # 两者都移交 dns-out → 拆分 DNS 应答: 国内域名走 223.5.5.5,
                # 国外域名走隧道内 DNS (防污染), 客户端只拿干净 IP
                {"port": 53, "outbound": "dns-out"},
                {"protocol": "dns", "outbound": "dns-out"},
                # Windows 联网探测走直连, 否则节点拒绝该域名时 Windows 会
                # 把整条链路标记为"无 Internet", 浏览器表现为完全没网
                {"domain_suffix": [".msftconnecttest.com", ".msftncsi.com"],
                 "outbound": "direct"},
                # Google 域族走隧道 (先于 geosite-cn, 理由见 dns_rules 处注释):
                # 被 geosite-cn 收录的 google 域名若按"中国域名直连"处理,
                # 目标是全球被墙 IP, 必超时 —— VM Chrome 后台服务反复失败实测根因
                {"domain_keyword": _google_keywords, "outbound": node.tag},
                {"rule_set": ["geosite-cn"], "outbound": "direct"},
                {"rule_set": ["geoip-cn"], "outbound": "direct"},
            ],
            "rule_set": [
                {"type": "local", "tag": "geosite-cn", "format": "binary",
                 "path": f"{RULE_SET_DIR}/geosite-cn.srs"},
                {"type": "local", "tag": "geoip-cn", "format": "binary",
                 "path": f"{RULE_SET_DIR}/geoip-cn.srs"},
            ],
            "final": node.tag,
        },
    }


def run_singbox_check(config_file: Optional[Path] = None) -> tuple[bool, str]:
    """运行 sing-box check 语法校验, 返回 (是否通过, 输出)。可指定待校验文件。"""
    try:
        r = subprocess.run(
            [SINGBOX_BIN, "check", "-c", str(config_file or SINGBOX_CONFIG_FILE)],
            shell=False,  # argv 列表直传, 不经 shell; 参数均为内部常量
            capture_output=True, text=True, timeout=CHECK_TIMEOUT,
        )
        return r.returncode == 0, (r.stderr or r.stdout or "").strip()
    except Exception as exc:  # 二进制缺失/超时等一律视为校验失败
        return False, str(exc)


# ---------------- 下发事务 ----------------
def _write_bytes_atomic(path: Path, data: bytes, mode: int, gid: Optional[int] = None) -> None:
    """字节级原子写 (回滚用); 与 atomic_write_json 同样的权限策略。"""
    tmp = path.with_name(path.name + ".rollback")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if gid is not None:
        try:
            os.chown(tmp, 0, gid)
        except PermissionError:
            pass
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _restore_bytes(path: Path, data: Optional[bytes], mode: int, gid: Optional[int] = None) -> None:
    """回滚文件; data=None 表示原文件不存在 -> 删除。"""
    try:
        if data is None:
            path.unlink(missing_ok=True)
        else:
            _write_bytes_atomic(path, data, mode, gid)
    except Exception as exc:
        log.error("rollback %s failed: %s", path, exc)


def _stderr_summary(output: str) -> str:
    return " ".join(str(output or "").split())[:500]


def _scrub_state_secrets(text: str, state: StateModel) -> str:
    """防止 check 输出回显配置时把节点密码写进日志/HTTP 错误。"""
    safe = str(text or "")
    secrets = set()
    for node in list(state.nodes) + [state.current_node]:
        for secret in (node.password, node.obfs_password):
            if secret:
                secrets.add(secret)
    for secret in secrets:
        safe = safe.replace(secret, "***")
    return safe


def commit_state(state: StateModel, restart: bool = True) -> str:
    """状态下发事务: 校验通过的配置才落盘, 重启失败自动回滚两个文件。

    1. 构建配置 -> 写 *.new (0640, gid 930) -> sing-box check
    2. 校验失败: 删除临时文件, 状态文件与运行中的 sing-box 均不动
    3. 通过: 备份旧状态/旧配置字节 -> 原子写状态 -> 替换配置 -> mark_config(True)
    4. restart=True: 重启失败回滚两个文件, 并尝试用旧配置重新拉起
    """
    data = state.model_dump()
    active = _resolve_active_node(state)
    if active is None:
        # 不生成坏配置, 只更新状态
        atomic_write_json(STATE_FILE, data, mode=0o600)
        return "未配置节点，sing-box 配置未更新"

    try:
        config = build_singbox_config(state)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    tmp_config = SINGBOX_CONFIG_FILE.with_name(SINGBOX_CONFIG_FILE.name + ".new")
    atomic_write_json(tmp_config, config, mode=0o640, gid=SINGBOX_GID)
    ok, output = run_singbox_check(tmp_config)
    if not ok:
        tmp_config.unlink(missing_ok=True)
        summary = _scrub_state_secrets(_stderr_summary(output), state)
        log.error("sing-box check failed: %s", summary)
        raise HTTPException(
            status_code=422,
            detail="sing-box 配置校验失败: " + summary,
        )

    # 校验通过: 记录旧文件字节用于回滚
    old_state = STATE_FILE.read_bytes() if STATE_FILE.exists() else None
    old_config = SINGBOX_CONFIG_FILE.read_bytes() if SINGBOX_CONFIG_FILE.exists() else None
    prev_valid = singbox_manager.is_config_valid()

    try:
        atomic_write_json(STATE_FILE, data, mode=0o600)
        os.replace(tmp_config, SINGBOX_CONFIG_FILE)
        singbox_manager.mark_config(True)
    except Exception as exc:
        tmp_config.unlink(missing_ok=True)
        _restore_bytes(STATE_FILE, old_state, 0o600)
        _restore_bytes(SINGBOX_CONFIG_FILE, old_config, 0o640, SINGBOX_GID)
        singbox_manager.mark_config(prev_valid)
        raise HTTPException(status_code=500, detail=f"保存配置失败: {exc}")

    if not restart:
        return "节点配置已保存，sing-box 配置已更新，未重启"

    if not singbox_manager.restart():
        # 新配置无法拉起 sing-box -> 回滚两个文件并尝试旧配置
        _restore_bytes(STATE_FILE, old_state, 0o600)
        _restore_bytes(SINGBOX_CONFIG_FILE, old_config, 0o640, SINGBOX_GID)
        singbox_manager.mark_config(prev_valid)
        restored = singbox_manager.restart()
        log.error("sing-box restart failed, rolled back (old config restored=%s)", restored)
        detail = "sing-box 重启失败，已回滚到旧配置"
        if not restored:
            detail += "；旧配置也未能启动，请检查日志"
        raise HTTPException(status_code=502, detail=detail)

    return "配置已下发，sing-box 已重启"


# ---------------- sing-box 进程守护 ----------------
class SingBoxManager:
    """sing-box 子进程生命周期管理: root 侧 spawn, UID 930 运行, 崩溃自动拉起。"""

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._stopping = False        # 主动停机标志 (区别于意外退出)
        self._config_valid = False    # 当前 singbox.json 是否通过 check
        self._backoff = 1.0           # 崩溃重启退避秒数
        self._spawned_at = 0.0

    def is_running(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def mark_config(self, valid: bool) -> None:
        self._config_valid = valid

    def is_config_valid(self) -> bool:
        return self._config_valid

    def _spawn(self) -> None:
        self._spawned_at = time.monotonic()
        # user/group 降权 (Python>=3.9); 不用 preexec_fn, 规避多线程进程死锁风险
        self._proc = subprocess.Popen(
            [SINGBOX_BIN, "run", "-D", "/data", "-c", str(SINGBOX_CONFIG_FILE)],
            shell=False,  # argv 列表直传, 不经 shell; 参数均为内部常量
            user=SINGBOX_UID,
            group=SINGBOX_GID,
        )

    def start(self) -> bool:
        """拉起 sing-box; 配置文件缺失或已存活时不动作。"""
        with self._lock:
            if self.is_running():
                return True
            if not SINGBOX_CONFIG_FILE.exists():
                return False
            self._stopping = False
            try:
                self._spawn()
            except Exception as exc:
                log.error("sing-box spawn failed: %s", exc)
                return False
        # 常驻监控线程只起一次
        if not getattr(self, "_monitor_on", False):
            self._monitor_on = True
            threading.Thread(target=self._monitor_loop, name="singbox-monitor", daemon=True).start()
        return self.is_running()

    def stop(self) -> None:
        """主动停机: terminate -> 超时 kill。"""
        with self._lock:
            self._stopping = True
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

    def restart(self) -> bool:
        self.stop()
        time.sleep(0.3)  # 留出端口释放时间
        return self.start()

    def _monitor_loop(self) -> None:
        """后台守护: 意外退出且配置有效 -> 指数退避自动重启; 主动 stop 只挂起。"""
        while True:
            proc = self._proc
            if proc is None:
                time.sleep(1.0)
                continue
            proc.wait()
            if self._stopping:
                time.sleep(1.0)  # 主动停机: 等待下一次 start()
                continue
            # 存活超过阈值视为曾稳定运行, 重置退避
            if time.monotonic() - self._spawned_at > STABLE_UPTIME:
                self._backoff = 1.0
            if not self._config_valid:
                log.warning("sing-box exited (code=%s) and config invalid, no auto-restart", proc.returncode)
                time.sleep(5.0)
                continue
            log.warning("sing-box exited unexpectedly (code=%s), restart in %.1fs", proc.returncode, self._backoff)
            time.sleep(self._backoff)
            self._backoff = min(self._backoff * 2, 30.0)
            with self._lock:
                if self._stopping or self.is_running():
                    continue
                try:
                    self._spawn()
                except Exception as exc:
                    log.error("sing-box respawn failed: %s", exc)


singbox_manager = SingBoxManager()
atexit.register(singbox_manager.stop)


# ---------------- 状态探测 ----------------
def detect_current_ssid() -> Optional[str]:
    """尽力获取当前 Wi-Fi SSID。

    容器内没有 nmcli 也连不到 dbus, 因此主路径是读宿主 dispatcher
    (99-wifi-proxy.sh) 落盘的 /data/current_ssid; nmcli 仅作宿主直接运行时的兜底。
    注意 nmcli 输出受 locale 影响 (zh_CN 下 active 列是 "是"/"否"), 必须 LC_ALL=C。
    """
    try:
        cached = CURRENT_SSID_FILE.read_text(encoding="utf-8").strip()
        if cached:
            return cached
    except Exception:
        pass
    try:
        env = dict(os.environ, LC_ALL="C")
        r = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            capture_output=True, text=True, timeout=5, env=env,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.startswith("yes:"):
                    ssid = line[4:].strip()
                    return ssid or None
    except Exception:
        pass
    return None


def read_state_fwmark() -> int:
    """从状态文件读取 fwmark (探测用), 缺省 1。"""
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return int(data.get("fwmark", 1))
    except Exception:
        return 1


def is_proxy_active() -> bool:
    """TProxy 是否生效: mangle HY2_PRE 链非空, 或策略路由含 fwmark 规则。"""
    try:
        r = subprocess.run(
            ["iptables", "-t", "mangle", "-S", "HY2_PRE"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            return True
    except Exception:
        pass
    try:
        r = subprocess.run(["ip", "rule"], capture_output=True, text=True, timeout=5)
        token = f"0x{read_state_fwmark():x}"
        if r.returncode == 0 and re.search(rf"fwmark {token}\b", r.stdout):
            return True
    except Exception:
        pass
    return False


def _dns_hijack_rules_ok() -> bool:
    """on 态关键规则形态检查: DNS:53 劫持序 + VMnet 直连 NAT 都必须在位。

    背景: 宿主侧 /usr/local/bin/proxy-switch.sh 与容器内副本可能版本分叉
    (宿主侧经 install.sh 更新, 早于某次修复时), dispatcher 触发宿主脚本
    重建规则会覆盖掉容器新版铺好的形态 —— DNS 劫持序回退会让私网 DNS
    漏出被污染; MASQUERADE 缺失则让内核直连放行的 VM 流量带着私网源地址
    出网卡被上游丢弃 (VM 国内流量黑洞)。本检查让 rule-guard 识别这类
    "开关态正确但形态回退"的回归并自动纠正。
    实现上仅执行固定字面量命令, 对 -S 输出做文本分析; 子网/网卡取值只
    用于字符串匹配不进 argv; 检查自身异常返回 True 不误伤。
    """
    try:
        pre = subprocess.run(["iptables", "-t", "mangle", "-S", "HY2_PRE"],
                             capture_output=True, text=True, timeout=5)
        out = subprocess.run(["iptables", "-t", "mangle", "-S", "HY2_OUT"],
                             capture_output=True, text=True, timeout=5)
        nat = subprocess.run(["iptables", "-t", "nat", "-S", "POSTROUTING"],
                             capture_output=True, text=True, timeout=5)
        if pre.returncode != 0 or out.returncode != 0 or nat.returncode != 0:
            return True

        def _dns_before_reserved(rules: str, udp_needle: str, tcp_needle: str) -> bool:
            lines = rules.splitlines()
            reserved_idx = next((i for i, l in enumerate(lines)
                                 if " -d 10.0.0.0/8 " in l), None)
            for needle in (udp_needle, tcp_needle):
                dns_idx = next((i for i, l in enumerate(lines) if needle in l), None)
                if dns_idx is None or (reserved_idx is not None and dns_idx > reserved_idx):
                    return False
            return True

        # needle 采用 iptables -S 的规范形式 (显式匹配模块 "-m udp"/"-m tcp"),
        # 手写 "-p udp --dport 53" 会因缺 "-m udp" 段而永不匹配
        dns_ok = (_dns_before_reserved(pre.stdout, "-m udp --dport 53 -j TPROXY",
                                       "-m tcp --dport 53 -j TPROXY")
                  and _dns_before_reserved(out.stdout, "-m udp --dport 53 -j MARK",
                                           "-m tcp --dport 53 -j MARK"))
        if not dns_ok:
            return False

        # VMnet 直连 NAT: 被 mangle RETURN 放行、经 FORWARD 转发的 VM 流量
        # (保留网段 + 中国 IP 内核直连) 必须有 MASQUERADE 才能回包。
        # 排除 docker 自带的 172.17/16 规则: 只认 -s 为状态文件 vmnet_subnet
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            vmnet_subnet = str(state.get("vmnet_subnet") or "192.168.100.0/24")
            wifi_iface = str(state.get("wifi_iface") or "wlo1")
        except Exception:
            vmnet_subnet, wifi_iface = "192.168.100.0/24", "wlo1"
        masq_ok = any(
            ("-j MASQUERADE" in l) and (f"-s {vmnet_subnet} " in l) and (f"-o {wifi_iface} " in l)
            for l in nat.stdout.splitlines()
        )
        return masq_ok
    except Exception:
        return True


def rule_guard_loop() -> None:
    """规则守护: 每 30s 将 iptables 实况对齐到落盘期望态 (last_decision)。

    期望态由 proxy-switch.sh 在每次 on/off 成功后写入 (dispatcher 决策与
    手动干预都经该脚本, 故始终权威)。任何第三方 (docker 生命周期/系统
    事件) 意外清除规则时, 一个周期内自动恢复, 不再依赖 Wi-Fi 事件触发。
    """
    while True:
        time.sleep(GUARD_INTERVAL)
        try:
            if not LAST_DECISION_FILE.exists():
                continue
            expected = LAST_DECISION_FILE.read_text(encoding="utf-8").strip()
            if expected not in ("on", "off"):
                continue
            active = is_proxy_active()
            shape_ok = (expected != "on") or _dns_hijack_rules_ok()
            if (expected == "on") != active or not shape_ok:
                log.warning("rule-guard: 规则与期望态不一致 (期望=%s 实际=%s 形态=%s), 自动恢复中",
                            expected, "on" if active else "off",
                            "完整" if shape_ok else "关键规则回退")
                # argv 仅用字面量 (expected 已白名单校验), 不把文件内容直传命令
                if expected == "on":
                    subprocess.run(
                        [PROXY_SWITCH_SCRIPT, "on"],
                        shell=False, capture_output=True, text=True,
                        timeout=SWITCH_TIMEOUT, env=proxy_switch_env(),
                    )
                else:
                    subprocess.run(
                        [PROXY_SWITCH_SCRIPT, "off"],
                        shell=False, capture_output=True, text=True,
                        timeout=SWITCH_TIMEOUT, env=proxy_switch_env(),
                    )
        except Exception as exc:
            log.warning("rule-guard: 巡检异常(%s), 下个周期重试", exc)


# ---------------- API 路由 (先于静态挂载注册) ----------------
@app.get("/api/state")
def get_state():
    """返回归一化后的状态文件完整内容; 未初始化时给出标记。"""
    if not STATE_FILE.exists():
        return {"status": "uninitialized"}
    return _load_state_dict()


def proxy_switch_env() -> dict:
    """为容器内执行的 proxy-switch.sh 构造确定性环境。

    脚本默认读宿主侧路径 /opt/hy2-gateway/..., 容器内必须显式指向 /data;
    并以状态文件的当前值覆盖 compose 注入的环境变量, 保证 WebUI 修改
    端口/网卡后, 规则切换与 sing-box 实际监听始终一致。
    """
    env = dict(os.environ)
    env["STATE_FILE"] = str(STATE_FILE)
    env_key_map = {
        "TPROXY_PORT": "tproxy_port",
        "FWMARK": "fwmark",
        "TABLE": "table",
        "RJ45_DEV": "rj45_iface",
        "WIFI_DEV": "wifi_iface",
        "VMNET_IFACE": "vmnet_iface",
        "VMNET_SUBNET": "vmnet_subnet",
    }
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return env  # 状态不可读: 至少修正 STATE_FILE, 其余回落脚本默认值
    for env_name, key in env_key_map.items():
        val = data.get(key)
        if val not in (None, ""):
            env[env_name] = str(val)
    return env


# ---------------- 内核层中国 IP 直连集 (ipset hy2_cn) ----------------
def sync_chnroute_ipset() -> bool:
    """从镜像内置 geoip-cn.srs 重建内核层中国 IP 直连集 (best-effort)。

    容器为 privileged + host 网络, ipset/netlink 操作直接作用于宿主内核,
    因此无需宿主机安装任何组件。失败 (缺 ipset 二进制/无权限/规则集缺失)
    仅告警, 分流回落 sing-box geoip 判定, 不影响主流程。
    数据源与 sing-box 路由判定是同一份 .srs 文件, 两层分流永不漂移。
    """
    set_name = "hy2_cn"
    if shutil.which("ipset") is None:
        log.info("chnroute: 容器内无 ipset, 内核层中国 IP 直连未启用 (sing-box 判定兜底)")
        return False

    def ipset(*args: str, stdin: Optional[str] = None) -> bool:
        try:
            r = subprocess.run(["ipset", *args], input=stdin, capture_output=True,
                               text=True, timeout=90)
            return r.returncode == 0
        except Exception:
            return False

    try:
        # sing-box decompile 把结果写入 -o 指定的文件而非 stdout (默认写到
        # srs 同目录的 .json, 会污染只读的规则集目录, 故显式指到 /tmp)
        out_path = "/tmp/geoip-cn.decompiled.json"
        r = subprocess.run(
            [SINGBOX_BIN, "rule-set", "decompile", f"{RULE_SET_DIR}/geoip-cn.srs",
             "-o", out_path],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0 or not os.path.exists(out_path):
            log.warning("chnroute: geoip-cn.srs decompile 失败: %s", (r.stderr or "")[:120])
            return False

        import ipaddress

        cidrs: list[str] = []
        decompiled = json.loads(Path(out_path).read_text(encoding="utf-8"))
        Path(out_path).unlink(missing_ok=True)
        for rule in decompiled.get("rules", []):
            for cidr in rule.get("ip_cidr") or []:
                try:
                    if ipaddress.ip_network(str(cidr), strict=False).version == 4:
                        cidrs.append(str(cidr))
                except ValueError:
                    continue
        if not cidrs:
            log.warning("chnroute: decompile 结果无 IPv4 CIDR, 保留现有集合")
            return False

        # 临时集填充 -> swap 原子换表: 内核中已有 iptables 规则即时命中新数据
        new_set = f"{set_name}_new"
        if not ipset("create", new_set, "hash:net", "family", "inet", "maxelem", "65536", "-exist"):
            log.warning("chnroute: ipset create 失败 (权限?)")
            return False
        ipset("flush", new_set)
        payload = "".join(f"add {new_set} {c} -exist\n" for c in cidrs)
        if not ipset("restore", "-exist", stdin=payload):
            log.warning("chnroute: ipset restore 失败, 保留现有集合")
            ipset("destroy", new_set)
            return False
        ok = (ipset("create", set_name, "hash:net", "family", "inet", "maxelem", "65536", "-exist")
              and ipset("swap", new_set, set_name))
        ipset("destroy", new_set)
        if not ok:
            log.warning("chnroute: ipset swap 失败, 保留现有集合")
            return False
        log.info("chnroute: ipset %s 已重建 (%d 条 IPv4 CIDR)", set_name, len(cidrs))

        # 代理在开时确保 mangle 匹配规则在位 (位次与 proxy-switch.sh 构建序一致:
        # HY2_PRE=4 / HY2_OUT=5, 后于 DNS 劫持、先于 catch-all)
        if is_proxy_active():
            for chain, pos in (("HY2_PRE", "4"), ("HY2_OUT", "5")):
                chk = subprocess.run(
                    ["iptables", "-t", "mangle", "-C", chain,
                     "-m", "set", "--match-set", set_name, "dst", "-j", "RETURN"],
                    capture_output=True, timeout=5,
                )
                if chk.returncode != 0:
                    subprocess.run(
                        ["iptables", "-t", "mangle", "-I", chain, pos,
                         "-m", "set", "--match-set", set_name, "dst", "-j", "RETURN"],
                        capture_output=True, timeout=5,
                    )
            log.info("chnroute: mangle 匹配规则已确保在位")
        return True
    except Exception as exc:
        log.warning("chnroute: 同步异常(%s), sing-box 判定兜底", exc)
        return False


def reapply_proxy_rules() -> str:
    """网络参数变更后按落盘期望态重建 iptables 规则。

    `proxy-switch.sh on/off` 会把 VMnet 网段/网卡/IP 端口写入规则；仅修改状态
    文件不会更新已有 MASQUERADE/FORWARD 规则。因此 /api/apply 成功后必须重放
    一次期望态，否则 WebUI 改 vmnet_iface/vmnet_subnet 后规则仍是旧值。
    """
    try:
        expected = LAST_DECISION_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return ""
    if expected not in ("on", "off"):
        return ""
    try:
        r = subprocess.run(
            [PROXY_SWITCH_SCRIPT, expected],
            shell=False,  # argv 列表直传; expected 已限定为 on/off
            capture_output=True, text=True, timeout=SWITCH_TIMEOUT,
            env=proxy_switch_env(),
        )
        if r.returncode != 0:
            summary = " ".join((r.stdout + " " + r.stderr).split())[:300]
            log.warning("reapply proxy rules failed: %s", summary)
            return f"网络规则重载失败: {summary}"
        return "网络规则已按新参数重载"
    except Exception as exc:
        log.warning("reapply proxy rules exception: %s", exc)
        return f"网络规则重载异常: {exc}"


@app.post("/api/apply")
def apply_state(state: StateModel):
    """保存状态 -> 归一化 -> 校验配置 -> 事务下发 (旧前端只传 current_node 也兼容)。"""
    data = state.model_dump()
    # 旧前端 payload 不含 nodes 字段: 保留已有多节点列表, 并把 current_node 的改动
    # 合并到当前活跃节点 (否则一次"保存设置"会把导入的节点列表清空)
    if "nodes" not in state.model_fields_set and "active_node_id" not in state.model_fields_set:
        try:
            stored = _load_state_dict(persist=False)
        except HTTPException:
            stored = None
        if stored and stored.get("nodes"):
            active = str(stored.get("active_node_id") or "")
            dumped = data.get("current_node") or {}
            incoming = {k: dumped[k] for k in state.current_node.model_fields_set if k in dumped}
            for node in stored["nodes"]:
                if node.get("id") == active:
                    for key in NODE_FIELDS:
                        if key in incoming:
                            node[key] = incoming[key]
                    break
            data["nodes"] = stored["nodes"]
            data["active_node_id"] = active
    data = normalize_state_dict(data)
    try:
        normalized = StateModel.model_validate(data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"状态参数非法: {exc}")
    message = commit_state(normalized, restart=True)
    network_message = reapply_proxy_rules()
    # 每周规则更新走 /api/apply 回传, 顺带刷新内核直连集 (数据源同源)
    chnroute_ok = sync_chnroute_ipset()
    has_active = _resolve_active_node(normalized) is not None
    return {
        "status": "success",
        "message": message,
        "network_message": network_message,
        "singbox_valid": has_active,
    }


# ---------------- 多节点管理 API ----------------
def _redact_text(text: str) -> str:
    """错误回显脱敏 (URL userinfo / JSON password / auth 参数)。"""
    safe = re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s?#]*@", r"\1***@", str(text or ""))
    safe = re.sub(r'(?i)("(?:password|obfs[-_]?password)"\s*:\s*")[^"]*(")', r"\1***\2", safe)
    safe = re.sub(r"(?i)((?:auth|password|obfs[-_]?password)=)[^&\s#]+", r"\1***", safe)
    return safe[:500]


@app.get("/api/nodes")
def list_nodes():
    """节点列表 + 活跃节点 + 内存中的延迟测试结果。"""
    data = _load_state_dict()
    return {
        "active_node_id": data.get("active_node_id", ""),
        "nodes": [_public_node(node) for node in data["nodes"]],
    }


@app.post("/api/nodes/import")
def import_nodes(body: NodeImportModel):
    """导入分享链接/base64 订阅/sing-box JSON; 只更新 nodes, 不重启 sing-box。"""
    text = (body.text or "").strip()
    url = (body.url or "").strip()
    if not text and not url:
        raise HTTPException(status_code=422, detail="text 与 url 不能同时为空")

    errors: list[dict] = []
    source = "clipboard"
    # 单行 http(s) URL 视为订阅地址
    if not url and "\n" not in text and re.match(r"(?i)^https?://", text):
        url, text = text, ""
    if url:
        source = "subscription"
        try:
            content = fetch_subscription(url)
        except Exception as exc:
            content = ""
            errors.append({"line": None, "input": _redact_text(url), "error": str(exc)[:300]})
    else:
        content = text

    parsed: list[dict] = []
    if content:
        try:
            parsed, parse_errors = parse_import_text(content, source=source)
        except Exception as exc:  # 解析器异常不应升级为 500
            parsed, parse_errors = [], [{
                "line": None,
                "input": _redact_text(content),
                "error": f"解析失败: {str(exc)[:200]}",
            }]
        errors.extend(parse_errors)

    data = _load_state_dict(persist=False)
    if parsed:
        nodes = data["nodes"]
        by_fp: dict[str, dict] = {}
        for node in nodes:
            by_fp.setdefault(node_fingerprint(node), node)
        used_ids = {str(node.get("id") or "") for node in nodes}
        imported = 0
        updated = 0
        skipped = 0
        for node in parsed:
            fp = node_fingerprint(node)
            existing = by_fp.get(fp)
            if existing is not None:
                # 同指纹 -> 更新参数, 保留原 id/created_at
                for key, value in node.items():
                    if key in ("id", "created_at"):
                        continue
                    existing[key] = value
                updated += 1
            else:
                node["id"] = _new_node_id(used_ids)
                used_ids.add(node["id"])
                node["created_at"] = int(time.time())
                node["source"] = str(node.get("source") or source)
                nodes.append(node)
                by_fp[fp] = node
                imported += 1

        was_active = bool(data.get("active_node_id"))
        data = normalize_state_dict(data)
        atomic_write_json(STATE_FILE, data, mode=0o600)
        log.info("nodes import: imported=%d updated=%d skipped=%d errors=%d",
                 imported, updated, skipped, len(errors))
        message = ""
        if data["nodes"] and data["active_node_id"] and not was_active:
            message = "已自动将第一个节点设为活跃节点；sing-box 未重启，请激活节点后生效"
    else:
        imported = updated = skipped = 0
        message = ""

    result = {
        "status": "success",
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "active_node_id": data.get("active_node_id", ""),
        "nodes": [_public_node(node) for node in data["nodes"]],
    }
    if message:
        result["message"] = message
    return result


@app.post("/api/nodes/{node_id}/activate")
def activate_node(node_id: str):
    """切换活跃节点并立即下发 (重启 sing-box)。"""
    data = _load_state_dict(persist=False)
    target = next((n for n in data["nodes"] if n["id"] == node_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="节点不存在")
    if not str(target.get("server") or "").strip() or not str(target.get("password") or ""):
        raise HTTPException(status_code=422, detail="节点缺少服务器或密码")
    data["active_node_id"] = node_id
    data = normalize_state_dict(data)
    try:
        state = StateModel.model_validate(data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"节点参数非法: {exc}")
    message = commit_state(state, restart=True)
    return {
        "status": "success",
        "message": message,
        "active_node_id": data["active_node_id"],
    }


@app.patch("/api/nodes/{node_id}")
def patch_node(node_id: str, patch: NodePatchModel):
    """部分更新节点; 活跃节点改动会立即下发, 非活跃节点只落盘。"""
    data = _load_state_dict(persist=False)
    node = next((n for n in data["nodes"] if n["id"] == node_id), None)
    if node is None:
        raise HTTPException(status_code=404, detail="节点不存在")

    updates = patch.model_dump(exclude_unset=True)
    for key, value in updates.items():
        if key == "tag":
            used = {n["tag"] for n in data["nodes"] if n["id"] != node_id}
            node["tag"] = sanitize_tag(str(value or ""), used)
        elif key == "port_hopping":
            try:
                node["port_hopping"] = normalize_port_hopping(str(value or ""))
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        elif key == "obfs_type":
            obfs_type = str(value or "").strip().lower()
            if obfs_type not in ("", "salamander"):
                raise HTTPException(status_code=422, detail="不支持的混淆类型 (仅支持 salamander)")
            node["obfs_type"] = obfs_type
        elif key in ("server", "password"):
            text = str(value) if value is not None else ""
            if not text.strip():
                raise HTTPException(status_code=422, detail=f"{key} 不能为空")
            if key == "server":
                text = text.strip()
                if any(ch.isspace() for ch in text) or "/" in text:
                    raise HTTPException(status_code=422, detail="服务器地址格式非法")
            node[key] = text
        elif key in ("up_mbps", "down_mbps"):
            if value is None:
                node[key] = None
            else:
                node[key] = int(value)
        elif key in ("sni", "obfs_password"):
            node[key] = str(value or "")
        elif key == "insecure":
            node["insecure"] = bool(value)
        elif key == "port":
            if value is not None:
                node["port"] = int(value)
        else:
            node[key] = value

    if node.get("obfs_type") and not str(node.get("obfs_password") or "").strip():
        raise HTTPException(status_code=422, detail="启用混淆时必须提供混淆口令")

    data = normalize_state_dict(data)
    activated = data.get("active_node_id") == node_id
    if activated:
        try:
            state = StateModel.model_validate(data)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"节点参数非法: {exc}")
        message = commit_state(state, restart=True)
    else:
        atomic_write_json(STATE_FILE, data, mode=0o600)
        message = "节点已更新"

    updated = next((n for n in data["nodes"] if n["id"] == node_id), node)
    return {
        "status": "success",
        "node": _public_node(updated),
        "activated": activated,
        "message": message,
    }


@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: str):
    """删除非活跃节点; 活跃节点需先切换。"""
    data = _load_state_dict(persist=False)
    node = next((n for n in data["nodes"] if n["id"] == node_id), None)
    if node is None:
        raise HTTPException(status_code=404, detail="节点不存在")
    if data.get("active_node_id") == node_id:
        raise HTTPException(status_code=409, detail="请先切换到其他节点再删除")

    data["nodes"] = [n for n in data["nodes"] if n["id"] != node_id]
    data = normalize_state_dict(data)
    atomic_write_json(STATE_FILE, data, mode=0o600)
    with _latency_lock:
        _latency_cache.pop(node_id, None)
    log.info("nodes delete: %s", node_id)
    return {
        "status": "success",
        "active_node_id": data.get("active_node_id", ""),
        "nodes": [_public_node(n) for n in data["nodes"]],
    }


# ---------------- 节点延迟测试 (临时 sing-box 实例 + Clash API) ----------------
def _clash_api_get(port: int, path: str, secret: str, timeout: float) -> tuple[int, bytes]:
    """访问临时实例的 Clash API (固定 127.0.0.1 回环); 非 2xx 也返回状态码与响应体。

    http.client 显式绑定回环主机与端口, 请求目标不经过 URL 拼接,
    从结构上排除请求目标被外部输入改写的可能。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Authorization": f"Bearer {secret}"})
        resp = conn.getresponse()
        return resp.status, resp.read(65536)
    finally:
        conn.close()


def _hop_start_port(node: Hy2NodeModel) -> int:
    if node.port_hopping:
        try:
            return int(str(node.port_hopping).split(",")[0].split(":")[0])
        except (TypeError, ValueError):
            pass
    return node.port


# TCP RTT 兜底探针: 以 sing-box UID 运行, 绕过 OUTPUT 链的 TProxy 劫持
# (否则 connect 只握到本地 sing-box, 测出来是 0ms)。连接成功或收到 RST
# 都代表 1 个 RTT 已返回; 超时则视为不可测。
_TCP_RTT_PROBE = r"""
import socket, sys, time
ip, port = sys.argv[1], int(sys.argv[2])
best = -1.0
for _ in range(2):
    s = socket.socket()
    s.settimeout(1.5)
    t = time.monotonic()
    ok = False
    try:
        s.connect((ip, port))
        ok = True
    except ConnectionRefusedError:
        ok = True
    except Exception:
        ok = False
    finally:
        dt = (time.monotonic() - t) * 1000
        s.close()
    if ok and (best < 0 or dt < best):
        best = dt
print(int(best))
"""


def _node_rtt(node: Hy2NodeModel) -> Optional[int]:
    """节点单程 RTT (1 个往返), 与 v2rayN「测试延迟」口径一致。

    优先 ICMP (ICMP 不进 TProxy: 宿主规则只处理 TCP/UDP, 因此是真实链路 RTT);
    ICMP 被封时回落到 TCP 握手 (以 UID 930 直连, 绕开 TProxy)。
    只应在节点已确认可达后调用, 避免不可达节点额外等待。
    """
    host = str(node.server or "").strip()
    if not host:
        return None
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        ip = infos[0][4][0]
    except Exception:
        return None

    # 1) ICMP: 3 个包取 avg, 0.2s 间隔, 单包 1s 超时
    try:
        proc = subprocess.run(
            ["ping", "-c", "3", "-i", "0.2", "-W", "1", ip],
            capture_output=True, text=True, timeout=5,
        )
        out = proc.stdout or ""
        # busybox: "round-trip min/avg/max = 272.2/281.0/290.1 ms"
        # iputils: "rtt min/avg/max/mdev = 272.2/281.0/290.1/5.0 ms"
        match = re.search(r"(?:round-trip|rtt)\s+min/avg/max(?:/mdev)?\s*=\s*[\d.]+/([\d.]+)/", out)
        if match:
            return max(1, int(round(float(match.group(1)))))
    except Exception:
        pass

    # 2) TCP 兜底
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _TCP_RTT_PROBE, ip, str(_hop_start_port(node))],
            capture_output=True, text=True, timeout=6,
            user=SINGBOX_UID, group=SINGBOX_GID,
        )
        value = int((proc.stdout or "").strip() or -1)
        if value > 0:
            return value
    except Exception:
        pass
    return None


def _udp_probe(ip: str, port: int, timeout: float = 2.0) -> str:
    """UDP 静默探测: QUIC 服务对垃圾包应静默丢弃; ICMP 拒绝则说明端口未开放。"""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(b"hy2-gateway-latency-probe")
            try:
                sock.recv(64)
                return "UDP 收到响应"
            except socket.timeout:
                return "UDP 静默 (2s 无 ICMP 拒绝)"
    except ConnectionRefusedError:
        return "UDP ICMP 端口不可达"
    except Exception as exc:
        return f"UDP 探测异常: {str(exc)[:60]}"


def _node_diagnosis(node: Hy2NodeModel) -> str:
    """延迟测试失败后的补充诊断: DNS + UDP 静默探测。"""
    try:
        infos = socket.getaddrinfo(node.server, None)
    except Exception as exc:
        return f"DNS 解析失败: {str(exc)[:80]}"
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return "DNS 解析失败: 无结果"
    text = f"DNS 解析: {','.join(ips[:2])}"
    text += "；" + _udp_probe(ips[0], _hop_start_port(node))
    return text


def _scrub_secrets(text: str, node: Hy2NodeModel) -> str:
    """日志/错误文本去密: 任何密码片段都替换为 ***。"""
    safe = str(text or "")
    for secret in (node.password, node.obfs_password):
        if secret:
            safe = safe.replace(secret, "***")
    return safe[:400]


def _proc_stderr_tail(proc: Optional[subprocess.Popen], limit: int = 200) -> str:
    """进程已退出时读取 stderr 末尾 (未退出/无输出返回空串)。"""
    if proc is None or proc.poll() is None or proc.stderr is None:
        return ""
    try:
        raw = proc.stderr.read()
    except Exception:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return " | ".join(lines[-3:])[-limit:]


def test_node_latency(node: Hy2NodeModel) -> dict:
    """用独立临时 sing-box 实例做真实握手测速, 不影响主进程与主配置。"""
    proc: Optional[subprocess.Popen] = None
    tmpdir = tempfile.mkdtemp(prefix="hy2test-", dir="/tmp")
    try:
        # 随机空闲本地端口 (仅临时 Clash API 使用)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            clash_port = int(probe.getsockname()[1])
        secret = secrets.token_urlsafe(18)
        tag = sanitize_tag(node.tag)  # 避免与 direct 等内置标签冲突
        test_node = node.model_copy(update={"tag": tag})
        # 节点自身是域名时走直连 DNS 自解析 (避免经节点隧道解析自身的鸡生蛋);
        # 其余查询 (若测试目标改成域名) 一律经节点解析, 避免系统 DNS 污染。
        node_host = str(test_node.server or "").strip()
        dns_rules: list[dict] = []
        try:
            import ipaddress as _ipaddress
            _ipaddress.ip_address(node_host)
        except ValueError:
            dns_rules.append({"domain": [node_host], "server": "direct-dns"})
        config = {
            "log": {"level": "error"},
            "dns": {
                "servers": [
                    {"tag": "direct-dns", "address": "udp://223.5.5.5", "detour": "direct"},
                    {"tag": "proxy-dns", "address": "https://1.1.1.1/dns-query", "detour": tag},
                ],
                "rules": dns_rules,
                "final": "proxy-dns",
            },
            "experimental": {
                "clash_api": {
                    "external_controller": f"127.0.0.1:{clash_port}",
                    "secret": secret,
                }
            },
            "outbounds": [build_hy2_outbound(test_node), {"type": "direct", "tag": "direct"}],
            "route": {"final": tag},
        }
        # 临时配置文件由 tempfile 命名 (目录 mkdtemp + 文件名自动生成,
        # 路径不经任何手工拼接/外部输入, 无穿越面)
        with tempfile.NamedTemporaryFile(
                "w", dir=tmpdir, prefix="config-", suffix=".json",
                delete=False, encoding="utf-8") as fh:
            fh.write(json.dumps(config, ensure_ascii=False))
            cfg_path = fh.name
        os.chmod(tmpdir, 0o755)
        os.chmod(cfg_path, 0o644)
        try:
            os.chown(tmpdir, SINGBOX_UID, SINGBOX_GID)
            os.chown(cfg_path, SINGBOX_UID, SINGBOX_GID)
        except OSError as exc:
            log.warning("latency: chown temp dir failed: %s", exc)

        proc = subprocess.Popen(
            [SINGBOX_BIN, "run", "-D", tmpdir, "-c", cfg_path],
            shell=False,
            user=SINGBOX_UID,
            group=SINGBOX_GID,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 等 Clash API 就绪 (最多约 3 秒)
        deadline = time.monotonic() + 3.0
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            try:
                status, _ = _clash_api_get(clash_port, "/proxies", secret, 0.4)
                if status == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.15)

        if not ready:
            reason = "临时 sing-box 实例未就绪 (Clash API 3 秒内无响应)"
            if proc.poll() is not None:
                reason += f"；进程提前退出 (code={proc.returncode})"
                tail = _proc_stderr_tail(proc)
                if tail:
                    reason += f"；stderr: {tail}"
            reason += "；" + _node_diagnosis(node)
            return {"ok": False, "latency_ms": None, "rtt_ms": None, "error": _scrub_secrets(reason, node)}

        # 真实握手: 让 sing-box 通过节点的 hysteria2 出站访问 Cloudflare 1.1.1.1。
        # 用 IP 字面量而非域名: 避免系统 DNS 把测试目标解析到污染/国内 CDN IP,
        # 再被强制走国外节点形成 CN→US→CN 的假高延迟 (实测可到 1.5s+)。
        params = urllib.parse.urlencode({
            "url": "https://1.1.1.1/cdn-cgi/trace",
            "timeout": "5000",
        })
        delay_path = f"/proxies/{urllib.parse.quote(tag, safe='')}/delay?{params}"
        try:
            status, body = _clash_api_get(clash_port, delay_path, secret, 6.0)
        except Exception as exc:
            reason = f"延迟测试请求失败: {str(exc)[:120]}"
            tail = _proc_stderr_tail(proc)
            if tail:
                reason += f"；sing-box: {tail}"
            reason += "；" + _node_diagnosis(node)
            return {"ok": False, "latency_ms": None, "rtt_ms": None, "error": _scrub_secrets(reason, node)}

        if status != 200:
            detail = ""
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
                detail = str(payload.get("message") or payload.get("error") or "")
            except Exception:
                detail = body.decode("utf-8", errors="replace")[:120]
            reason = f"节点握手失败 (HTTP {status})"
            if detail:
                reason += f": {detail}"
            tail = _proc_stderr_tail(proc)
            if tail:
                reason += f"；sing-box: {tail}"
            reason += "；" + _node_diagnosis(node)
            return {"ok": False, "latency_ms": None, "rtt_ms": None, "error": _scrub_secrets(reason, node)}

        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
            delay = int(payload.get("delay") or 0)
        except Exception as exc:
            reason = f"Clash API 响应解析失败: {str(exc)[:80]}"
            return {"ok": False, "latency_ms": None, "rtt_ms": None, "error": _scrub_secrets(reason, node)}
        if delay <= 0:
            reason = "节点握手失败: 延迟为 0；" + _node_diagnosis(node)
            return {"ok": False, "latency_ms": None, "rtt_ms": None, "error": _scrub_secrets(reason, node)}
        # 单程 RTT: 与 v2rayN「测试延迟」同口径 (1 个往返), 用于解释
        # 完整 HTTPS 延迟 (≥3 RTT) 与 ping 数值之间的倍数关系。
        rtt = _node_rtt(node)
        return {"ok": True, "latency_ms": delay, "rtt_ms": rtt, "error": ""}
    except Exception as exc:
        reason = f"延迟测试异常: {str(exc)[:160]}"
        return {"ok": False, "latency_ms": None, "error": _scrub_secrets(reason, node)}
    finally:
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                        proc.wait(timeout=2)
                    except Exception:
                        pass
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/api/nodes/test")
def test_nodes(body: Optional[NodeTestModel] = None):
    """并发测试节点延迟 (最多 3 并发), 结果写入内存缓存。"""
    data = _load_state_dict()
    by_id = {str(n["id"]): n for n in data["nodes"]}
    ids = list(body.ids) if body is not None else []
    requested = [str(i).strip() for i in ids if str(i).strip()]
    if not requested:
        requested = [str(n["id"]) for n in data["nodes"]]
    # 去重并保序
    ordered: list[str] = []
    seen: set[str] = set()
    for nid in requested:
        if nid not in seen:
            seen.add(nid)
            ordered.append(nid)

    results: dict[str, dict] = {}
    targets = [by_id[nid] for nid in ordered if nid in by_id]
    if targets:
        valid_targets: list[tuple[dict, Hy2NodeModel]] = []
        for node in targets:
            try:
                valid_targets.append((node, Hy2NodeModel.model_validate(node)))
            except Exception as exc:
                nid = str(node["id"])
                results[nid] = {
                    "id": nid, "ok": False, "latency_ms": None, "rtt_ms": None,
                    "error": f"节点参数非法: {str(exc)[:200]}",
                }
                with _latency_lock:
                    _latency_cache[nid] = {
                        "latency_ms": None, "rtt_ms": None, "ok": False,
                        "error": results[nid]["error"], "tested_at": int(time.time()),
                    }
        with ThreadPoolExecutor(max_workers=3) as pool:
            future_map = {
                pool.submit(test_node_latency, model): node
                for node, model in valid_targets
            }
            for future, node in future_map.items():
                nid = str(node["id"])
                try:
                    outcome = future.result()
                except Exception as exc:
                    outcome = {"ok": False, "latency_ms": None, "error": str(exc)[:300]}
                results[nid] = {
                    "id": nid,
                    "ok": bool(outcome.get("ok")),
                    "latency_ms": outcome.get("latency_ms"),
                    "rtt_ms": outcome.get("rtt_ms"),
                    "error": str(outcome.get("error") or ""),
                }
                with _latency_lock:
                    _latency_cache[nid] = {
                        "latency_ms": outcome.get("latency_ms"),
                        "rtt_ms": outcome.get("rtt_ms"),
                        "ok": bool(outcome.get("ok")),
                        "error": str(outcome.get("error") or ""),
                        "tested_at": int(time.time()),
                    }

    ordered_results: list[dict] = []
    for nid in ordered:
        if nid in results:
            ordered_results.append(results[nid])
        else:
            ordered_results.append({"id": nid, "ok": False, "latency_ms": None, "rtt_ms": None, "error": "节点不存在"})
    return {"status": "success", "results": ordered_results}


@app.get("/api/status")
def get_status():
    """网关运行时健康快照。"""
    return {
        "singbox_running": singbox_manager.is_running(),
        "proxy_active": is_proxy_active(),
        "current_ssid": detect_current_ssid(),
        "version": APP_VERSION,
    }


@app.post("/api/proxy")
def proxy_switch(body: ProxyActionModel):
    """执行 TProxy 规则切换脚本 (on/off)。"""
    action = body.action.strip().lower()
    if action not in ("on", "off"):
        raise HTTPException(status_code=400, detail="action must be 'on' or 'off'")
    try:
        r = subprocess.run(
            [PROXY_SWITCH_SCRIPT, action],
            shell=False,  # argv 列表直传, 不经 shell; action 已白名单限定为 on/off
            capture_output=True, text=True, timeout=SWITCH_TIMEOUT,
            env=proxy_switch_env(),
        )
        output = (r.stdout + "\n" + r.stderr).strip()
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="proxy-switch.sh timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"{PROXY_SWITCH_SCRIPT} not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=output or f"proxy-switch.sh exited with {r.returncode}")
    return {"status": "success", "action": action, "output": output}


# ---------------- 网卡枚举与连通性测试 ----------------
def list_host_interfaces() -> list[dict]:
    """枚举宿主网络接口。

    容器以 host 网络模式运行, /sys/class/net 即宿主视图;
    kind 用于前端下拉分组 (以太网/无线/VMware/网桥/隧道/回环)。
    """
    base = Path("/sys/class/net")
    out: list[dict] = []
    if base.is_dir():
        for p in sorted(base.iterdir()):
            name = p.name
            if name.startswith("veth") or (p / "bridge").is_dir():
                kind = "bridge"          # docker / libvirt 虚拟网桥及 veth
            elif (p / "phy80211").exists():
                kind = "wifi"
            elif (p / "tun_flags").exists() or name.startswith(("tun", "tap", "wg", "zt")):
                kind = "tunnel"          # 内核 tun_flags 存在即为 tun/tap 设备
            elif name.startswith("vmnet"):
                kind = "vmware"
            elif name == "lo":
                kind = "loopback"
            else:
                kind = "ethernet"
            out.append({"name": name, "kind": kind})
    order = {"ethernet": 0, "wifi": 1, "vmware": 2, "bridge": 3, "tunnel": 4, "other": 5, "loopback": 6}
    out.sort(key=lambda x: (order.get(x["kind"], 9), x["name"]))
    return out


@app.get("/api/interfaces")
def get_interfaces():
    """供控制台网卡下拉选择: 返回宿主机全部网络接口及分类。"""
    return {"interfaces": list_host_interfaces()}


@app.post("/api/nettest")
def nettest(body: NetTestModel):
    """分段连通性诊断 (容器即宿主网络栈, 结果代表宿主机视角):

    1. DNS 解析目标域名 (系统 resolver)
    2. 直连 TCP 国内锚点 223.5.5.5:443
    3. 直连 TCP 国际锚点 1.1.1.1:443
    4. 当前节点域名解析
    5. 节点 UDP 静默探测 (QUIC 服务对垃圾包应静默丢弃;
       收到 ICMP 拒绝说明端口未开放, 是明确故障信号)
    """
    target = body.target.strip() or "www.google.com"
    results: list[dict] = []

    def add(name: str, label: str, ok, ms: int, detail: str = "") -> None:
        results.append({"name": name, "label": label, "ok": ok, "ms": ms, "detail": detail})

    def dns_probe(name: str, label: str, host: str) -> str | None:
        t0 = time.monotonic()
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
            ip = infos[0][4][0]
            add(name, label, True, int((time.monotonic() - t0) * 1000), ip)
            return ip
        except Exception as exc:
            add(name, label, False, int((time.monotonic() - t0) * 1000), str(exc)[:90])
            return None

    def tcp_probe(name: str, label: str, host: str, port: int) -> None:
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=3.0):
                add(name, label, True, int((time.monotonic() - t0) * 1000))
        except Exception as exc:
            add(name, label, False, int((time.monotonic() - t0) * 1000), str(exc)[:90])

    def udp_probe(name: str, label: str, ip: str, port: int) -> None:
        t0 = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.connect((ip, port))
                s.send(b"hy2-gateway-probe")
                try:
                    s.recv(64)
                    add(name, label, True, int((time.monotonic() - t0) * 1000), "收到响应包")
                except socket.timeout:
                    # QUIC/UDP 服务对无效载荷静默丢弃: 无法确认握手, 但链路未被拒绝
                    add(name, label, None, int((time.monotonic() - t0) * 1000), "静默 (QUIC 预期)")
                except ConnectionRefusedError:
                    add(name, label, False, int((time.monotonic() - t0) * 1000), "ICMP 端口不可达")
        except Exception as exc:
            add(name, label, False, int((time.monotonic() - t0) * 1000), str(exc)[:90])

    # 1-3: 基础直连能力
    dns_probe("dns_target", f"DNS 解析 {target}", target)
    tcp_probe("tcp_cn", "直连 TCP 223.5.5.5:443 (国内)", "223.5.5.5", 443)
    tcp_probe("tcp_global", "直连 TCP 1.1.1.1:443 (国际)", "1.1.1.1", 443)

    # 4-5: 当前活跃节点可达性
    node = None
    try:
        node = _load_state_dict().get("current_node") or {}
    except Exception:
        pass
    server = str(node.get("server") or "").strip()
    port = int(node.get("port") or 443)
    if server:
        ip = dns_probe("node_dns", f"节点域名解析 {server}", server)
        if ip:
            udp_probe("node_udp", f"节点 UDP 静默探测 :{port}", ip, port)
        else:
            add("node_udp", f"节点 UDP 静默探测 :{port}", False, 0, "跳过: 节点域名未解析")
    else:
        add("node_dns", "节点域名解析", False, 0, "未配置节点 (先在控制台下发)")
        add("node_udp", "节点 UDP 静默探测", False, 0, "跳过: 未配置节点")

    key_results = [r for r in results if r["name"] in ("dns_target", "tcp_cn")]
    overall = "up" if all(r["ok"] for r in key_results) else ("degraded" if any(r["ok"] for r in results) else "down")
    return {"status": "success", "target": target, "overall": overall, "results": results}


# ---------------- 出口 IP 实测 ----------------
# 后端容器与宿主共享网络栈: 它自己的出站 HTTP 同样被 OUTPUT 链劫持。
# 代理开启时 echo 服务看到的是 Hysteria 2 隧道出口 IP, 关闭时是本地宽带
# 公网 IP —— 因此"后端自己请求一次 IP echo"即等价于实测当前真实出口。
# 探测源均为国际站点 (经隧道出网): 若混入国内源, sing-box 地理分流会将其
# 直连放行, 代理开启时就会把"国内直连出口"误标为"隧道出口"。
# 源1 cloudflare trace (ip=x), 源2 ip.sb 纯文本; 两者皆败则如实报不可测。
_EGRESS_TTL = 15.0
_EGRESS_TIMEOUT = 2.5
_egress_cache: dict = {"at": 0.0, "payload": None}
_egress_lock = threading.Lock()


def _parse_public_ip(text: str) -> Optional[str]:
    """从 echo 响应中提取首个公网 IP; 异常内容一律返回 None。"""
    import ipaddress

    for token in str(text or "").replace(",", " ").split():
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        if not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return token
    return None


def _egress_ip_cloudflare() -> Optional[str]:
    """源1: cloudflare trace, 形如 "ip=1.2.3.4"。
    用字面量 IPv4 地址而非域名: 双栈宿主上域名解析可能选 IPv6, 而 TProxy
    仅接管 IPv4, v6 直连会绕过隧道把家宽地址误报成隧道出口。1.1.1.1 的
    证书 SAN 覆盖该 IP, 直连校验不受影响。"""
    try:
        with urllib.request.urlopen(
            "https://1.1.1.1/cdn-cgi/trace", timeout=_EGRESS_TIMEOUT
        ) as resp:
            body = resp.read(2048).decode("utf-8", "ignore")
    except Exception:
        return None
    for line in body.splitlines():
        if line.startswith("ip="):
            return _parse_public_ip(line.split("=", 1)[1])
    return None


def _egress_ip_cloudflare_host() -> Optional[str]:
    """源2: cloudflare trace 域名形态 (1.1.1.1 被阻断时的回落; 双栈机上
    可能选 v6 直连, 仅作降级参考)。"""
    try:
        with urllib.request.urlopen(
            "https://www.cloudflare.com/cdn-cgi/trace", timeout=_EGRESS_TIMEOUT
        ) as resp:
            body = resp.read(2048).decode("utf-8", "ignore")
    except Exception:
        return None
    for line in body.splitlines():
        if line.startswith("ip="):
            return _parse_public_ip(line.split("=", 1)[1])
    return None


def _egress_ip_ipsb() -> Optional[str]:
    """源3: api.ip.sb 纯文本 IP (末级回落)。"""
    try:
        with urllib.request.urlopen("https://api.ip.sb/ip", timeout=_EGRESS_TIMEOUT) as resp:
            return _parse_public_ip(resp.read(256).decode("utf-8", "ignore"))
    except Exception:
        return None


def _egress_probe() -> dict:
    proxy_active = is_proxy_active()
    for provider in (_egress_ip_cloudflare, _egress_ip_cloudflare_host, _egress_ip_ipsb):
        ip = provider()
        if ip:
            return {
                "ok": True, "ip": ip,
                "proxy_active": proxy_active,
                "via": "tunnel" if proxy_active else "direct",
            }
    detail = "出口探测失败: 各探测源均不可达"
    if proxy_active:
        detail += " (代理已接管但出口不通, 检查节点可达性与 sing-box 进程)"
    return {"ok": False, "ip": None, "proxy_active": proxy_active, "via": None, "detail": detail}


@app.get("/api/egress")
def get_egress_ip():
    """实测当前出口公网 IP (15s 缓存; 探测本身走真实路径, 结果即所见即所得)。"""
    with _egress_lock:
        now = time.monotonic()
        if _egress_cache["payload"] and now - _egress_cache["at"] < _EGRESS_TTL:
            return {"status": "success", **_egress_cache["payload"]}
        payload = _egress_probe()
        _egress_cache["at"] = now
        _egress_cache["payload"] = payload
    return {"status": "success", **payload}


# 静态控制台挂载必须放在所有 API 路由之后
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="console")


# ---------------- 启动入口 ----------------
def main() -> None:
    web_host = os.environ.get("WEB_HOST", "0.0.0.0")
    web_port = int(os.environ.get("WEB_PORT", "8080"))

    # 启动恢复: 状态文件存在则归一化并生成配置; 无活跃节点时不写坏配置
    if STATE_FILE.exists():
        try:
            data = _load_state_dict()
            state = StateModel.model_validate(data)
            if _resolve_active_node(state) is None:
                log.info("startup: no active node, waiting for node activation")
            else:
                atomic_write_json(SINGBOX_CONFIG_FILE, build_singbox_config(state), mode=0o640, gid=SINGBOX_GID)
                ok, output = run_singbox_check()
                singbox_manager.mark_config(ok)
                if ok:
                    singbox_manager.start()
                    log.info("startup: sing-box restored from saved state")
                else:
                    log.warning("startup: singbox.json check failed, sing-box not started: %s", output)
        except Exception as exc:
            log.warning("startup: restore failed (%s), waiting for /api/apply", exc)
    else:
        log.info("startup: no state file, waiting for /api/apply")

    # 内核层中国 IP 直连集: 容器特权直写宿主内核, 无需宿主机安装任何组件
    sync_chnroute_ipset()

    # 优雅退出: uvicorn 接管信号前兜底; 接管后由 atexit 收尾
    def _handle_signal(signum, _frame):
        singbox_manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_signal)

    # 规则守护线程: 兜底任何意外清除的 TProxy 规则 (期望态见 last_decision)
    threading.Thread(target=rule_guard_loop, name="rule-guard", daemon=True).start()
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("WebUI listening on %s:%d", web_host, web_port)
    uvicorn.run(app, host=web_host, port=web_port, log_level="info")


if __name__ == "__main__":
    main()

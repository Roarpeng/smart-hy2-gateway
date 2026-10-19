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
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Literal, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
log = logging.getLogger("hy2-gateway")

app = FastAPI(title="Smart Hysteria 2 Gateway Daemon", version=APP_VERSION)


# ---------------- 数据模型 (pydantic v2) ----------------
class Hy2NodeModel(BaseModel):
    """Hysteria 2 出站节点参数。"""

    tag: str = "hy2-out"
    server: str = Field(min_length=1)
    port: int = Field(default=443, ge=1, le=65535)
    password: str = Field(min_length=1)
    sni: str = ""
    insecure: bool = False
    obfs_type: str = ""      # 为空表示无混淆; 有值时通常为 salamander
    obfs_password: str = ""
    # 带宽仅显式指定时写入配置; None = 缺省 -> BBR 自适应 (v2rayN 导入语义)
    up_mbps: Optional[int] = Field(default=None, ge=0)
    down_mbps: Optional[int] = Field(default=None, ge=0)
    # v2rayN 的 mport/ports 参数 -> sing-box 端口跳跃, 如 "20000-30000" 或 "443,8443"
    port_hopping: str = ""


class StateModel(BaseModel):
    """状态文件 schema (GET/POST /api/state 共用)。"""

    whitelist: list[str]
    current_node: Hy2NodeModel
    wifi_iface: str = "wlp2s0"
    rj45_iface: str = "enp3s0"
    vmnet_iface: str = "vmnet8"
    vmnet_subnet: str = "192.168.100.0/24"
    # Wi-Fi 通道策略 (顶层, 双通道模型):
    #   whitelist     = 默认走代理, 白名单 SSID 例外直连
    #   always_proxy  = 强制代理 (忽略白名单)
    #   always_direct = 强制直连
    wifi_policy: Literal["whitelist", "always_proxy", "always_direct"] = "whitelist"
    tproxy_port: int = Field(default=12345, ge=1, le=65535)
    fwmark: int = 1
    table: int = 100


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
        # 容器内以 root 运行: 授权 singbox 组读取 (sing-box 以 UID 930 运行)
        os.chown(tmp, 0, gid)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def build_singbox_config(state: StateModel) -> dict:
    """按状态生成 sing-box 1.10.x (legacy DNS schema) 运行配置。"""
    node = state.current_node
    hy2_outbound = {
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
        hy2_outbound["obfs"] = {"type": node.obfs_type, "password": node.obfs_password}
    # 带宽仅显式指定时写入: 缺省 = BBR (v2rayN 语义: 链接不带 upmbps/downmbps 即不指定)
    if node.up_mbps:
        hy2_outbound["up_mbps"] = node.up_mbps
    if node.down_mbps:
        hy2_outbound["down_mbps"] = node.down_mbps
    if node.port_hopping:
        # v2rayN mport/ports -> sing-box 端口跳跃
        hy2_outbound["port_hopping"] = node.port_hopping
        hy2_outbound["port_hopping_interval"] = "30s"

    return {
        "log": {"level": "info", "timestamp": True},
        # DNS 拆分: 国内域名用国内 DNS (CDN 调度友好), 其余经隧道解析 (防污染)
        "dns": {
            "servers": [
                {"tag": "cn-dns", "address": "udp://223.5.5.5", "detour": "direct"},
                {"tag": "proxy-dns", "address": "udp://1.1.1.1", "detour": node.tag},
            ],
            "rules": [
                {"rule_set": ["geosite-cn"], "server": "cn-dns"},
                {"outbound": "any", "server": "cn-dns"},   # sing-box 自身解析(节点域名/直连出站)走直连
            ],
            "final": "proxy-dns",
        },
        "inbounds": [
            {
                "type": "tproxy",
                "tag": "tproxy-in",
                "listen": "::",                 # 双栈监听, 端口由状态文件驱动
                "listen_port": state.tproxy_port,
                "sniff": True,
            }
        ],
        "outbounds": [hy2_outbound, {"type": "direct", "tag": "direct"}],
        # 地理分流 (v2rayN 式"绕过大陆"): 中国域名/IP 直连, 其余走 Hysteria 2 隧道;
        # 规则集为镜像内置本地文件, 运行时零下载依赖
        "route": {
            "auto_detect_interface": True,
            "rules": [
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
    """尽力获取当前 Wi-Fi SSID; 容器内无 nmcli 或查询失败一律返回 None。"""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            capture_output=True, text=True, timeout=5,
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


# ---------------- API 路由 (先于静态挂载注册) ----------------
@app.get("/api/state")
def get_state():
    """返回状态文件完整内容; 未初始化时给出标记。"""
    if not STATE_FILE.exists():
        return {"status": "uninitialized"}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"state file corrupted: {exc}")


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


@app.post("/api/apply")
def apply_state(state: StateModel):
    """保存状态 -> 渲染新配置 -> check 校验 -> 通过后才落盘并重启 sing-box。"""
    # 1) 原子落盘状态文件 (含密码 -> 600)
    atomic_write_json(STATE_FILE, state.model_dump(), mode=0o600)
    # 2) 渲染到 .new 临时文件并校验; 失败时磁盘保留旧配置,
    #    运行中的 sing-box 与崩溃自愈能力均不受影响
    config = build_singbox_config(state)
    tmp_config = SINGBOX_CONFIG_FILE.with_name(SINGBOX_CONFIG_FILE.name + ".new")
    atomic_write_json(tmp_config, config, mode=0o640, gid=SINGBOX_GID)
    ok, output = run_singbox_check(tmp_config)
    if not ok:
        tmp_config.unlink(missing_ok=True)
        log.error("sing-box check failed: %s", output)
        raise HTTPException(status_code=422, detail=f"sing-box check failed: {output}")
    # 3) 校验通过: 替换正式配置 (sing-box 以 GID 930 运行 -> 640 root:singbox) 并重启
    os.replace(tmp_config, SINGBOX_CONFIG_FILE)
    singbox_manager.mark_config(True)
    started = singbox_manager.restart()
    message = (
        "State saved, singbox config valid, sing-box restarted."
        if started else
        "State saved, singbox config valid, but sing-box failed to start; see logs."
    )
    return {"status": "success", "message": message, "singbox_valid": True}


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

    # 4-5: 当前节点可达性
    node = None
    try:
        node = json.loads(STATE_FILE.read_text(encoding="utf-8")).get("current_node") or {}
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


# 静态控制台挂载必须放在所有 API 路由之后
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="console")


# ---------------- 启动入口 ----------------
def main() -> None:
    web_host = os.environ.get("WEB_HOST", "0.0.0.0")
    web_port = int(os.environ.get("WEB_PORT", "8080"))

    # 启动恢复: 状态文件存在则生成配置并拉起 sing-box; 不存在则仅等待 /api/apply
    if STATE_FILE.exists():
        try:
            state = StateModel.model_validate_json(STATE_FILE.read_text(encoding="utf-8"))
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

    # 优雅退出: uvicorn 接管信号前兜底; 接管后由 atexit 收尾
    def _handle_signal(signum, _frame):
        singbox_manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("WebUI listening on %s:%d", web_host, web_port)
    uvicorn.run(app, host=web_host, port=web_port, log_level="info")


if __name__ == "__main__":
    main()

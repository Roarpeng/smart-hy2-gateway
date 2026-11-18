"""v2rayN 式节点链接解析器 (独立模块, 无第三方依赖)。

职责:
  1. 解析 hy2/hysteria2/vless/trojan/ss 分享链接 (v2rayN 语义)
  2. 解析多行链接、base64 订阅、sing-box JSON (完整配置/单 outbound/数组)
  3. 安全抓取远程订阅 (仅公网 http/https, 防 SSRF)
  4. 节点指纹 / 标签清洗 / 端口跳跃规范化

安全约定:
  - 本模块不记录、不回显节点密码; 报错信息只描述原因
  - parse_import_text 返回的 errors.input 已脱敏
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import time
import urllib.parse
from typing import Any, Optional

# ---------------- 冻结常量 ----------------
DEFAULT_PORT = 443
RESERVED_TAGS = {
    "direct",
    "proxy-dns",
    "cn-dns",
    "direct-dns",
    "tproxy-in",
    "diag-in",
    "dns-out",
    "auto-out",
    "geosite-cn",
    "geoip-cn",
    "block",
}

MAX_TAG_LEN = 64
FALLBACK_TAG = "hy2-node"
USER_AGENT = "v2rayN/6.60"

# 链接/订阅解析时允许的 scheme
_SCHEMES = ("hy2://", "hysteria2://", "vless://", "trojan://", "ss://")
_JSON_TYPES = frozenset({"hysteria2", "vless", "trojan", "shadowsocks"})

# 脱敏正则: 链接 userinfo / JSON password / query 中的敏感参数
_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s?#]*@")
_PASSWORD_JSON_RE = re.compile(r'(?i)("(?:password|uuid|obfs[-_]?password)"\s*:\s*")[^"]*(")')
_PASSWORD_QUERY_RE = re.compile(r"(?i)((?:auth|password|uuid|obfs[-_]?password|pbk)=)[^&\s#]+")
# 首尾空白与控制字符 (标签清洗)
_TAG_EDGE_RE = re.compile(r"^[\s\x00-\x1f\x7f]+|[\s\x00-\x1f\x7f]+$")
_PROXIES_RE = re.compile(r"(?im)^\s*proxies\s*:")
_POS_INT_RE = re.compile(r"^\d+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")

CLASH_ERROR = "暂不支持 Clash 配置，请使用 v2rayN 分享链接或 base64 订阅"


# ---------------- 基础工具 ----------------
def node_fingerprint(node: dict) -> str:
    """节点内容指纹 (protocol/server/port/auth), 用于导入去重。"""
    protocol = str(node.get("protocol") or "hysteria2").strip().lower() or "hysteria2"
    server = str(node.get("server") or "")
    port = node.get("port")
    if port in (None, ""):
        port = DEFAULT_PORT
    password = str(node.get("password") or node.get("uuid") or "")

    if protocol == "shadowsocks":
        method = str(node.get("method") or node.get("obfs_type") or "")
        plugin = str(node.get("plugin") or "")
        raw = f"{protocol}|{server}|{port}|{password}|{method}|{plugin}"
    elif protocol == "vless":
        flow = str(node.get("flow") or "")
        transport = str(node.get("transport") or "")
        reality_pk = str(node.get("reality_public_key") or "")
        raw = f"{protocol}|{server}|{port}|{password}|{flow}|{transport}|{reality_pk}"
    elif protocol == "trojan":
        transport = str(node.get("transport") or "")
        sni = str(node.get("sni") or "")
        raw = f"{protocol}|{server}|{port}|{password}|{transport}|{sni}"
    else:
        # hysteria2 (缺省 protocol 按 hysteria2 处理, 保持与旧节点兼容)
        obfs_type = str(node.get("obfs_type") or "")
        obfs_password = str(node.get("obfs_password") or "")
        port_hopping = str(node.get("port_hopping") or "")
        raw = f"{protocol}|{server}|{port}|{password}|{obfs_type}|{obfs_password}"
        if port_hopping:
            raw += f"|{port_hopping}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sanitize_tag(tag: str, existing_tags: Optional[set[str]] = None) -> str:
    """清洗出站标签: 去首尾空白/控制字符, 限长 64, 避开保留标签与重名。"""
    text = _TAG_EDGE_RE.sub("", str(tag or ""))
    if not text:
        text = FALLBACK_TAG
    text = text[:MAX_TAG_LEN]
    if text in RESERVED_TAGS:
        text = (text + "-node")[:MAX_TAG_LEN]
    used = {str(t) for t in (existing_tags or set())}
    if text not in used:
        return text
    idx = 2
    while True:
        suffix = f"-{idx}"
        candidate = text[: MAX_TAG_LEN - len(suffix)] + suffix
        if candidate not in used:
            return candidate
        idx += 1


def normalize_port_hopping(raw: str) -> str:
    """端口跳跃规范化: 20000-30000 -> 20000:30000; 443,8443 -> 443:443,8443:8443。"""
    text = str(raw or "").strip()
    if not text:
        return ""
    parts: list[str] = []
    for chunk in text.split(","):
        seg = chunk.strip()
        if not seg:
            raise ValueError("端口跳跃格式非法: 存在空段")
        normalized = seg.replace("-", ":")
        pieces = normalized.split(":")
        if len(pieces) > 2:
            raise ValueError("端口跳跃格式非法: 单段只支持 端口 或 起:止")
        for piece in pieces:
            if not _POS_INT_RE.match(piece.strip()):
                raise ValueError("端口跳跃格式非法: 端口必须是数字")
        if len(pieces) == 1:
            start = end = int(pieces[0].strip())
        else:
            start = int(pieces[0].strip())
            end = int(pieces[1].strip())
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError("端口跳跃端口超出范围 1..65535")
        if start > end:
            raise ValueError("端口跳跃起始端口不能大于结束端口")
        parts.append(f"{start}:{end}")
    return ",".join(parts)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _first_query(q: dict[str, str], keys: tuple[str, ...]) -> Optional[str]:
    for key in keys:
        if key in q and str(q[key]).strip():
            return str(q[key])
    return None


def _query_dict(query: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        key = key.strip().lower()
        if key and key not in out:
            out[key] = value
    return out


def _valid_server(server: str) -> str:
    server = str(server or "").strip()
    if not server:
        raise ValueError("服务器地址不能为空")
    if any(ch.isspace() for ch in server) or "/" in server:
        raise ValueError("服务器地址格式非法")
    return server


def _positive_bw(value: Any, label: str) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if not _POS_INT_RE.match(text):
        raise ValueError(f"{label} 必须是正整数")
    number = int(text)
    if number <= 0:
        raise ValueError(f"{label} 必须是正整数")
    return number


def _redact_input(text: str) -> str:
    """错误回显脱敏: 只保留结构, 不泄露密码。"""
    safe = _USERINFO_RE.sub(r"\1***@", str(text or ""))
    safe = _PASSWORD_JSON_RE.sub(r"\1***\2", safe)
    safe = _PASSWORD_QUERY_RE.sub(r"\1***", safe)
    return safe[:500]


# ---------------- 分享链接 ----------------
def _split_link_parts(raw: str) -> tuple[str, str, str]:
    """拆出 scheme 后的 userinfo / hostport / tail(?query#frag)。"""
    scheme_end = raw.index("://") + 3
    rest = raw[scheme_end:]
    boundary = len(rest)
    for sep in ("/", "?", "#"):
        pos = rest.find(sep)
        if pos >= 0:
            boundary = min(boundary, pos)
    authority = rest[:boundary]
    tail = rest[boundary:]
    if "@" in authority:
        userinfo_raw, hostport = authority.rsplit("@", 1)
    else:
        userinfo_raw, hostport = "", authority
    return userinfo_raw, hostport, tail


def _parse_hostport_tail(hostport: str, tail: str, scheme: str = "https") -> tuple[str, int, dict[str, str], str]:
    """解析 host:port + query/fragment, 返回 (server, port, query, tag)。"""
    if not hostport:
        raise ValueError("缺少服务器地址")
    try:
        split = urllib.parse.urlsplit(f"{scheme}://" + hostport + tail)
    except ValueError as exc:
        raise ValueError(f"链接格式非法: {exc}") from exc

    server = _valid_server(split.hostname or "")
    try:
        port = split.port
    except ValueError as exc:
        raise ValueError("端口非法") from exc
    if port is None:
        port = DEFAULT_PORT
    if not (1 <= port <= 65535):
        raise ValueError("端口超出范围 1..65535")

    query = _query_dict(split.query)
    tag = urllib.parse.unquote(split.fragment).strip()
    if not tag:
        tag = (query.get("remarks") or query.get("remark") or query.get("tag") or "").strip()
    if not tag:
        tag = f"{server}:{port}"
    return server, port, query, tag


def _b64_decode_bytes(text: str) -> bytes:
    compact = re.sub(r"\s+", "", str(text or ""))
    if not compact:
        raise ValueError("base64 内容为空")
    candidate = compact.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(candidate, validate=False)
    except Exception as exc:
        raise ValueError("base64 解码失败") from exc


def _b64_decode_text(text: str) -> str:
    try:
        return _b64_decode_bytes(text).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("base64 内容不是合法 UTF-8") from exc


def _normalize_transport(raw: Optional[str]) -> str:
    value = str(raw or "tcp").strip().lower()
    aliases = {
        "": "tcp",
        "tcp": "tcp",
        "ws": "ws",
        "websocket": "ws",
        "http": "http",
        "h2": "http",
        "grpc": "grpc",
        "httpupgrade": "httpupgrade",
        "http_upgrade": "httpupgrade",
    }
    if value not in aliases:
        raise ValueError(f"不支持的传输类型: {value}")
    return aliases[value]


def _tls_flags_from_security(security: str) -> tuple[bool, bool]:
    sec = str(security or "").strip().lower()
    if sec in ("", "none", "0", "false"):
        return False, False
    if sec == "reality":
        return True, True
    # tls / xtls / 其它显式安全层
    return True, False


def _parse_hy2_link(raw: str, source: str) -> dict:
    """解析 hy2/hysteria2。userinfo 整体即认证串, 不做 username/password 拆分。"""
    userinfo_raw, hostport, tail = _split_link_parts(raw)
    server, port, query, tag = _parse_hostport_tail(hostport, tail, scheme="hysteria2")

    password = urllib.parse.unquote(userinfo_raw)
    if not password.strip():
        password = query.get("auth", "")
    if not str(password).strip():
        raise ValueError("缺少密码")

    sni = _first_query(query, ("sni", "peer", "server_name", "servername")) or ""
    insecure = _truthy(
        _first_query(query, ("insecure", "allowinsecure", "allow_insecure", "skip-cert-verify")) or ""
    )

    obfs_raw = (query.get("obfs") or "").strip().lower()
    if obfs_raw not in ("", "salamander"):
        raise ValueError("不支持的混淆类型 (仅支持 salamander)")
    obfs_password = _first_query(query, ("obfs-password", "obfs_password", "obfspassword")) or ""
    if obfs_raw and not obfs_password.strip():
        raise ValueError("启用混淆时必须提供混淆口令")

    up_mbps = _positive_bw(_first_query(query, ("upmbps", "up")), "上行带宽")
    down_mbps = _positive_bw(_first_query(query, ("downmbps", "down")), "下行带宽")
    hopping_raw = _first_query(query, ("mport", "ports", "port-hopping", "port_hopping")) or ""
    port_hopping = normalize_port_hopping(hopping_raw)

    return {
        "protocol": "hysteria2",
        "tag": tag,
        "server": server,
        "port": port,
        "password": str(password),
        "sni": sni.strip(),
        "insecure": insecure,
        "obfs_type": obfs_raw,
        "obfs_password": str(obfs_password),
        "up_mbps": up_mbps,
        "down_mbps": down_mbps,
        "port_hopping": port_hopping,
        "source": source,
    }


def _parse_vless_link(raw: str, source: str) -> dict:
    userinfo_raw, hostport, tail = _split_link_parts(raw)
    server, port, query, tag = _parse_hostport_tail(hostport, tail, scheme="vless")

    uuid = urllib.parse.unquote(userinfo_raw).strip()
    if not uuid:
        uuid = (query.get("uuid") or "").strip()
    if not uuid:
        raise ValueError("缺少 UUID")

    security = (_first_query(query, ("security", "tls")) or "").strip().lower()
    tls_enabled, reality_enabled = _tls_flags_from_security(security)
    transport = _normalize_transport(_first_query(query, ("type", "network", "transport")))

    encryption = (_first_query(query, ("encryption",)) or "none").strip() or "none"
    flow = (_first_query(query, ("flow",)) or "").strip()
    packet_encoding = (_first_query(query, ("packetencoding", "packet_encoding")) or "").strip()
    sni = (_first_query(query, ("sni", "peer", "servername", "server_name")) or "").strip()
    insecure = _truthy(
        _first_query(query, ("insecure", "allowinsecure", "allow_insecure", "skip-cert-verify")) or ""
    )
    fingerprint = (_first_query(query, ("fp", "fingerprint")) or "").strip()
    public_key = (_first_query(query, ("pbk", "publickey", "public_key")) or "").strip()
    short_id = (_first_query(query, ("sid", "shortid", "short_id")) or "").strip()
    spider_x = (_first_query(query, ("spx", "spiderx", "spider_x")) or "").strip()
    path = (_first_query(query, ("path",)) or "").strip()
    host = (_first_query(query, ("host", "authority")) or "").strip()
    service_name = (_first_query(query, ("servicename", "service_name")) or "").strip()

    if reality_enabled and not public_key:
        raise ValueError("Reality 缺少公钥 (pbk)")

    return {
        "protocol": "vless",
        "tag": tag,
        "server": server,
        "port": port,
        "password": uuid,
        "uuid": uuid,
        "flow": flow,
        "encryption": encryption,
        "packet_encoding": packet_encoding,
        "transport": transport,
        "transport_path": path,
        "transport_host": host,
        "transport_service_name": service_name,
        "tls_enabled": tls_enabled,
        "reality_enabled": reality_enabled,
        "reality_public_key": public_key,
        "reality_short_id": short_id,
        "spider_x": spider_x,
        "utls_fingerprint": fingerprint,
        "sni": sni,
        "insecure": insecure,
        "source": source,
    }


def _parse_trojan_link(raw: str, source: str) -> dict:
    userinfo_raw, hostport, tail = _split_link_parts(raw)
    server, port, query, tag = _parse_hostport_tail(hostport, tail, scheme="trojan")

    password = urllib.parse.unquote(userinfo_raw)
    if not str(password).strip():
        password = query.get("password", "")
    if not str(password).strip():
        raise ValueError("缺少密码")

    transport = _normalize_transport(_first_query(query, ("type", "network", "transport")))
    sni = (_first_query(query, ("sni", "peer", "servername", "server_name")) or "").strip()
    insecure = _truthy(
        _first_query(query, ("insecure", "allowinsecure", "allow_insecure", "skip-cert-verify")) or ""
    )
    path = (_first_query(query, ("path",)) or "").strip()
    host = (_first_query(query, ("host", "authority")) or "").strip()

    return {
        "protocol": "trojan",
        "tag": tag,
        "server": server,
        "port": port,
        "password": str(password),
        "sni": sni,
        "insecure": insecure,
        "transport": transport,
        "transport_path": path,
        "transport_host": host,
        "tls_enabled": True,
        "reality_enabled": False,
        "source": source,
    }


def _parse_ss_link(raw: str, source: str) -> dict:
    """解析 ss:// SIP002 或 legacy base64 分享链接。"""
    scheme_end = raw.index("://") + 3
    rest = raw[scheme_end:]

    tag = ""
    if "#" in rest:
        rest, frag = rest.rsplit("#", 1)
        tag = urllib.parse.unquote(frag).strip()

    query: dict[str, str] = {}
    if "?" in rest:
        rest, qpart = rest.split("?", 1)
        query = _query_dict(qpart)

    method = ""
    password = ""
    server = ""
    port = DEFAULT_PORT

    if "@" in rest:
        # SIP002: base64(method:password)@host:port  或  method:password@host:port
        userinfo_raw, hostport = rest.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo_raw)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            decoded = _b64_decode_text(userinfo)
            if ":" not in decoded:
                raise ValueError("SS 用户信息缺少 method:password")
            method, password = decoded.split(":", 1)
        server, port, _, default_tag = _parse_hostport_tail(hostport, "", scheme="ss")
        if not tag:
            tag = default_tag
    else:
        # legacy: base64(method:password@host:port)
        decoded = _b64_decode_text(rest)
        if "@" not in decoded:
            raise ValueError("SS legacy 链接缺少 @host:port")
        userinfo, hostport = decoded.rsplit("@", 1)
        if ":" not in userinfo:
            raise ValueError("SS 用户信息缺少 method:password")
        method, password = userinfo.split(":", 1)
        hostport = hostport.split("/")[0].split("?")[0]
        server, port, _, default_tag = _parse_hostport_tail(hostport, "", scheme="ss")
        if not tag:
            tag = default_tag

    method = str(method).strip()
    password = str(password)
    if not method:
        raise ValueError("缺少加密方法")
    if not password:
        raise ValueError("缺少密码")

    plugin = (query.get("plugin") or "").strip()
    plugin_opts = ""
    if plugin and ";" in plugin:
        plugin, plugin_opts = plugin.split(";", 1)

    return {
        "protocol": "shadowsocks",
        "tag": tag or f"{server}:{port}",
        "server": server,
        "port": port,
        "password": password,
        "method": method,
        "obfs_type": "",
        "plugin": plugin,
        "plugin_opts": plugin_opts,
        "source": source,
    }


def parse_share_link(line: str, source: str = "clipboard") -> dict:
    """解析单条 hy2/vless/trojan/ss 分享链接为节点字典。"""
    raw = str(line or "").strip()
    if not raw:
        raise ValueError("链接为空")
    lower = raw.lower()
    if not lower.startswith(_SCHEMES):
        raise ValueError("不支持的分享链接 (仅 hy2/hysteria2/vless/trojan/ss)")

    if lower.startswith(("hy2://", "hysteria2://")):
        return _parse_hy2_link(raw, source)
    if lower.startswith("vless://"):
        return _parse_vless_link(raw, source)
    if lower.startswith("trojan://"):
        return _parse_trojan_link(raw, source)
    if lower.startswith("ss://"):
        return _parse_ss_link(raw, source)
    raise ValueError("不支持的分享链接")


# ---------------- sing-box JSON ----------------
def _json_port_hopping(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (list, tuple)):
        raw = ",".join(str(v) for v in value)
    else:
        raw = str(value)
    return normalize_port_hopping(raw)


def _json_bandwidth(value: Any, label: str) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} 非法") from exc
    if number < 0:
        raise ValueError(f"{label} 非法")
    return number if number > 0 else None


def _json_server_port(obj: dict) -> tuple[str, int]:
    server = _valid_server(str(obj.get("server") or ""))
    raw_port = obj.get("server_port", obj.get("port", DEFAULT_PORT))
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise ValueError("端口非法") from exc
    if not (1 <= port <= 65535):
        raise ValueError("端口超出范围 1..65535")
    return server, port


def _json_tls_fields(obj: dict) -> dict[str, Any]:
    tls = obj.get("tls") if isinstance(obj.get("tls"), dict) else {}
    sni = str(tls.get("server_name") or tls.get("sni") or "").strip()
    insecure = _truthy(tls.get("insecure", False))
    tls_enabled = bool(tls) and _truthy(tls.get("enabled", True))

    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    reality_enabled = bool(reality) and _truthy(reality.get("enabled", True))
    reality_public_key = str(reality.get("public_key") or "").strip()
    reality_short_id = str(reality.get("short_id") or "").strip()

    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    fingerprint = str(utls.get("fingerprint") or "").strip()

    return {
        "sni": sni,
        "insecure": insecure,
        "tls_enabled": tls_enabled,
        "reality_enabled": reality_enabled,
        "reality_public_key": reality_public_key,
        "reality_short_id": reality_short_id,
        "utls_fingerprint": fingerprint,
    }


def _json_transport_fields(obj: dict) -> dict[str, str]:
    transport_obj = obj.get("transport") if isinstance(obj.get("transport"), dict) else {}
    if not transport_obj:
        return {
            "transport": "tcp",
            "transport_path": "",
            "transport_host": "",
            "transport_service_name": "",
        }
    ttype = _normalize_transport(str(transport_obj.get("type") or "tcp"))
    path = str(transport_obj.get("path") or "").strip()
    headers = transport_obj.get("headers") if isinstance(transport_obj.get("headers"), dict) else {}
    host_raw = transport_obj.get("host") or headers.get("Host") or headers.get("host") or ""
    if isinstance(host_raw, (list, tuple)):
        host = str(host_raw[0]).strip() if host_raw else ""
    else:
        host = str(host_raw).strip()
    service_name = str(transport_obj.get("service_name") or "").strip()
    return {
        "transport": ttype,
        "transport_path": path,
        "transport_host": host,
        "transport_service_name": service_name,
    }


def _node_from_hy2_json(obj: dict, source: str) -> dict:
    server, port = _json_server_port(obj)
    password = str(obj.get("password") or "")
    if not password.strip():
        raise ValueError("缺少密码")

    tls = _json_tls_fields(obj)
    obfs = obj.get("obfs") if isinstance(obj.get("obfs"), dict) else {}
    obfs_type = str(obfs.get("type") or "").strip().lower()
    if obfs_type not in ("", "salamander"):
        raise ValueError("不支持的混淆类型 (仅支持 salamander)")
    obfs_password = str(obfs.get("password") or "")
    if obfs_type and not obfs_password.strip():
        raise ValueError("启用混淆时必须提供混淆口令")

    return {
        "protocol": "hysteria2",
        "tag": str(obj.get("tag") or "").strip() or f"{server}:{port}",
        "server": server,
        "port": port,
        "password": password,
        "sni": tls["sni"],
        "insecure": tls["insecure"],
        "obfs_type": obfs_type,
        "obfs_password": obfs_password,
        "up_mbps": _json_bandwidth(obj.get("up_mbps"), "up_mbps"),
        "down_mbps": _json_bandwidth(obj.get("down_mbps"), "down_mbps"),
        "port_hopping": _json_port_hopping(obj.get("server_ports", obj.get("port_hopping"))),
        "source": source,
    }


def _node_from_vless_json(obj: dict, source: str) -> dict:
    server, port = _json_server_port(obj)
    uuid = str(obj.get("uuid") or obj.get("password") or "").strip()
    if not uuid:
        raise ValueError("缺少 UUID")

    tls = _json_tls_fields(obj)
    transport = _json_transport_fields(obj)
    # 无 tls 块时, sing-box 默认不启 TLS; Reality 块则强制 TLS
    if not obj.get("tls"):
        tls["tls_enabled"] = False

    return {
        "protocol": "vless",
        "tag": str(obj.get("tag") or "").strip() or f"{server}:{port}",
        "server": server,
        "port": port,
        "password": uuid,
        "uuid": uuid,
        "flow": str(obj.get("flow") or "").strip(),
        "encryption": str(obj.get("encryption") or "none").strip() or "none",
        "packet_encoding": str(obj.get("packet_encoding") or "").strip(),
        "transport": transport["transport"],
        "transport_path": transport["transport_path"],
        "transport_host": transport["transport_host"],
        "transport_service_name": transport["transport_service_name"],
        "tls_enabled": tls["tls_enabled"],
        "reality_enabled": tls["reality_enabled"],
        "reality_public_key": tls["reality_public_key"],
        "reality_short_id": tls["reality_short_id"],
        "utls_fingerprint": tls["utls_fingerprint"],
        "sni": tls["sni"],
        "insecure": tls["insecure"],
        "source": source,
    }


def _node_from_trojan_json(obj: dict, source: str) -> dict:
    server, port = _json_server_port(obj)
    password = str(obj.get("password") or "")
    if not password.strip():
        raise ValueError("缺少密码")

    tls = _json_tls_fields(obj)
    transport = _json_transport_fields(obj)
    if not obj.get("tls"):
        # trojan 通常强制 TLS; 无块时仍标记启用, 与分享链接一致
        tls["tls_enabled"] = True

    return {
        "protocol": "trojan",
        "tag": str(obj.get("tag") or "").strip() or f"{server}:{port}",
        "server": server,
        "port": port,
        "password": password,
        "sni": tls["sni"],
        "insecure": tls["insecure"],
        "transport": transport["transport"],
        "transport_path": transport["transport_path"],
        "transport_host": transport["transport_host"],
        "tls_enabled": tls["tls_enabled"],
        "reality_enabled": tls["reality_enabled"],
        "source": source,
    }


def _node_from_ss_json(obj: dict, source: str) -> dict:
    server, port = _json_server_port(obj)
    password = str(obj.get("password") or "")
    if not password.strip():
        raise ValueError("缺少密码")
    method = str(obj.get("method") or "").strip()
    if not method:
        raise ValueError("缺少加密方法")

    return {
        "protocol": "shadowsocks",
        "tag": str(obj.get("tag") or "").strip() or f"{server}:{port}",
        "server": server,
        "port": port,
        "password": password,
        "method": method,
        "obfs_type": "",
        "plugin": str(obj.get("plugin") or "").strip(),
        "plugin_opts": str(obj.get("plugin_opts") or "").strip(),
        "source": source,
    }


def _node_from_json(obj: dict, source: str) -> dict:
    """把 sing-box outbound 映射为节点字典 (hy2/vless/trojan/ss)。"""
    if not isinstance(obj, dict):
        raise ValueError("JSON 节点必须是对象")
    typ = str(obj.get("type") or "").strip().lower()
    if typ not in _JSON_TYPES:
        raise ValueError(f"不支持的出站类型: {typ or '(空)'}")
    if typ == "hysteria2":
        return _node_from_hy2_json(obj, source)
    if typ == "vless":
        return _node_from_vless_json(obj, source)
    if typ == "trojan":
        return _node_from_trojan_json(obj, source)
    return _node_from_ss_json(obj, source)


def _extract_json_nodes(data: Any, source: str, raw_text: str) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    errors: list[dict] = []
    snippets = _redact_input(raw_text)

    if isinstance(data, dict) and isinstance(data.get("outbounds"), list):
        candidates = data["outbounds"]
    elif isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        candidates = [data]
    else:
        return [], [{"line": None, "input": snippets, "error": "JSON 根节点必须是对象或数组"}]

    for item in candidates:
        if not isinstance(item, dict):
            continue
        typ = str(item.get("type") or "").strip().lower()
        if typ not in _JSON_TYPES:
            continue  # 完整配置中的 direct/dns 等出站直接跳过
        try:
            nodes.append(_node_from_json(item, source))
        except ValueError as exc:
            errors.append({"line": None, "input": snippets, "error": str(exc)})

    if not nodes and not errors:
        errors.append({"line": None, "input": snippets, "error": "JSON 中未找到可导入节点"})
    return nodes, errors



# ---------------- 批量导入文本 ----------------
def _try_b64_decode(raw: str) -> Optional[str]:
    compact = re.sub(r"\s+", "", raw)
    if len(compact) < 8 or not _B64_RE.match(compact):
        return None
    candidate = compact.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        blob = base64.b64decode(candidate, validate=True)
    except Exception:
        return None
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    return text


def _is_clash_yaml(text: str) -> bool:
    return "://" not in text and bool(_PROXIES_RE.search(text))


def _dedup_nodes(nodes: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for node in nodes:
        fp = node_fingerprint(node)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(node)
    return out


def parse_import_text(text: str, source: str = "clipboard") -> tuple[list[dict], list[dict]]:
    """解析导入文本, 返回 (nodes, errors)。errors 中的 input 已脱敏。"""
    raw = str(text or "").replace("\ufeff", "").strip()
    if not raw:
        return [], [{"line": None, "input": "", "error": "导入内容为空"}]

    if _is_clash_yaml(raw):
        return [], [{"line": None, "input": _redact_input(raw), "error": CLASH_ERROR}]

    # 1) sing-box JSON
    if raw[0] in "[{":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            return [], [{
                "line": None, "input": _redact_input(raw),
                "error": f"JSON 解析失败: {exc.msg} (行 {exc.lineno})",
            }]
        nodes, errors = _extract_json_nodes(data, source, raw)
        return _dedup_nodes(nodes), errors

    # 2) 整段 base64 订阅
    decoded = _try_b64_decode(raw)
    if decoded is not None:
        stripped = decoded.strip()
        if _is_clash_yaml(stripped):
            return [], [{"line": None, "input": _redact_input(raw), "error": CLASH_ERROR}]
        if "://" in stripped or stripped.startswith(("{", "[")):
            return parse_import_text(stripped, source)

    # 3) 逐行分享链接
    nodes = []
    errors = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        item = line.strip()
        if not item:
            continue
        if item.startswith("#"):
            continue  # 纯注释行 (链接的 # 是 fragment, 只可能出现在行中)
        try:
            nodes.append(parse_share_link(item, source))
        except ValueError as exc:
            errors.append({"line": lineno, "input": _redact_input(item), "error": str(exc)})

    if not nodes and not errors:
        errors.append({"line": None, "input": _redact_input(raw), "error": "未找到有效的节点链接"})
    return _dedup_nodes(nodes), errors


# ---------------- 远程订阅抓取 ----------------
_NON_PUBLIC_NETS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
)
_STD_HTTP_CONNECTION = http.client.HTTPConnection
_STD_HTTPS_CONNECTION = http.client.HTTPSConnection


def _public_ip(ip_text: str) -> bool:
    text = str(ip_text or "").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if ip.version == 6:
        if getattr(ip, "is_site_local", False):
            return False
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False
    if ip.version == 4 and any(ip in net for net in _NON_PUBLIC_NETS):
        return False
    return True


def _resolve_public_ip(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"订阅域名解析失败: {host}") from exc
    if not infos:
        raise ValueError(f"订阅域名解析失败: {host}")
    first_ip = ""
    for info in infos:
        ip_text = info[4][0]
        if not _public_ip(ip_text):
            raise ValueError(f"订阅地址解析到非公网 IP，已拒绝: {ip_text}")
        if not first_ip:
            first_ip = ip_text
    return first_ip


def _assert_public_host(host: str, port: int) -> str:
    return _resolve_public_ip(host, port)


def _validate_subscription_url(url: str) -> tuple[str, urllib.parse.SplitResult, str]:
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("订阅地址仅支持 http/https")
    host = parts.hostname or ""
    if not host:
        raise ValueError("订阅地址缺少主机名")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("订阅地址端口非法") from exc
    pinned_ip = _assert_public_host(host, port) or host
    return scheme, parts, pinned_ip


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """绑定已校验公网 IP 的 HTTP 连接，防止 DNS Rebinding (TOCTOU)。"""

    def __init__(self, host: str, port: int, timeout: float, pinned_ip: str = "") -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip or host

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """绑定已校验公网 IP 的 HTTPS 连接，TCP 直连 pinned_ip，SNI 与证书校验保持原域名。"""

    def __init__(self, host: str, port: int, timeout: float, pinned_ip: str = "") -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip or host

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        server_hostname = self._tunnel_host if self._tunnel_host else self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


def _decode_body(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def fetch_subscription(url: str, timeout: float = 10.0, max_bytes: int = 2 * 1024 * 1024) -> str:
    """抓取远程订阅文本 (仅公网 http/https, 防 SSRF 与 DNS Rebinding, 限制大小)。"""
    current = str(url or "").strip()
    if not current:
        raise ValueError("订阅地址为空")

    deadline = time.monotonic() + max(1.0, float(timeout))
    redirects = 0
    while True:
        scheme, parts, pinned_ip = _validate_subscription_url(current)
        host = parts.hostname or ""
        default_port = 443 if scheme == "https" else 80
        port = parts.port or default_port
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("订阅抓取超时")

        host_fmt = f"[{host}]" if ":" in host else host
        host_header = host_fmt if port == default_port else f"{host_fmt}:{port}"
        if scheme == "https":
            if http.client.HTTPSConnection is _STD_HTTPS_CONNECTION:
                conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                    host, port, timeout=remaining, pinned_ip=pinned_ip
                )
            else:
                conn = http.client.HTTPSConnection(host, port, timeout=remaining)
        else:
            if http.client.HTTPConnection is _STD_HTTP_CONNECTION:
                conn = _PinnedHTTPConnection(
                    host, port, timeout=remaining, pinned_ip=pinned_ip
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=remaining)
        try:
            conn.request("GET", path, headers={
                "Host": host_header,
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "gzip",
            })
            resp = conn.getresponse()
            status = resp.status
            location = resp.getheader("Location") or ""
            if status in (301, 302, 303, 307, 308):
                if redirects >= 3:
                    raise ValueError("订阅重定向次数过多")
                if not location:
                    raise ValueError("订阅重定向缺少 Location")
                current = urllib.parse.urljoin(current, location)
                redirects += 1
                resp.read(64)
                continue
            if status != 200:
                raise ValueError(f"订阅服务器返回 HTTP {status}")

            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("订阅抓取超时")
                try:
                    conn.sock.settimeout(remaining)  # type: ignore[union-attr]
                except Exception:
                    pass
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"订阅内容超过 {max_bytes} 字节上限")
                chunks.append(chunk)
            raw = b"".join(chunks)

            encoding = (resp.getheader("Content-Encoding") or "").lower()
            if "gzip" in encoding or raw[:2] == b"\x1f\x8b":
                try:
                    raw = gzip.decompress(raw)
                except OSError as exc:
                    raise ValueError("订阅内容 gzip 解压失败") from exc
                if len(raw) > max_bytes:
                    raise ValueError(f"订阅内容超过 {max_bytes} 字节上限")
            return _decode_body(raw)
        finally:
            try:
                conn.close()
            except Exception:
                pass

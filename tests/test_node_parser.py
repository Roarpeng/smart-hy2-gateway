"""node_parser 公共契约单元测试。

刻意只依赖 node_parser 的公开接口，不导入其内部辅助函数；
所有用例均在本机完成，不发起真实网络请求。
运行：python3 -m unittest tests.test_node_parser -v
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import node_parser  # noqa: E402


class NodeParserTestCase(unittest.TestCase):
    NODE_KEYS = {
        "tag",
        "server",
        "port",
        "password",
        "sni",
        "insecure",
        "obfs_type",
        "obfs_password",
        "up_mbps",
        "down_mbps",
        "port_hopping",
        "source",
    }

    def _node(self, nodes, tag):
        for node in nodes:
            if node.get("tag") == tag:
                return node
        self.fail("未找到 tag=%r 的节点，实际 tags=%r" % (tag, [n.get("tag") for n in nodes]))

# 1. 基础 hy2 链接：全部字段
    def test_basic_hy2_link_all_fields(self):
        link = (
            "hy2://secret@node.example.com:8443"
            "?sni=cdn.example.com&insecure=1&obfs=salamander&obfs-password=obfspw"
            "&upmbps=50&downmbps=120#Tokyo-01"
        )
        node = node_parser.parse_share_link(link)

        self.assertTrue(self.NODE_KEYS.issubset(node.keys()), node.keys())
        self.assertEqual(node["protocol"], "hysteria2")
        self.assertEqual(node["tag"], "Tokyo-01")
        self.assertEqual(node["server"], "node.example.com")
        self.assertEqual(node["port"], 8443)
        self.assertEqual(node["password"], "secret")
        self.assertEqual(node["sni"], "cdn.example.com")
        self.assertIs(node["insecure"], True)
        self.assertEqual(node["obfs_type"], "salamander")
        self.assertEqual(node["obfs_password"], "obfspw")
        self.assertEqual(node["up_mbps"], 50)
        self.assertEqual(node["down_mbps"], 120)
        self.assertEqual(node["source"], "clipboard")

        node_web = node_parser.parse_share_link(link, source="web")
        self.assertEqual(node_web["source"], "web")


    # 2. hysteria2 协议名 + allowInsecure 别名 + 大小写不敏感
    def test_hysteria2_scheme_and_allow_insecure_alias(self):
        for scheme in ("hysteria2", "HYSTERIA2", "Hy2"):
            with self.subTest(scheme=scheme):
                link = "{}://allowpw@1.2.3.4:443?allowInsecure=1&sni=edge.example.com#alias".format(
                    scheme
                )
                node = node_parser.parse_share_link(link)
                self.assertEqual(node["server"], "1.2.3.4")
                self.assertEqual(node["port"], 443)
                self.assertEqual(node["password"], "allowpw")
                self.assertIs(node["insecure"], True)
                self.assertEqual(node["sni"], "edge.example.com")

    # 3. 未编码冒号口令必须整体保留
    def test_unencoded_colon_password_preserved(self):
        node = node_parser.parse_share_link("hy2://roar:pass@example.com:443#colon")
        self.assertEqual(node["password"], "roar:pass")

    # 4. percent-encoded 冒号口令
    def test_percent_encoded_colon_password(self):
        node = node_parser.parse_share_link("hy2://roar%3Apass@example.com:443#encoded-colon")
        self.assertEqual(node["password"], "roar:pass")

    # 5. IPv6 主机去方括号
    def test_ipv6_host_brackets_stripped(self):
        node = node_parser.parse_share_link("hy2://pw@[2001:db8::1]:8443#v6-node")
        self.assertEqual(node["server"], "2001:db8::1")
        self.assertEqual(node["port"], 8443)

    # 6. mport 端口跳跃归一化
    def test_port_hopping_normalization(self):
        cases = {
            "20000-30000": "20000:30000",
            "443,8443": "443:443,8443:8443",
        }
        for raw, expected in cases.items():
            with self.subTest(mport=raw):
                link = "hy2://pw@example.com:443?mport={}#hopping".format(raw)
                node = node_parser.parse_share_link(link)
                self.assertEqual(node["port_hopping"], expected)

    def test_invalid_port_hopping_raises(self):
        for raw in ("30000-20000", "abc", "20000-"):
            with self.subTest(mport=raw):
                link = "hy2://pw@example.com:443?mport={}#bad-hop".format(raw)
                with self.assertRaises(ValueError):
                    node_parser.parse_share_link(link)

    # 7. fragment / remarks 标签优先级
    def test_tag_priority_fragment_remarks(self):
        frag = node_parser.parse_share_link(
            "hy2://pw@example.com:443?remarks=ParamTag#FragTag"
        )
        self.assertEqual(frag["tag"], "FragTag")

        remarks = node_parser.parse_share_link("hy2://pw@example.com:443?remarks=RemarkTag")
        self.assertEqual(remarks["tag"], "RemarkTag")

        remark = node_parser.parse_share_link("hy2://pw@example.com:443?remark=SingularTag")
        self.assertEqual(remark["tag"], "SingularTag")

        tag_param = node_parser.parse_share_link("hy2://pw@example.com:443?tag=TagParam")
        self.assertEqual(tag_param["tag"], "TagParam")

    def test_tag_fallback_to_server_port(self):
        node = node_parser.parse_share_link("hy2://pw@example.com:443")
        self.assertEqual(node["tag"], "example.com:443")

    # 8. obfs 校验
    def test_obfs_requires_password(self):
        with self.assertRaises(ValueError):
            node_parser.parse_share_link(
                "hy2://pw@example.com:443?obfs=salamander#no-obfs-password"
            )

    def test_invalid_obfs_type_rejected(self):
        with self.assertRaises(ValueError):
            node_parser.parse_share_link(
                "hy2://pw@example.com:443?obfs=simple&obfs-password=op#bad-obfs"
            )

    # 9. 多行：空行/注释忽略，坏链接进入 errors 且 input 脱敏
    def test_multiline_import_with_comments_blank_and_bad_line(self):
        text = "\n".join(
            [
                "# 这是注释，应被忽略",
                "hy2://pw-a@a.example.com:443#Node-A",
                "",
                "hy2://supersecretpw@:443#broken-node",
                "hy2://pw-b@b.example.com:8443#Node-B",
            ]
        )
        nodes, errors = node_parser.parse_import_text(text)

        self.assertEqual([n["tag"] for n in nodes], ["Node-A", "Node-B"])
        self.assertEqual(len(errors), 1)

        err = errors[0]
        self.assertIn("line", err)
        self.assertIn("input", err)
        self.assertIn("error", err)
        self.assertIsInstance(err["line"], int)
        self.assertGreater(err["line"], 0)
        self.assertNotIn("supersecretpw", err["input"])
        self.assertTrue(err["error"])

    # 10. base64 订阅：标准 / URL-safe / 无 padding
    def test_base64_standard_padded(self):
        raw = b"hy2://pwb64@b64.example.com:8443#B64-Node"
        text = base64.b64encode(raw).decode("ascii")
        nodes, errors = node_parser.parse_import_text(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["server"], "b64.example.com")
        self.assertEqual(nodes[0]["password"], "pwb64")
        self.assertEqual(nodes[0]["tag"], "B64-Node")

    def test_base64_urlsafe(self):
        raw = b"hy2://pwb64@b64.example.com:8443#B64-URLSafe"
        text = base64.urlsafe_b64encode(raw).decode("ascii")
        nodes, errors = node_parser.parse_import_text(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["tag"], "B64-URLSafe")
        self.assertEqual(nodes[0]["server"], "b64.example.com")

    def test_base64_without_padding(self):
        raw = b"hy2://pwb64@b64.example.com:8443#B64-NoPad"
        text = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        nodes, errors = node_parser.parse_import_text(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["tag"], "B64-NoPad")
        self.assertEqual(nodes[0]["server"], "b64.example.com")

    # 11. sing-box JSON：完整配置
    def test_sing_box_full_config(self):
        config = {
            "log": {"level": "info"},
            "dns": {"servers": [{"address": "223.5.5.5"}]},
            "inbounds": [{"type": "tproxy", "listen": "::", "listen_port": 12345}],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "hysteria2",
                    "tag": "json-node",
                    "server": "hy.example.com",
                    "server_port": 8443,
                    "password": "jsonpw",
                    "up_mbps": 30,
                    "down_mbps": 60,
                    "tls": {
                        "enabled": True,
                        "server_name": "cdn.example.com",
                        "insecure": True,
                    },
                    "obfs": {"type": "salamander", "password": "json-obfs"},
                },
            ],
            "route": {"final": "json-node"},
        }
        nodes, errors = node_parser.parse_import_text(json.dumps(config))
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1, [n.get("tag") for n in nodes])

        node = nodes[0]
        self.assertEqual(node["tag"], "json-node")
        self.assertEqual(node["server"], "hy.example.com")
        self.assertEqual(node["port"], 8443)
        self.assertEqual(node["password"], "jsonpw")
        self.assertEqual(node["sni"], "cdn.example.com")
        self.assertIs(node["insecure"], True)
        self.assertEqual(node["obfs_type"], "salamander")
        self.assertEqual(node["obfs_password"], "json-obfs")
        self.assertEqual(node["up_mbps"], 30)
        self.assertEqual(node["down_mbps"], 60)

    def test_sing_box_server_ports_list(self):
        outbound = {
            "type": "hysteria2",
            "tag": "hop-node",
            "server": "hop.example.com",
            "server_port": 443,
            "server_ports": ["20000-30000", "8443-8443"],
            "hop_interval": "30s",
            "password": "hoppw",
            "tls": {"enabled": True, "server_name": "hop.example.com"},
        }
        nodes, errors = node_parser.parse_import_text(json.dumps(outbound))
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        # 内部统一为冒号格式, 与 sing-box 1.11 server_ports 的要求一致
        self.assertEqual(nodes[0]["port_hopping"], "20000:30000,8443:8443")

    def test_sing_box_single_outbound(self):
        outbound = {
            "type": "hysteria2",
            "tag": "single-node",
            "server": "single.example.com",
            "server_port": 443,
            "password": "singlepw",
            "tls": {"enabled": True, "server_name": "sni.example.com"},
        }
        nodes, errors = node_parser.parse_import_text(json.dumps(outbound))
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["tag"], "single-node")
        self.assertEqual(nodes[0]["server"], "single.example.com")
        self.assertEqual(nodes[0]["port"], 443)
        self.assertEqual(nodes[0]["password"], "singlepw")
        self.assertEqual(nodes[0]["sni"], "sni.example.com")

    # 12. Clash YAML 明确报错
    def test_clash_yaml_rejected(self):
        text = "\n".join(
            [
                "proxies:",
                "  - name: clash-node",
                "    type: hysteria2",
                "    server: clash.example.com",
                "    port: 443",
                "    password: clashpw",
            ]
        )
        nodes, errors = node_parser.parse_import_text(text)
        self.assertEqual(nodes, [])
        self.assertTrue(errors, "Clash YAML 应返回错误项")
        message = " ".join(str(e.get("error", "")) for e in errors).lower()
        self.assertTrue("clash" in message or "yaml" in message, message)

    # 13. 输入内去重
    def test_duplicate_nodes_deduplicated(self):
        duplicate = "hy2://dup-pw@dup.example.com:443#Dup-Node"
        text = "\n".join(
            [
                duplicate,
                duplicate,
                "hy2://other-pw@other.example.com:8443#Other-Node",
            ]
        )
        nodes, errors = node_parser.parse_import_text(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 2)
        self.assertEqual({n["tag"] for n in nodes}, {"Dup-Node", "Other-Node"})

    # 14. sanitize_tag：保留字与冲突后缀
    def test_sanitize_tag_reserved_and_conflict(self):
        reserved = "direct"
        sanitized = node_parser.sanitize_tag(reserved)
        self.assertTrue(sanitized)
        self.assertNotEqual(sanitized, reserved)
        self.assertNotIn(sanitized, node_parser.RESERVED_TAGS)

        sanitized = node_parser.sanitize_tag("node", {"node"})
        self.assertTrue(sanitized)
        self.assertNotEqual(sanitized, "node")
        self.assertNotIn(sanitized, {"node"})
        self.assertTrue(sanitized.lower().startswith("node"), sanitized)

    # 15. node_fingerprint 对关键字段敏感
    def test_node_fingerprint_sensitive(self):
        base = {
            "tag": "fp-node",
            "server": "fp.example.com",
            "port": 443,
            "password": "fp-pw",
            "sni": "fp-sni.example.com",
            "insecure": False,
            "obfs_type": "",
            "obfs_password": "",
            "up_mbps": 0,
            "down_mbps": 0,
            "port_hopping": "",
            "source": "clipboard",
        }
        # 缺省 protocol 与显式 hysteria2 指纹一致
        with_proto = dict(base)
        with_proto["protocol"] = "hysteria2"
        self.assertEqual(
            node_parser.node_fingerprint(dict(base)),
            node_parser.node_fingerprint(with_proto),
        )

        changes = {
            "server": "changed.example.com",
            "port": 8443,
            # 测试向量 (运行时拼接构造, 非任何真实凭据字面量)
            "password": "changed" + "-pw",
            "obfs_type": "salamander",
            "obfs_password": "changed" + "-obfs",
            "port_hopping": "20000:30000",
            "protocol": "vless",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = dict(base)
                changed[field] = value
                self.assertNotEqual(
                    node_parser.node_fingerprint(dict(base)),
                    node_parser.node_fingerprint(changed),
                )

    # 16. fetch_subscription：SSRF / 协议拒绝（不发起真实网络请求）
    def test_fetch_subscription_rejects_private_and_non_http(self):
        urls = [
            "http://127.0.0.1/sub",
            "http://192.168.1.1/sub",
            "http://10.0.0.1/sub",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/sub",
            "file:///etc/passwd",
            "ftp://example.com/sub",
        ]
        for url in urls:
            with self.subTest(url=url):
                with self.assertRaises((ValueError, RuntimeError), msg=url):
                    node_parser.fetch_subscription(url)

    # 17. vless Reality 分享链接
    def test_vless_reality_share_link(self):
        uuid = "11111111-2222-3333-4444-555555555555"
        link = (
            f"vless://{uuid}@v.example.com:443"
            "?encryption=none&flow=xtls-rprx-vision&security=reality"
            "&sni=www.example.com&fp=chrome&pbk=AbCdEfGh&sid=1a2b"
            "&type=tcp&spx=%2F#VLESS-R"
        )
        node = node_parser.parse_share_link(link)
        self.assertEqual(node["protocol"], "vless")
        self.assertEqual(node["tag"], "VLESS-R")
        self.assertEqual(node["server"], "v.example.com")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["password"], uuid)
        self.assertEqual(node["uuid"], uuid)
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["encryption"], "none")
        self.assertEqual(node["transport"], "tcp")
        self.assertIs(node["tls_enabled"], True)
        self.assertIs(node["reality_enabled"], True)
        self.assertEqual(node["reality_public_key"], "AbCdEfGh")
        self.assertEqual(node["reality_short_id"], "1a2b")
        self.assertEqual(node["utls_fingerprint"], "chrome")
        self.assertEqual(node["sni"], "www.example.com")
        self.assertEqual(node["spider_x"], "/")

    def test_vless_ws_tls_share_link(self):
        uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        link = (
            f"vless://{uuid}@ws.example.com:8443"
            "?encryption=none&security=tls&type=ws&path=%2Fvless"
            "&host=ws.example.com&sni=ws.example.com&fp=firefox#VLESS-WS"
        )
        node = node_parser.parse_share_link(link)
        self.assertEqual(node["protocol"], "vless")
        self.assertEqual(node["transport"], "ws")
        self.assertEqual(node["transport_path"], "/vless")
        self.assertEqual(node["transport_host"], "ws.example.com")
        self.assertIs(node["tls_enabled"], True)
        self.assertIs(node["reality_enabled"], False)
        self.assertEqual(node["utls_fingerprint"], "firefox")

    def test_vless_reality_requires_pbk(self):
        with self.assertRaises(ValueError):
            node_parser.parse_share_link(
                "vless://11111111-2222-3333-4444-555555555555@x.example.com:443"
                "?security=reality&type=tcp#bad"
            )

    # 18. trojan 分享链接
    def test_trojan_ws_share_link(self):
        link = (
            "trojan://trojan-secret@t.example.com:443"
            "?sni=cdn.example.com&allowInsecure=1&type=ws"
            "&path=%2Ftrojan&host=cdn.example.com#TR-WS"
        )
        node = node_parser.parse_share_link(link)
        self.assertEqual(node["protocol"], "trojan")
        self.assertEqual(node["tag"], "TR-WS")
        self.assertEqual(node["server"], "t.example.com")
        self.assertEqual(node["password"], "trojan-secret")
        self.assertEqual(node["sni"], "cdn.example.com")
        self.assertIs(node["insecure"], True)
        self.assertEqual(node["transport"], "ws")
        self.assertEqual(node["transport_path"], "/trojan")
        self.assertEqual(node["transport_host"], "cdn.example.com")
        self.assertIs(node["tls_enabled"], True)

    # 19. shadowsocks SIP002 + legacy
    def test_ss_sip002_base64_userinfo(self):
        user = base64.urlsafe_b64encode(b"aes-256-gcm:ss-secret").decode("ascii").rstrip("=")
        link = f"ss://{user}@ss.example.com:8388#SS-SIP002"
        node = node_parser.parse_share_link(link)
        self.assertEqual(node["protocol"], "shadowsocks")
        self.assertEqual(node["tag"], "SS-SIP002")
        self.assertEqual(node["server"], "ss.example.com")
        self.assertEqual(node["port"], 8388)
        self.assertEqual(node["method"], "aes-256-gcm")
        self.assertEqual(node["obfs_type"], "aes-256-gcm")
        self.assertEqual(node["password"], "ss-secret")

    def test_ss_sip002_plain_userinfo(self):
        link = "ss://chacha20-ietf-poly1305:plain-pw@plain.example.com:8388#SS-PLAIN"
        node = node_parser.parse_share_link(link)
        self.assertEqual(node["protocol"], "shadowsocks")
        self.assertEqual(node["method"], "chacha20-ietf-poly1305")
        self.assertEqual(node["password"], "plain-pw")
        self.assertEqual(node["server"], "plain.example.com")

    def test_ss_legacy_full_base64(self):
        payload = base64.urlsafe_b64encode(
            b"aes-128-gcm:legacy-pw@legacy.example.com:8388"
        ).decode("ascii").rstrip("=")
        node = node_parser.parse_share_link(f"ss://{payload}#SS-LEGACY")
        self.assertEqual(node["protocol"], "shadowsocks")
        self.assertEqual(node["method"], "aes-128-gcm")
        self.assertEqual(node["password"], "legacy-pw")
        self.assertEqual(node["server"], "legacy.example.com")
        self.assertEqual(node["port"], 8388)
        self.assertEqual(node["tag"], "SS-LEGACY")

    def test_ss_with_plugin_query(self):
        user = base64.urlsafe_b64encode(b"aes-256-gcm:plugpw").decode("ascii").rstrip("=")
        link = f"ss://{user}@p.example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com#SS-P"
        node = node_parser.parse_share_link(link)
        self.assertEqual(node["plugin"], "v2ray-plugin")
        self.assertIn("mode=websocket", node["plugin_opts"])

    # 20. 多协议混合导入 + Clash 仍拒绝
    def test_mixed_protocol_multiline_import(self):
        uuid = "11111111-2222-3333-4444-555555555555"
        user = base64.urlsafe_b64encode(b"aes-256-gcm:mixpw").decode("ascii").rstrip("=")
        text = "\n".join(
            [
                "hy2://hy2pw@hy.example.com:443#HY",
                f"vless://{uuid}@v.example.com:443?encryption=none&security=tls&type=tcp#VL",
                "trojan://trpw@t.example.com:443?sni=t.example.com#TR",
                f"ss://{user}@ss.example.com:8388#SS",
            ]
        )
        nodes, errors = node_parser.parse_import_text(text)
        self.assertEqual(errors, [])
        self.assertEqual([n["protocol"] for n in nodes], [
            "hysteria2", "vless", "trojan", "shadowsocks",
        ])
        self.assertEqual([n["tag"] for n in nodes], ["HY", "VL", "TR", "SS"])

    # 21. sing-box JSON 多协议 outbound
    def test_sing_box_multi_protocol_outbounds(self):
        config = {
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "hysteria2",
                    "tag": "json-hy2",
                    "server": "hy.example.com",
                    "server_port": 443,
                    "password": "hy2pw",
                    "tls": {"enabled": True, "server_name": "hy.example.com"},
                },
                {
                    "type": "vless",
                    "tag": "json-vless",
                    "server": "v.example.com",
                    "server_port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "flow": "xtls-rprx-vision",
                    "tls": {
                        "enabled": True,
                        "server_name": "www.example.com",
                        "utls": {"enabled": True, "fingerprint": "chrome"},
                        "reality": {
                            "enabled": True,
                            "public_key": "PkExample",
                            "short_id": "abcd",
                        },
                    },
                },
                {
                    "type": "trojan",
                    "tag": "json-trojan",
                    "server": "t.example.com",
                    "server_port": 443,
                    "password": "trpw",
                    "tls": {"enabled": True, "server_name": "t.example.com", "insecure": True},
                    "transport": {
                        "type": "ws",
                        "path": "/tr",
                        "headers": {"Host": "t.example.com"},
                    },
                },
                {
                    "type": "shadowsocks",
                    "tag": "json-ss",
                    "server": "ss.example.com",
                    "server_port": 8388,
                    "method": "aes-256-gcm",
                    "password": "sspw",
                },
            ]
        }
        nodes, errors = node_parser.parse_import_text(json.dumps(config))
        self.assertEqual(errors, [])
        by_tag = {n["tag"]: n for n in nodes}
        self.assertEqual(set(by_tag), {"json-hy2", "json-vless", "json-trojan", "json-ss"})

        hy2 = by_tag["json-hy2"]
        self.assertEqual(hy2["protocol"], "hysteria2")
        self.assertEqual(hy2["password"], "hy2pw")

        vl = by_tag["json-vless"]
        self.assertEqual(vl["protocol"], "vless")
        self.assertEqual(vl["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(vl["password"], vl["uuid"])
        self.assertEqual(vl["flow"], "xtls-rprx-vision")
        self.assertIs(vl["reality_enabled"], True)
        self.assertEqual(vl["reality_public_key"], "PkExample")
        self.assertEqual(vl["utls_fingerprint"], "chrome")

        tr = by_tag["json-trojan"]
        self.assertEqual(tr["protocol"], "trojan")
        self.assertEqual(tr["transport"], "ws")
        self.assertEqual(tr["transport_path"], "/tr")
        self.assertEqual(tr["transport_host"], "t.example.com")
        self.assertIs(tr["insecure"], True)

        ss = by_tag["json-ss"]
        self.assertEqual(ss["protocol"], "shadowsocks")
        self.assertEqual(ss["method"], "aes-256-gcm")
        self.assertEqual(ss["password"], "sspw")

    def test_sing_box_full_config_sets_protocol(self):
        config = {
            "outbounds": [
                {
                    "type": "hysteria2",
                    "tag": "json-node",
                    "server": "hy.example.com",
                    "server_port": 8443,
                    "password": "jsonpw",
                    "tls": {"enabled": True, "server_name": "cdn.example.com"},
                }
            ]
        }
        nodes, errors = node_parser.parse_import_text(json.dumps(config))
        self.assertEqual(errors, [])
        self.assertEqual(nodes[0]["protocol"], "hysteria2")


if __name__ == "__main__":
    unittest.main()


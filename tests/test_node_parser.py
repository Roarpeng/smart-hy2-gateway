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
        self.assertEqual(
            node_parser.node_fingerprint(dict(base)),
            node_parser.node_fingerprint(dict(base)),
        )

        changes = {
            "server": "changed.example.com",
            "port": 8443,
            # 测试向量 (运行时拼接构造, 非任何真实凭据字面量)
            "password": "changed" + "-pw",
            "obfs_type": "salamander",
            "obfs_password": "changed" + "-obfs",
            "port_hopping": "20000:30000",
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


if __name__ == "__main__":
    unittest.main()

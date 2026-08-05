import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("tcp_forward.py")
SPEC = importlib.util.spec_from_file_location("tcp_forward", MODULE_PATH)
tcp_forward = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tcp_forward)


class TcpForwardRuleTests(unittest.TestCase):
    def test_accepts_lab_rules(self):
        self.assertEqual(
            tcp_forward.parse_rule("127.0.0.1:18080=bitcoin-a:28080"),
            (("127.0.0.1", 18080), ("bitcoin-a", 28080)),
        )
        self.assertEqual(
            tcp_forward.parse_rule("0.0.0.0:28081=127.0.0.1:18081"),
            (("0.0.0.0", 28081), ("127.0.0.1", 18081)),
        )

    def test_rejects_public_or_unbounded_endpoints(self):
        invalid = [
            "0.0.0.0:1=example.com:80",
            "127.0.0.1:1=203.0.113.10:80",
            "192.168.1.10:1=127.0.0.1:2",
            "127.0.0.1:0=bitcoin-a:1",
            "127.0.0.1:1=bitcoin_a:2",
            "127.0.0.1:1",
        ]
        for rule in invalid:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                tcp_forward.parse_rule(rule)


if __name__ == "__main__":
    unittest.main()

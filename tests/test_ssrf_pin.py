"""SSRF guard tests for webscanx.scanners.web.http. getaddrinfo is mocked: no network."""
import os, sys, socket, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from webscanx.scanners.web import http


def ai(*ips):
    return [(socket.AF_INET6 if ":" in i else socket.AF_INET, socket.SOCK_STREAM, 6, "", (i, 80)) for i in ips]


def patched(*answers):
    """getaddrinfo returning each answer in turn (last one repeats)."""
    it = iter(answers)
    last = [answers[-1]]
    def f(*a, **k):
        last[0] = next(it, last[0])
        return ai(*last[0])
    return mock.patch("socket.getaddrinfo", side_effect=f)


class SsrfPin(unittest.TestCase):
    def setUp(self):
        http._rate.allow = None

    def test_private_answers_blocked(self):
        for ip in ("10.0.0.5", "169.254.169.254", "127.0.0.1"):
            with self.subTest(ip=ip), patched((ip,)):
                with self.assertRaises(http.Blocked):
                    http.resolve_checked("evil.example", 80)

    def test_public_ok_returns_vetted_ip(self):
        with patched(("93.184.216.34",)):
            self.assertEqual(http.resolve_checked("ok.example", 80), "93.184.216.34")

    def test_mixed_answer_blocked(self):
        with patched(("93.184.216.34", "10.0.0.5")):
            with self.assertRaises(http.Blocked):
                http.resolve_checked("mixed.example", 80)

    def test_rebinding_refused_on_second_call(self):
        with patched(("93.184.216.34",), ("10.0.0.5",)):
            http.resolve_checked("rebind.example", 80)
            with self.assertRaises(http.Blocked):
                http.resolve_checked("rebind.example", 80)

    def test_nat64_and_6to4_blocked(self):
        for ip in ("64:ff9b::a00:1", "2002:c0a8:101::"):
            with self.subTest(ip=ip), patched((ip,)):
                with self.assertRaises(http.Blocked):
                    http.resolve_checked("v6.example", 80)

    def test_unresolvable_fails_closed(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with self.assertRaises(http.Blocked):
                http.resolve_checked("nx.example", 80)

    def test_blocked_is_oserror_and_valueerror(self):
        self.assertTrue(issubclass(http.Blocked, OSError) and issubclass(http.Blocked, ValueError))

    def test_set_scope_loopback_allowed_only_for_that_host(self):
        with patched(("127.0.0.1",)):
            http.set_scope("http://localhost:8000/")
            self.assertEqual(http.resolve_checked("localhost", 80), "127.0.0.1")
        with patched(("127.0.0.1",)):
            with self.assertRaises(http.Blocked):  # other hosts still refused
                http.resolve_checked("other.example", 80)
        http._rate.allow = None

    def test_set_scope_rejects_private_nonloopback(self):
        with patched(("10.0.0.5",)):
            with self.assertRaises(ValueError):
                http.set_scope("http://intranet.example/")

    def test_scoped_loopback_host_cannot_rebind_to_private(self):
        with patched(("127.0.0.1",), ("127.0.0.1",), ("10.0.0.5",)):  # set_scope resolves twice
            http.set_scope("http://localhost/")
            with self.assertRaises(http.Blocked):
                http.resolve_checked("localhost", 80)
        http._rate.allow = None


if __name__ == "__main__":
    unittest.main()

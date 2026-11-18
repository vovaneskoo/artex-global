import importlib.util
import contextlib
import http.server
import io
import json
import sys
import threading
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve()
SCRIPT_CANDIDATES = [
    HERE.with_name("privacy_check.py"),
    HERE.parents[1] / "scripts" / "privacy-check" / "privacy_check.py",
]
SCRIPT_PATH = next((path for path in SCRIPT_CANDIDATES if path.is_file()), None)
if SCRIPT_PATH is None:
    raise RuntimeError("Could not locate privacy_check.py beside this test or at scripts/privacy-check/privacy_check.py")
SPEC = importlib.util.spec_from_file_location("privacy_check_under_test", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
pc = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pc
SPEC.loader.exec_module(pc)

VM = "lab"


def result(stdout="", kind="ok", returncode=0):
    return pc.CommandResult(kind, returncode if kind in {"ok", "error"} else None, stdout)


def guest(*parts):
    return ("limactl", "shell", VM, "--", *parts)


def default_runner(overrides=None):
    values = {
        ("mullvad", "status", "--json"): result('{"state":"connected","exit_ip":"8.8.8.8","city":"private"}'),
        ("mullvad", "lockdown-mode", "get"): result("on\n"),
        ("limactl", "list", "--json"): result('[{"name":"lab","status":"Running","config":{"secret":"must-not-print"}}]'),
        guest("ip", "route"): result("default via 10.0.2.2 dev eth0\n10.0.2.0/24 dev eth0 proto kernel\n"),
        guest("ip", "-6", "route"): result("fe80::/64 dev eth0 proto kernel metric 256\n"),
        guest("ip", "-6", "address", "show"): result(
            "1: lo: <LOOPBACK,UP>\n    inet6 ::1/128 scope host\n"
            "2: eth0: <BROADCAST,UP>\n    inet6 fe80::1234/64 scope link\n"
        ),
        guest("cat", "/etc/resolv.conf"): result(
            "nameserver 10.0.2.3\nnameserver 127.0.0.53\nsearch internal.example\n"
        ),
        guest("sudo", "-n", "iptables", "-S", "OUTPUT"): result("-P OUTPUT ACCEPT\n"),
        guest("sudo", "-n", "iptables", "-L", "OUTPUT", "-n", "-v", "-x"): result(
            "Chain OUTPUT (policy ACCEPT 3 packets, 256 bytes)\n"
        ),
        guest("sudo", "-n", "iptables", "-S", "DOCKER-USER"): result("-N DOCKER-USER\n"),
        guest("sudo", "-n", "iptables", "-L", "DOCKER-USER", "-n", "-v", "-x"): result(
            "Chain DOCKER-USER (0 references)\n"
        ),
        guest("sudo", "-n", "ip6tables", "-S", "OUTPUT"): result("-P OUTPUT ACCEPT\n"),
        guest("sudo", "-n", "ip6tables", "-L", "OUTPUT", "-n", "-v", "-x"): result(
            "Chain OUTPUT (policy ACCEPT 1 packets, 64 bytes)\n"
        ),
        guest("sudo", "-n", "ip6tables", "-S", "DOCKER-USER"): result("-N DOCKER-USER\n"),
        guest("sudo", "-n", "ip6tables", "-L", "DOCKER-USER", "-n", "-v", "-x"): result(
            "Chain DOCKER-USER (0 references)\n"
        ),
    }
    values.update(overrides or {})
    calls = []

    def runner(argv, timeout=8):
        key = tuple(argv)
        calls.append((key, timeout))
        return values.get(key, result(kind="unavailable"))

    runner.calls = calls
    return runner


class PrivacyCheckTests(unittest.TestCase):
    def test_exit_probe_rejects_redirect_without_contacting_destination(self):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path == "/":
                    self.send_response(302)
                    self.send_header("Location", "/unexpected")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"ip":"8.8.8.8","mullvad_exit_ip":false}')

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        worker.start()
        try:
            fixture_url = "http://127.0.0.1:" + str(server.server_port) + "/"
            # Only the fixed starting URL changes; execute the actual guest probe.
            code = pc.PROBE_CODE.replace("https://am.i.mullvad.net/json", fixture_url)
            with self.assertRaises(urllib.error.HTTPError) as raised:
                with contextlib.redirect_stdout(io.StringIO()):
                    exec(code, {})
            self.assertEqual(raised.exception.code, 302)
            self.assertEqual(requests, ["/"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_mullvad_states_include_connected_disconnected_transitional_and_unavailable(self):
        cases = [
            (result('{"state":"connected"}'), "connected"),
            (result('{"state":"disconnected"}'), "disconnected"),
            (result('{"state":"connecting"}'), "transitional"),
            (result(kind="unavailable"), "unavailable"),
        ]
        for status_result, expected in cases:
            with self.subTest(expected=expected):
                runner = default_runner({("mullvad", "status", "--json"): status_result})
                report = pc.collect(VM, runner=runner)
                self.assertEqual(report["collectors"]["mullvad_status"]["parsed_state"], expected)

    def test_ipv6_absence_is_snapshot_only_and_not_a_leak_free_claim(self):
        report = pc.collect(VM, runner=default_runner())
        assessment = report["observations"]["ipv6_egress"]
        self.assertEqual(assessment["status"], "absent")
        self.assertEqual(assessment["confidence"], "proven")
        self.assertIn("snapshot only", assessment["basis"])
        self.assertEqual(report["observations"]["overall_leak_free"]["confidence"], "unproven")

    def test_firewall_drop_policy_is_not_labeled_proven_blocked(self):
        overrides = {
            guest("ip", "-6", "route"): result("default via 2001:4860::1 dev eth0\n"),
            guest("ip", "-6", "address", "show"): result(
                "2: eth0: <BROADCAST,UP>\n    inet6 2606:4700:4700::1111/64 scope global\n"
            ),
            guest("sudo", "-n", "ip6tables", "-S", "OUTPUT"): result("-P OUTPUT DROP\n"),
            guest("sudo", "-n", "ip6tables", "-L", "OUTPUT", "-n", "-v", "-x"): result(
                "Chain OUTPUT (policy DROP 7 packets, 448 bytes)\n"
            ),
        }
        report = pc.collect(VM, runner=default_runner(overrides))
        assessment = report["observations"]["ipv6_egress"]
        self.assertEqual(assessment["confidence"], "partial")
        self.assertNotEqual(assessment["status"], "proven_blocked")
        self.assertEqual(report["firewall_summaries"]["ipv6"]["OUTPUT"]["policies"], {"OUTPUT": "DROP"})
        self.assertEqual(report["observations"]["overall_leak_free"]["confidence"], "unproven")

    def test_negated_loopback_rule_does_not_create_any_blocking_proof(self):
        overrides = {
            guest("ip", "-6", "route"): result("default via 2001:4860::1 dev eth0\n"),
            guest("ip", "-6", "address", "show"): result(
                "2: eth0: <BROADCAST,UP>\n    inet6 2606:4700:4700::1111/64 scope global\n"
            ),
            guest("sudo", "-n", "ip6tables", "-S", "OUTPUT"): result(
                "-P OUTPUT DROP\n-A OUTPUT ! -o lo -j ACCEPT\n"
            ),
            guest("sudo", "-n", "ip6tables", "-L", "OUTPUT", "-n", "-v", "-x"): result(
                "Chain OUTPUT (policy DROP 7 packets, 448 bytes)\n"
            ),
        }
        report = pc.collect(VM, runner=default_runner(overrides))
        self.assertEqual(report["observations"]["ipv6_egress"]["confidence"], "partial")

    def test_resolver_metadata_alone_remains_unproven(self):
        overrides = {
            guest("cat", "/etc/resolv.conf"): result(
                "nameserver 10.10.0.1\nnameserver 8.8.8.8\nsearch private.example\n"
            )
        }
        report = pc.collect(VM, runner=default_runner(overrides))
        dns = report["observations"]["dns_resolver_metadata"]
        self.assertEqual(dns["confidence"], "unproven")
        self.assertEqual(dns["configured_nameservers"], ["10.10.0.1", "[redacted-public-ip]"])
        serialized = json.dumps(report)
        self.assertNotIn("private.example", serialized)
        self.assertNotIn("8.8.8.8", serialized)

    def test_redaction_hides_public_ips_and_preserves_private_and_loopback(self):
        source = "default via 8.8.8.8 src 10.1.2.3 lo 127.0.0.1 v6 2606:4700:4700::1111 local ::1 ula fc00::1"
        redacted = pc.redact_public_ips(source)
        self.assertEqual(redacted.count("[redacted-public-ip]"), 2)
        for preserved in ("10.1.2.3", "127.0.0.1", "::1", "fc00::1"):
            self.assertIn(preserved, redacted)
        self.assertNotIn("8.8.8.8", redacted)
        self.assertNotIn("2606:4700:4700::1111", redacted)

    def test_mullvad_raw_json_and_lima_configuration_never_appear(self):
        report = pc.collect(VM, runner=default_runner())
        serialized = json.dumps(report)
        self.assertNotIn('"exit_ip"', serialized)
        self.assertNotIn("must-not-print", serialized)
        self.assertNotIn('"config"', serialized)

    def test_stopped_vm_is_never_opened_or_started(self):
        runner = default_runner({("limactl", "list", "--json"): result('[{"name":"lab","status":"Stopped"}]')})
        report = pc.collect(VM, probe_exit=True, runner=runner)
        self.assertEqual(report["vm"]["status"], "not_running")
        self.assertEqual(report["collectors"]["exit_probe"]["status"], "not_run")
        self.assertFalse(any(argv[:3] == ("limactl", "shell", VM) for argv, _ in runner.calls))
        self.assertFalse(any(argv[:2] == ("limactl", "start") for argv, _ in runner.calls))

    def test_probe_is_opt_in_fixed_endpoint_and_emits_only_digest(self):
        probe_json = '{"ip":"8.8.4.4","mullvad_exit_ip":true,"city":"secret-city"}'
        probe_argv = guest("python3", "-c", pc.PROBE_CODE)
        runner = default_runner({probe_argv: result(probe_json)})
        default_report = pc.collect(VM, runner=runner)
        self.assertEqual(default_report["collectors"]["exit_probe"]["status"], "not_requested")
        self.assertFalse(any("am.i.mullvad.net" in arg for argv, _ in runner.calls for arg in argv))

        runner = default_runner({probe_argv: result(probe_json)})
        report = pc.collect(VM, probe_exit=True, runner=runner)
        probe = report["collectors"]["exit_probe"]
        serialized = json.dumps(probe)
        self.assertEqual(probe["status"], "ok")
        self.assertIs(probe["mullvad_exit_ip"], True)
        self.assertEqual(probe["address_digest"]["algorithm"], "ephemeral-hmac-sha256")
        self.assertEqual(len(probe["address_digest"]["value"]), 64)
        self.assertNotIn("8.8.4.4", serialized)
        self.assertNotIn("secret-city", serialized)
        self.assertIn("https://am.i.mullvad.net/json", pc.PROBE_CODE)
        self.assertIn("--", probe_argv)

    def test_commands_are_allowlisted_read_only_and_never_use_a_shell(self):
        runner = default_runner()
        pc.collect(VM, runner=runner)
        for argv, _ in runner.calls:
            self.assertIn(argv[0], {"mullvad", "limactl"})
            self.assertNotIn("start", argv)
            self.assertNotIn("stop", argv)
            self.assertNotIn("connect", argv)
            self.assertNotIn("disconnect", argv)
            self.assertNotIn("-A", argv)
            self.assertNotIn("-I", argv)
            self.assertNotIn("-F", argv)
            if argv[:2] == ("limactl", "shell"):
                self.assertEqual(argv[3], "--")
                if "iptables" in argv or "ip6tables" in argv:
                    self.assertEqual(argv[4:6], ("sudo", "-n"))

        with patch.object(pc.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="ok", stderr="")) as mocked:
            self.assertEqual(pc.run_command(["mullvad", "status", "--json"]).kind, "ok")
            self.assertIs(mocked.call_args.kwargs["shell"], False)
            self.assertNotIn("env", mocked.call_args.kwargs)

    def test_explicit_vm_name_is_required_and_validated(self):
        with self.assertRaises(ValueError):
            pc.collect("../other")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pc.main([])


if __name__ == "__main__":
    unittest.main()

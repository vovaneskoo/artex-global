#!/usr/bin/env python3
"""Credential-free, read-only network privacy snapshot for a selected Lima VM."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Iterable

VM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
IP_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,3})?(?![A-Za-z0-9_.])"
    r"|(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?:%[A-Za-z0-9_.-]+)?(?:/[0-9]{1,3})?(?![A-Za-z0-9:])"
)
DEFAULT_ENDPOINT = "https://am.i.mullvad.net/json"
PROBE_CODE = """import json,urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None
u='https://am.i.mullvad.net/json'
o=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
r=o.open(urllib.request.Request(u,headers={'Accept':'application/json'}),timeout=8)
d=json.load(r)
print(json.dumps({'ip':d.get('ip'),'mullvad_exit_ip':d.get('mullvad_exit_ip')}))
"""


@dataclass(frozen=True)
class CommandResult:
    kind: str
    returncode: int | None = None
    stdout: str = ""


def run_command(argv: Iterable[str], timeout: int = 8) -> CommandResult:
    """Run a fixed argv without a shell and discard stderr and all error text."""
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return CommandResult("unavailable")
    except subprocess.TimeoutExpired:
        return CommandResult("timeout")
    except OSError:
        return CommandResult("error")
    return CommandResult("ok" if completed.returncode == 0 else "error", completed.returncode, completed.stdout)


def _command_summary(result: CommandResult) -> dict[str, object]:
    summary: dict[str, object] = {"status": result.kind}
    if result.returncode is not None:
        summary["returncode"] = result.returncode
    return summary


def _public_ip_match_is_global(token: str) -> bool:
    address_text = token.split("/", 1)[0]
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return False
    return address.is_global


def redact_public_ips(text: str) -> str:
    """Redact globally-routable IP literals while preserving private/loopback data."""
    return IP_LITERAL_RE.sub(
        lambda match: "[redacted-public-ip]" if _public_ip_match_is_global(match.group(0)) else match.group(0),
        text,
    )


def _sanitized_lines(raw: str, limit: int = 50) -> list[str]:
    lines = [redact_public_ips(line.strip()) for line in raw.splitlines() if line.strip()]
    return lines[:limit]


def _json_records(raw: str) -> list[dict[str, object]] | None:
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [record for record in parsed if isinstance(record, dict)]
        if isinstance(parsed, dict):
            instances = parsed.get("instances")
            if isinstance(instances, list):
                return [record for record in instances if isinstance(record, dict)]
            if "name" in parsed:
                return [parsed]
    except (json.JSONDecodeError, TypeError):
        pass

    records: list[dict[str, object]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None
        records.append(record)
    return records if records else None


def _vm_state(record: dict[str, object]) -> str:
    value = record.get("status", record.get("state", ""))
    state = str(value).strip().lower()
    if state in {"running", "started"}:
        return "running"
    if state in {"stopped", "stopping", "starting", "creating", "limbo"}:
        return state
    return "unknown"


def parse_mullvad_state(raw: str) -> str:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return "unknown"
    state: object = data.get("state") if isinstance(data, dict) else data
    if isinstance(state, dict):
        state = state.get("state", state.get("type", ""))
    normalized = str(state).strip().lower()
    if normalized == "connected":
        return "connected"
    if normalized == "disconnected":
        return "disconnected"
    if normalized in {"connecting", "disconnecting", "reconnecting", "reconnecting_after_disconnect"}:
        return "transitional"
    return "unknown"


def parse_lockdown(raw: str) -> str:
    normalized = raw.strip().lower()
    if normalized in {"on", "enabled", "true"}:
        return "on"
    if normalized in {"off", "disabled", "false"}:
        return "off"
    if re.search(r"(?:^|[\s:=])(?:on|enabled|true)(?:$|[\s.,])", normalized):
        return "on"
    if re.search(r"(?:^|[\s:=])(?:off|disabled|false)(?:$|[\s.,])", normalized):
        return "off"
    return "unknown"


def _has_default_route(raw: str, ipv6: bool) -> bool:
    for line in raw.splitlines():
        first = line.strip().split(maxsplit=1)
        if not first:
            continue
        route = first[0]
        if route == "default" or route == ("::/0" if ipv6 else "0.0.0.0/0"):
            return True
    return False


def _global_ipv6_address_present(raw: str) -> bool:
    for line in raw.splitlines():
        if "inet6" not in line:
            continue
        parts = line.split()
        for index, token in enumerate(parts[:-1]):
            if token != "inet6":
                continue
            address_token = parts[index + 1].split("/", 1)[0]
            try:
                address = ipaddress.IPv6Address(address_token)
            except ValueError:
                continue
            if address.is_global:
                return True
    return False


def _parse_resolver_addresses(raw: str) -> list[str]:
    addresses: list[str] = []
    for line in raw.splitlines():
        match = re.match(r"\s*nameserver\s+(\S+)", line, flags=re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1).strip("[]")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        safe = redact_public_ips(candidate)
        if safe not in addresses:
            addresses.append(safe)
    return addresses


def _parse_firewall_rules(raw: str) -> tuple[dict[str, str], list[list[str]]]:
    policies: dict[str, str] = {}
    rules: list[list[str]] = []
    for line in raw.splitlines():
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if len(parts) == 3 and parts[0] == "-P":
            policies[parts[1].upper()] = parts[2].upper()
        elif len(parts) >= 3 and parts[0] == "-A":
            rules.append(parts)
    return policies, rules


def _parse_firewall_counters(raw: str) -> tuple[dict[str, dict[str, object]], int, int]:
    chains: dict[str, dict[str, object]] = {}
    packet_sum = 0
    byte_sum = 0
    chain_re = re.compile(
        r"^Chain\s+(\S+)\s+\(policy\s+(\S+)\s+(\d+)\s+packets?,\s+(\d+)\s+bytes?\)",
        re.IGNORECASE,
    )
    for line in raw.splitlines():
        match = chain_re.match(line.strip())
        if match:
            name, policy, packets, bytes_count = match.groups()
            packet_count = int(packets)
            byte_count = int(bytes_count)
            chains[name.upper()] = {"policy": policy.upper(), "packets": packet_count, "bytes": byte_count}
            packet_sum += packet_count
            byte_sum += byte_count
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0].isdigit() and fields[1].isdigit():
            packet_sum += int(fields[0])
            byte_sum += int(fields[1])
    return chains, packet_sum, byte_sum


def _firewall_summary(rules_result: CommandResult, counters_result: CommandResult) -> dict[str, object]:
    policies: dict[str, str] = {}
    rules: list[list[str]] = []
    chain_counters: dict[str, dict[str, object]] = {}
    packets = 0
    bytes_count = 0
    if rules_result.kind == "ok":
        policies, rules = _parse_firewall_rules(rules_result.stdout)
    if counters_result.kind == "ok":
        chain_counters, packets, bytes_count = _parse_firewall_counters(counters_result.stdout)
    status = "ok" if rules_result.kind == "ok" and counters_result.kind == "ok" else "incomplete"
    return {
        "status": status,
        "rules_status": rules_result.kind,
        "counters_status": counters_result.kind,
        "policies": policies,
        "rule_count": len(rules),
        "chain_counters": chain_counters,
        "listed_packet_counter_sum": packets,
        "listed_byte_counter_sum": bytes_count,
    }


def _ipv6_assessment(
    route_result: CommandResult,
    address_result: CommandResult,
) -> dict[str, object]:
    route_ok = route_result.kind == "ok"
    address_ok = address_result.kind == "ok"
    has_default = _has_default_route(route_result.stdout, ipv6=True) if route_ok else None
    has_global_address = _global_ipv6_address_present(address_result.stdout) if address_ok else None
    if route_ok and address_ok and has_default is False and has_global_address is False:
        return {
            "status": "absent",
            "confidence": "proven",
            "basis": "No global IPv6 address and no default IPv6 route appeared in the successful VM snapshot. This describes the snapshot only; it does not prove leak-free behavior.",
            "default_route_observed": False,
            "global_address_observed": False,
        }
    if route_ok and address_ok:
        return {
            "status": "not_established",
            "confidence": "partial",
            "basis": "A global IPv6 address or default route was observed. Firewall rule and counter snapshots are metadata and do not prove that traffic is blocked.",
            "default_route_observed": has_default,
            "global_address_observed": has_global_address,
        }
    return {
        "status": "unavailable",
        "confidence": "unproven",
        "basis": "Required IPv6 route or address metadata was unavailable, so the snapshot cannot establish presence, absence, or blocking.",
        "default_route_observed": has_default,
        "global_address_observed": has_global_address,
    }


def _probe_digest(raw: str) -> dict[str, object]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "invalid_response"}
    if not isinstance(data, dict):
        return {"status": "invalid_response"}
    observed_ip = data.get("ip")
    try:
        address = ipaddress.ip_address(str(observed_ip))
    except ValueError:
        return {"status": "invalid_response"}
    digest = hmac.new(secrets.token_bytes(32), address.packed, hashlib.sha256).hexdigest()
    mullvad_exit = data.get("mullvad_exit_ip")
    if not isinstance(mullvad_exit, bool):
        mullvad_exit = None
    return {
        "status": "ok",
        "address_digest": {"algorithm": "ephemeral-hmac-sha256", "value": digest},
        "mullvad_exit_ip": mullvad_exit,
        "note": "The address is hashed with a one-run random key; the key and plaintext address are not emitted.",
    }


def collect(vm_name: str, probe_exit: bool = False, runner: Callable[..., CommandResult] = run_command) -> dict[str, object]:
    if not VM_NAME_RE.fullmatch(vm_name):
        raise ValueError("VM name must be a simple Lima instance identifier.")

    commands: dict[str, CommandResult] = {}

    def call(key: str, argv: list[str], timeout: int = 8) -> CommandResult:
        result = runner(argv, timeout=timeout)
        commands[key] = result
        return result

    mullvad_result = call("mullvad_status", ["mullvad", "status", "--json"])
    lockdown_result = call("mullvad_lockdown", ["mullvad", "lockdown-mode", "get"])
    lima_result = call("lima_inventory", ["limactl", "list", "--json"])

    mullvad_state = parse_mullvad_state(mullvad_result.stdout) if mullvad_result.kind == "ok" else "unavailable"
    lockdown_state = parse_lockdown(lockdown_result.stdout) if lockdown_result.kind == "ok" else "unavailable"
    records = _json_records(lima_result.stdout) if lima_result.kind == "ok" else None
    selected: dict[str, object] | None = None
    if records is not None:
        selected = next((record for record in records if record.get("name") == vm_name), None)

    if lima_result.kind != "ok" or records is None:
        vm_observation = {"requested_name": vm_name, "status": "unavailable", "state": "unknown"}
        is_running = False
    elif selected is None:
        vm_observation = {"requested_name": vm_name, "status": "not_found", "state": "unknown"}
        is_running = False
    else:
        state = _vm_state(selected)
        is_running = state == "running"
        vm_observation = {
            "requested_name": vm_name,
            "status": "running" if is_running else "not_running",
            "state": state,
        }

    vm_commands: dict[str, dict[str, object]] = {}
    routes: dict[str, object] = {
        "ipv4": {"collector_status": "not_run", "default_route_observed": None, "lines": []},
        "ipv6": {"collector_status": "not_run", "default_route_observed": None, "lines": []},
    }
    resolver_addresses: list[str] = []
    ipv6_firewall: dict[str, object] = {}
    ipv4_firewall: dict[str, object] = {}
    v6_route_result = CommandResult("unavailable")
    v6_address_result = CommandResult("unavailable")
    v4_route_result = CommandResult("unavailable")
    resolv_result = CommandResult("unavailable")

    if is_running:
        shell_prefix = ["limactl", "shell", vm_name, "--"]
        shell_specs = {
            "ipv4_route": [*shell_prefix, "ip", "route"],
            "ipv6_route": [*shell_prefix, "ip", "-6", "route"],
            "ipv6_addresses": [*shell_prefix, "ip", "-6", "address", "show"],
            "resolv_conf": [*shell_prefix, "cat", "/etc/resolv.conf"],
            "iptables_output_rules": [*shell_prefix, "sudo", "-n", "iptables", "-S", "OUTPUT"],
            "iptables_output_counters": [*shell_prefix, "sudo", "-n", "iptables", "-L", "OUTPUT", "-n", "-v", "-x"],
            "iptables_docker_user_rules": [*shell_prefix, "sudo", "-n", "iptables", "-S", "DOCKER-USER"],
            "iptables_docker_user_counters": [*shell_prefix, "sudo", "-n", "iptables", "-L", "DOCKER-USER", "-n", "-v", "-x"],
            "ip6tables_output_rules": [*shell_prefix, "sudo", "-n", "ip6tables", "-S", "OUTPUT"],
            "ip6tables_output_counters": [*shell_prefix, "sudo", "-n", "ip6tables", "-L", "OUTPUT", "-n", "-v", "-x"],
            "ip6tables_docker_user_rules": [*shell_prefix, "sudo", "-n", "ip6tables", "-S", "DOCKER-USER"],
            "ip6tables_docker_user_counters": [*shell_prefix, "sudo", "-n", "ip6tables", "-L", "DOCKER-USER", "-n", "-v", "-x"],
        }
        for key, argv in shell_specs.items():
            result = call(key, argv)
            vm_commands[key] = _command_summary(result)
            if key == "ipv4_route":
                v4_route_result = result
                routes["ipv4"] = {
                    "collector_status": result.kind,
                    "default_route_observed": _has_default_route(result.stdout, ipv6=False) if result.kind == "ok" else None,
                    "lines": _sanitized_lines(result.stdout),
                }
            elif key == "ipv6_route":
                v6_route_result = result
                routes["ipv6"] = {
                    "collector_status": result.kind,
                    "default_route_observed": _has_default_route(result.stdout, ipv6=True) if result.kind == "ok" else None,
                    "lines": _sanitized_lines(result.stdout),
                }
            elif key == "ipv6_addresses":
                v6_address_result = result
            elif key == "resolv_conf":
                resolv_result = result
                if result.kind == "ok":
                    resolver_addresses = _parse_resolver_addresses(result.stdout)
        ipv4_firewall = {
            "OUTPUT": _firewall_summary(commands["iptables_output_rules"], commands["iptables_output_counters"]),
            "DOCKER-USER": _firewall_summary(commands["iptables_docker_user_rules"], commands["iptables_docker_user_counters"]),
        }
        ipv6_firewall = {
            "OUTPUT": _firewall_summary(commands["ip6tables_output_rules"], commands["ip6tables_output_counters"]),
            "DOCKER-USER": _firewall_summary(commands["ip6tables_docker_user_rules"], commands["ip6tables_docker_user_counters"]),
        }
        vm_commands["iptables_summary"] = ipv4_firewall
        vm_commands["ip6tables_summary"] = ipv6_firewall

    ipv6_assessment = _ipv6_assessment(v6_route_result, v6_address_result)
    resolver_collector_status = resolv_result.kind if is_running else "not_run"
    observations: dict[str, object] = {
        "ipv6_egress": ipv6_assessment,
        "dns_resolver_metadata": {
            "confidence": "unproven",
            "collector_status": resolver_collector_status,
            "configured_nameservers": resolver_addresses,
            "basis": "Resolver configuration is metadata only; it does not establish the actual DNS query path or rule out DNS leakage.",
        },
        "overall_leak_free": {
            "confidence": "unproven",
            "basis": "Read-only route, firewall, resolver, and optional exit snapshots cannot prove that no traffic or DNS query can escape.",
        },
    }

    collectors: dict[str, object] = {
        "mullvad_status": {**_command_summary(mullvad_result), "parsed_state": mullvad_state},
        "mullvad_lockdown": {**_command_summary(lockdown_result), "parsed_state": lockdown_state},
        "lima_inventory": {**_command_summary(lima_result), "selected_vm": vm_observation},
        "vm_shell": vm_commands,
    }
    if probe_exit:
        if not is_running:
            collectors["exit_probe"] = {"status": "not_run", "reason": "The explicitly selected VM was not confirmed running."}
        else:
            probe_result = call(
                "exit_probe",
                ["limactl", "shell", vm_name, "--", "python3", "-c", PROBE_CODE],
                timeout=12,
            )
            probe_summary = _probe_digest(probe_result.stdout) if probe_result.kind == "ok" else {"status": probe_result.kind}
            collectors["exit_probe"] = probe_summary
    else:
        collectors["exit_probe"] = {"status": "not_requested"}

    return {
        "schema_version": 1,
        "vm": vm_observation,
        "collectors": collectors,
        "routes": routes,
        "firewall_summaries": {"ipv4": ipv4_firewall, "ipv6": ipv6_firewall},
        "observations": observations,
    }


def _valid_vm_name(value: str) -> str:
    if not VM_NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("VM must be a simple Lima instance name (letters, digits, dot, underscore, hyphen).")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect a sanitized, read-only privacy snapshot for one explicitly named running Lima VM."
    )
    parser.add_argument("--vm", required=True, type=_valid_vm_name, help="Existing Lima VM to inspect; the tool never starts it.")
    parser.add_argument("--probe-exit", action="store_true", help="Make one fixed benign request to am.i.mullvad.net from the selected VM.")
    args = parser.parse_args(argv)
    report = collect(args.vm, probe_exit=args.probe_exit)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

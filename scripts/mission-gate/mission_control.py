#!/usr/bin/env python3
"""Serialized mission lifecycle with open/closed egress policy.

Open mode (default) keeps DROP policy but appends a generic ACCEPT, so new
addresses discovered mid-run need no rule. Grant classes (target/osint/feed/
callback/oast) are still journaled per address for counters, audit and exact
teardown. IPv4 and IPv6 are symmetric; containers are covered via DOCKER-USER.

Only verified rule removal releases VPN protection.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import time
import mission_state as state

class ControlError(RuntimeError): pass

DNS_PORTS = ['53']
NO_PORTS_CLASSES = {'target', 'callback'}

class Controller:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else state.state_directory()
        self.mullvad = os.environ.get('ARTEX_MULLVAD', '/Applications/Mullvad VPN.app/Contents/Resources/mullvad')
        self.lima = os.environ.get('ARTEX_LIMACTL', 'limactl')
        self.vm = os.environ.get('ARTEX_MISSION_VM', 'artex-bench')
        self._docker_chain = {}

    def run(self, args):
        try: result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error: raise ControlError(str(error)) from error
        if result.returncode:
            raise ControlError(f'{args[0]} failed ({result.returncode}): {result.stderr.strip()}')
        return result.stdout

    def guest(self, family, *args):
        binary = 'iptables' if family == 'v4' else 'ip6tables'
        return self.run([self.lima, 'shell', self.vm, '--', 'sudo', '-n', binary, *args])

    def chains(self, family):
        if family in self._docker_chain: return self._docker_chain[family]
        chains = ['OUTPUT']
        try:
            self.guest(family, '-S', 'DOCKER-USER')
            chains.append('DOCKER-USER')
        except ControlError:
            pass
        self._docker_chain[family] = chains
        return chains

    def load(self):
        if (self.directory / 'state.json').exists():
            return state.read(self.directory)
        # Missing state is not evidence that an earlier mission had no rules.
        snapshot = self.guest('v4', '-S', 'OUTPUT')
        if not snapshot.strip() or not any(line.startswith('-P OUTPUT ') for line in snapshot.splitlines()):
            raise ControlError('Unrecognized OUTPUT snapshot during initialization')
        for line in snapshot.splitlines():
            tokens = shlex.split(line)
            if '--comment' in tokens and '-j' in tokens:
                comment = tokens[tokens.index('--comment') + 1]
                if comment.startswith('artex-mission:') and tokens[tokens.index('-j') + 1] == 'ACCEPT':
                    raise ControlError('Missing journal with owned ACCEPT rules: restore non-active journal before cleanup')
        legacy = self.directory / 'targets.txt'
        # A legacy marker is never an active grant. Keep the original file intact.
        targets = [str(ipaddress.ip_address(s.strip())) for s in legacy.read_text().splitlines() if s.strip()] if legacy.exists() else []
        value = state.new_state(targets, 'legacy' if targets else 'tagged', 'closed' if targets else 'open')
        if (self.directory / 'armed').exists() and not targets:
            raise ControlError('Legacy armed marker without target journal: manual firewall reconciliation required')
        value['rules'] = self.scan_owned('artex-mission-closed')
        if targets:
            value.update(status='cleanup-failed', last_error='Legacy state requires mission-down before a new mission')
        state.write(self.directory, value)
        return value

    def tag(self, value, suffix=''):
        if value['rule_style'] != 'tagged': return 'artex-mission-closed'
        comment = 'artex-mission:' + value['mission_id']
        return comment + (':' + suffix if suffix else '')

    def link_rules(self, family):
        """Keep the default gateway and its on-link subnet reachable.

        limactl-managed SSH terminates on the host behind the NAT gateway. The
        reply path is OUTPUT and must survive the default DROP even when
        conntrack does not classify it, so allow the gateway subnet explicitly.
        """
        flag = '-6' if family == 'v6' else '-4'
        rules = []
        try: routes = self.run([self.lima, 'shell', self.vm, '--', 'sudo', '-n', 'ip', flag, 'route', 'show', 'default'])
        except ControlError: return rules
        for line in routes.splitlines():
            parts = shlex.split(line)
            if len(parts) < 2 or parts[0] != 'default': continue
            if 'via' in parts:
                gw = parts[parts.index('via') + 1]
                try: net = ipaddress.ip_network(gw + ('/128' if family == 'v6' else '/32'), strict=False)
                except ValueError: continue
                rules.append(['-d', str(net), '-j', 'ACCEPT'])
            if 'dev' in parts:
                dev = parts[parts.index('dev') + 1]
                try: addr = self.run([self.lima, 'shell', self.vm, '--', 'sudo', '-n', 'ip', flag, 'addr', 'show', 'dev', dev, 'scope', 'global'])
                except ControlError: addr = ''
                for token in addr.split():
                    if '/' not in token: continue
                    try: net = ipaddress.ip_interface(token).network
                    except ValueError: continue
                    if str(net) not in ('127.0.0.0/8', '::1/128'):
                        rules.append(['-d', str(net), '-j', 'ACCEPT'])
        return rules

    def base_rules(self, family):
        proto = 'ipv6-icmp' if family == 'v6' else 'icmp'
        rules = self.link_rules(family) + [
            ['-o', 'lo', '-j', 'ACCEPT'],
            ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
            ['-p', 'udp', '-m', 'multiport', '--dports', '53', '-j', 'ACCEPT'],
            ['-p', 'tcp', '-m', 'multiport', '--dports', '53', '-j', 'ACCEPT'],
            ['-p', proto, '-j', 'ACCEPT'],
        ]
        if family == 'v4':
            rules.insert(1, ['-d', '172.16.0.0/12', '-j', 'ACCEPT'])
        return rules

    def class_rules(self, value, grant):
        addr = ['-d', grant['addr']]
        comment = ['-m', 'comment', '--comment', self.tag(value, grant['class'])]
        cls = grant['class']
        if grant['family'] == 'v6' and cls != 'target':
            # keep class visibility for v6 too; protocol logic is identical
            pass
        if cls in NO_PORTS_CLASSES:
            if cls == 'callback':
                return [addr + ['-p', 'tcp'] + comment + ['-j', 'ACCEPT']]
            return [addr + comment + ['-j', 'ACCEPT']]
        if cls in ('oast', 'osint'):
            if cls == 'osint':
                return [addr + ['-p', 'tcp', '--dport', '443'] + comment + ['-j', 'ACCEPT'],
                        addr + ['-p', 'tcp', '--dport', '53'] + comment + ['-j', 'ACCEPT'],
                        addr + ['-p', 'udp', '--dport', '53'] + comment + ['-j', 'ACCEPT'],
                        addr + ['-p', 'tcp', '--dport', '853'] + comment + ['-j', 'ACCEPT']]
            return [addr + ['-p', 'tcp', '--dport', '443'] + comment + ['-j', 'ACCEPT'],
                    addr + ['-p', 'udp', '--dport', '53'] + comment + ['-j', 'ACCEPT']]
        return [addr + ['-p', 'tcp', '-m', 'multiport', '--dports', '22,80,443'] + comment + ['-j', 'ACCEPT']]

    def open_rule(self, value):
        if value.get('mode') != 'open': return None
        return ['-m', 'comment', '--comment', self.tag(value, 'open'), '-j', 'ACCEPT']

    def present(self, family, tokens):
        for chain in self.chains(family):
            self.guest(family, '-C', chain, *tokens)
        return True

    def add_rule(self, value, family, tokens):
        if '--comment' not in tokens and '-j' in tokens:
            idx = tokens.index('-j')
            tokens = tokens[:idx] + ['-m', 'comment', '--comment', self.tag(value, 'rule')] + tokens[idx:]
        # Write-ahead: journal the intent BEFORE applying, so a lost reply still
        # leaves a removable entry for rollback.
        value['rules'].append({'family': family, 'tokens': tokens})
        state.write(self.directory, value)
        for chain in self.chains(family):
            if chain == 'DOCKER-USER':
                self.guest(family, '-I', chain, '1', *tokens)
            else:
                self.guest(family, '-A', chain, *tokens)
        for chain in self.chains(family):
            try:
                self.guest(family, '-C', chain, *tokens)
            except ControlError as error:
                raise ControlError(f'Added rule could not be verified in {chain}: {error}') from error

    def remove_rule(self, value, family, tokens):
        for chain in self.chains(family):
            try:
                self.guest(family, '-D', chain, *tokens)
            except ControlError:
                continue  # already gone in this chain
        value['rules'] = [r for r in value['rules'] if not (r['family'] == family and r['tokens'] == tokens)]
        state.write(self.directory, value)

    def flush_owned(self, family):
        """Atomically drop owned rules and restore the ACCEPT policy.

        One save/restore round trip per family instead of hundreds of limactl
        spawns. Non-owned rules are preserved untouched.
        """
        dump = self.dump(family)
        kept = []
        for line in dump.splitlines():
            if 'artex-mission' in line: continue
            parts = line.split()
            if line.startswith(':OUTPUT') and len(parts) >= 2 and 'DROP' in parts[1]:
                line = ':OUTPUT ACCEPT - [0:0]'
            kept.append(line)
        payload = '\n'.join(kept) + '\n'
        self.restore(family, payload)

    def dump(self, family):
        binary = 'iptables' if family == 'v4' else 'ip6tables'
        return self.run([self.lima, 'shell', self.vm, '--', 'sudo', '-n', binary + '-save'])

    def restore(self, family, payload):
        binary = 'iptables' if family == 'v4' else 'ip6tables'
        try:
            result = subprocess.run([self.lima, 'shell', self.vm, '--', 'sudo', '-n', binary + '-restore'],
                                    input=payload, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as error:
            raise ControlError(str(error)) from error
        if result.returncode:
            raise ControlError(binary + '-restore failed: ' + result.stderr.strip())

    def verify_clean(self):
        for family in ('v4', 'v6'):
            for chain in self.chains(family):
                try: listing = self.guest(family, '-S', chain)
                except ControlError: continue
                if 'artex-mission' in listing:
                    raise ControlError('Owned rules remain after teardown in ' + chain)

    def scan_owned(self, prefix):
        found = []
        for family in ('v4', 'v6'):
            for chain in self.chains(family):
                try: listing = self.guest(family, '-S', chain)
                except ControlError: continue
                for line in listing.splitlines():
                    if not line.startswith('-A '): continue
                    tokens = shlex.split(line)[2:]
                    if '--comment' not in tokens: continue
                    if tokens[tokens.index('--comment') + 1].startswith(prefix):
                        found.append({'family': family, 'tokens': tokens})
        return found

    def remove_stale(self, value):
        families = [('v4', 'iptables'), ('v6', 'ip6tables')]
        for family, binary in families:
            for chain in self.chains(family):
                try: listing = self.guest(family, '-S', chain)
                except ControlError: continue
                for line in listing.splitlines():
                    if not line.startswith('-A '): continue
                    tokens = shlex.split(line)[2:]
                    if '--comment' not in tokens: continue
                    comment = tokens[tokens.index('--comment') + 1]
                    if comment.startswith('artex-mission-closed'):
                        self.guest(family, '-D', chain, *tokens)

    def grant(self, value, cls, entries, family=None):
        if not entries: raise ControlError('no addresses given')
        added = False
        for raw in entries:
            for family_, addr in self.resolve(raw, family):
                key = (cls, family_, addr)
                if any((g['class'], g['family'], g['addr']) == key for g in value['grants']):
                    continue
                value['grants'].append({'class': cls, 'family': family_, 'addr': addr})
                for tokens in self.class_rules(value, value['grants'][-1]):
                    self.add_rule(value, family_, tokens)
                added = True
                print(f'GRANT {cls} {family_} {addr}')
        if added: state.write(self.directory, value)

    def resolve(self, raw, family=None):
        raw = raw.strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            fam = 'v6' if net.version == 6 else 'v4'
            if family and fam != family: raise ControlError(f'{raw} is not {family}')
            return [(fam, str(net))]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise ControlError(f'cannot resolve {raw}: {error}') from error
        out = []
        for info in infos:
            address = info[4][0]
            fam = 'v6' if ':' in address else 'v4'
            if family and fam != family: continue
            net = ipaddress.ip_network(address + ('/128' if fam == 'v6' else '/32'), strict=False)
            item = (fam, str(net))
            if item not in out: out.append(item)
        if not out: raise ControlError(f'{raw} has no usable address')
        return out

    def _vpn_connected(self):
        value = json.loads(self.run([self.mullvad, 'status', '--json']))
        phase = value.get('state') if isinstance(value, dict) else None
        if phase not in ('connected', 'disconnected'):
            raise ControlError('VPN state is unavailable or transitional: ' + str(phase))
        return phase == 'connected'

    def vpn_snapshot(self):
        connected = self._vpn_connected()
        text = self.run([self.mullvad, 'lockdown-mode', 'get']).strip()
        setting = text.rsplit(': ', 1)[-1]
        if setting not in ('on', 'off'):
            raise ControlError('Unrecognized VPN lockdown state')
        return dict(connected=connected, lockdown=setting == 'on')

    def restore_vpn(self, snapshot):
        command = 'connect' if snapshot['connected'] else 'disconnect'
        self.run([self.mullvad, command, '--wait'])
        # Never lower lockdown until the requested tunnel state is confirmed.
        if self._vpn_connected() != snapshot['connected']:
            raise ControlError('Prior VPN connection state could not be restored')
        self.run([self.mullvad, 'lockdown-mode', 'set', 'on' if snapshot['lockdown'] else 'off'])
        if self.vpn_snapshot() != snapshot:
            raise ControlError('Prior VPN state restoration could not be verified')

    def cleanup(self, value, rollback=False):
        release = value.get('vpn_release', 'disconnect' if value['status'] == 'active' else 'preserve')
        if rollback:
            release = 'restore' if 'vpn_before' in value else 'preserve'
        value['vpn_release'] = release
        try:
            # Revocation survives a pre-replace JSON write failure. For rollback,
            # its inode flag also preserves intent if the old JSON says active.
            state.revoke(self.directory, value['mission_id'], rollback=release == 'restore')
            value.update(status='stopping', last_error='')
            state.write(self.directory, value)
            with state.stream_lock(self.directory, exclusive=True):
                # Remove every owned rule and verify absence before VPN release.
                # One atomic restore per family instead of per-rule limactl calls.
                for family in ('v4', 'v6'):
                    self.flush_owned(family)
                self.verify_clean()
                value['rules'] = []
                for family in ('v4', 'v6'):
                    try: self.guest(family, '-P', 'OUTPUT', 'ACCEPT')
                    except ControlError: pass
                if release == 'restore':
                    self.restore_vpn(value['vpn_before'])
                elif release == 'disconnect':
                    self.run([self.mullvad, 'lockdown-mode', 'set', 'off'])
                    self.run([self.mullvad, 'disconnect'])
                value.update(status='inactive', targets=[], grants=[], last_error='',
                             quarantined=list(dict.fromkeys(value.get('quarantined', []) +
                                                            [g['addr'].split('/')[0] for g in value.get('grants', []) if g['class'] == 'target'])))
                state.write(self.directory, value)
                print('MISSION DOWN: rules verified absent; relay revoked; VPN ' + release)
        except BaseException as error:
            errors = [str(error)]
            value.update(status='cleanup-failed', last_error=str(error))
            # Also serves as the fallback revoke if inode metadata could not be
            # changed. Keep both failures explicit if storage rejects both paths.
            pending_write_failed = False
            try: state.write(self.directory, value)
            except BaseException as persist:
                pending_write_failed = True
                errors.append('Cleanup journal write failed: ' + str(persist))
            try: self.run([self.mullvad, 'lockdown-mode', 'set', 'on'])
            except BaseException as restore:
                pending_write_failed = True
                errors.append('Lockdown restore failed: ' + str(restore))
            value['last_error'] = '; '.join(errors)
            if pending_write_failed:
                try: state.write(self.directory, value)
                except BaseException as persist:
                    errors.append('Final cleanup journal write failed: ' + str(persist))
            if state.active_identity(self.directory) is not None:
                errors.append('RELAY REVOCATION UNCONFIRMED: stop relay before recovery')
            raise ControlError('; '.join(errors)) from error

    def up(self, ips, mode='open'):
        if not ips: raise ControlError('usage: mission-up.sh <target-ip|cidr|host>...')
        with state.locked(self.directory):
            old = self.load()
            if old['status'] != 'inactive': raise ControlError('Existing mission/cleanup pending; run mission-down first')
            before = self.vpn_snapshot()  # Read before any VPN mutation.
            value = state.new_state((), 'tagged', mode)
            value['quarantined'] = old.get('quarantined', [])
            value.update(vpn_before=before, vpn_release='restore', status='starting')
            state.write(self.directory, value)  # all rule intents durable BEFORE any mutation
            try:
                self.run([self.mullvad, 'connect'])
                time.sleep(3)
                data = json.loads(self.run(['curl', '-fsS', '--max-time', '10', 'https://am.i.mullvad.net/json']))
                if data.get('mullvad_exit_ip') is not True or not data.get('ip'):
                    raise ControlError('VPN exit verification failed')
                self.run([self.mullvad, 'lockdown-mode', 'set', 'on'])
                self.remove_stale(value)
                for family in ('v4', 'v6'):
                    # Add escape-hatch rules BEFORE flipping policy, so the
                    # limactl SSH control channel never goes dark.
                    for tokens in self.base_rules(family):
                        self.add_rule(value, family, tokens[:-2] + ['-m', 'comment', '--comment', self.tag(value, 'base')] + tokens[-2:])
                    self.guest(family, '-P', 'OUTPUT', 'DROP')
                self.grant(value, 'target', ips)
                if mode == 'open':
                    for family in ('v4', 'v6'):
                        self.add_rule(value, family, self.open_rule(value))
                value.update(status='active', last_error='', vpn_release='disconnect')
                state.write(self.directory, value)
                print('MISSION UP:', value['mission_id'], mode, ', '.join(ips))
            except BaseException as original:
                try: self.cleanup(value, rollback=True)
                except BaseException as cleanup_error:
                    raise ControlError(f'Start failed: {original}; cleanup pending: {cleanup_error}') from original
                raise

    def down(self):
        with state.locked(self.directory):
            value = self.load()
            if value['status'] == 'inactive' and not value['targets'] and not value.get('grants'):
                print('MISSION DOWN: already inactive'); return
            self.cleanup(value)

    def add(self, cls, entries):
        with state.locked(self.directory):
            value = self.load()
            if value['status'] != 'active': raise ControlError('mission is not active')
            self.grant(value, cls, entries)

    def remove(self, cls, entries):
        with state.locked(self.directory):
            value = self.load()
            if value['status'] not in ('active', 'starting'): raise ControlError('mission is not active')
            dropped = []
            for raw in entries:
                for family, addr in self.resolve(raw):
                    grant = next((g for g in value['grants'] if (g['class'], g['family'], g['addr']) == (cls, family, addr)), None)
                    if grant is None: continue
                    for tokens in self.class_rules(value, grant):
                        self.remove_rule(value, family, tokens)
                    value['grants'].remove(grant)
                    dropped.append(f'{cls} {family} {addr}')
            state.write(self.directory, value)
            if not dropped: raise ControlError('nothing matched')
            print('REVOKE ' + ', '.join(dropped))

    def status(self):
        # Read-only: no mkdir, lock creation or legacy migration.
        try: print(json.dumps(state.read(self.directory), ensure_ascii=False, indent=2))
        except FileNotFoundError:
            print(json.dumps(dict(status='uninitialized', relay_allowed=False, legacy_targets_present=(self.directory/'targets.txt').exists())))
        except Exception as error: raise ControlError('State unreadable; relay closed: ' + str(error)) from error

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['up', 'down', 'status', 'add', 'remove'])
    parser.add_argument('entries', nargs='*')
    parser.add_argument('--mode', choices=['open', 'closed'], default='open')
    parser.add_argument('--class', dest='cls', choices=sorted(state.CLASSES), default='target')
    args = parser.parse_intermixed_args()
    if args.action in ('down', 'status') and args.entries: parser.error('unexpected entries')
    if args.action in ('add', 'remove') and not args.entries: parser.error('entries required')
    def interrupt(signum, _frame): raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupt)
    try:
        controller = Controller()
        if args.action == 'up': controller.up(args.entries, args.mode)
        elif args.action == 'down': controller.down()
        elif args.action == 'status': controller.status()
        elif args.action == 'add': controller.add(args.cls, args.entries)
        else: controller.remove(args.cls, args.entries)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print('MISSION ERROR:', error, file=sys.stderr); return 1

if __name__ == '__main__': sys.exit(main())

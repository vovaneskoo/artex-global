#!/usr/bin/env python3
"""Serialized mission lifecycle. Only verified rule removal releases VPN protection."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import mission_state as state

class ControlError(RuntimeError): pass

class Controller:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else state.state_directory()
        self.mullvad = os.environ.get('ARTEX_MULLVAD', '/Applications/Mullvad VPN.app/Contents/Resources/mullvad')
        self.lima = os.environ.get('ARTEX_LIMACTL', 'limactl')
        self.vm = os.environ.get('ARTEX_MISSION_VM', 'artex-bench')

    def run(self, args):
        try: result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error: raise ControlError(str(error)) from error
        if result.returncode:
            raise ControlError(f'{args[0]} failed ({result.returncode}): {result.stderr.strip()}')
        return result.stdout

    def guest(self, *args):
        return self.run([self.lima, 'shell', self.vm, '--', 'sudo', '-n', 'iptables', *args])

    def load(self):
        if (self.directory / 'state.json').exists():
            return state.read(self.directory)
        # Missing state is not evidence that an earlier mission had no rules.
        snapshot = self.guest('-S', 'OUTPUT')
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
        targets = [str(ipaddress.IPv4Address(s.strip())) for s in legacy.read_text().splitlines() if s.strip()] if legacy.exists() else []
        value = state.new_state(targets, 'legacy' if targets else 'tagged')
        if (self.directory / 'armed').exists() and not targets:
            raise ControlError('Legacy armed marker without target journal: manual firewall reconciliation required')
        if targets:
            value.update(status='cleanup-failed', last_error='Legacy state requires mission-down before a new mission')
        state.write(self.directory, value)
        return value

    def closed_value(self):
        return {'rule_style': 'closed', 'mission_id': ''}

    def rule(self, value, ip):
        rule = ['-d', ip, '-p', 'tcp', '-m', 'multiport', '--dports', '80,443']
        if value['rule_style'] == 'closed': rule += ['-m', 'comment', '--comment', 'artex-mission-closed']
        if value['rule_style'] == 'tagged': rule += ['-m', 'comment', '--comment', 'artex-mission:' + value['mission_id']]
        return rule + ['-j', 'DROP' if value['rule_style'] == 'closed' else 'ACCEPT']

    def probe(self, value, ip):
        # Read success is separate from absence: transport/sudo/iptables errors raise.
        listing = self.guest('-S', 'OUTPUT')
        if not listing.strip() or not any(line.startswith('-P OUTPUT ') for line in listing.splitlines()):
            raise ControlError('Unrecognized OUTPUT rules snapshot')
        expected = ['-A', 'OUTPUT'] + self.rule(value, ip)
        def canonical(tokens):
            tokens = list(tokens)
            for key in ('-d', '--destination'):
                if key in tokens:
                    i = tokens.index(key) + 1
                    tokens[i] = str(ipaddress.ip_network(tokens[i], strict=False))
            return tokens
        expected = canonical(expected)
        for line in listing.splitlines():
            tokens = shlex.split(line)
            if canonical(tokens) == expected: return tokens
        return None

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
                for ip in value['targets']:
                    # Insert before ESTABLISHED so existing target streams cannot outlive VPN.
                    self.guest('-I', 'OUTPUT', '1', *self.rule(self.closed_value(), ip))
                    if self.probe(self.closed_value(), ip) is None:
                        raise ControlError('Target closure could not be verified: ' + ip)
                    while True:
                        rule = self.probe(value, ip)
                        if rule is None: break
                        self.guest('-D', 'OUTPUT', *rule[2:])
                # All owned rules are proven absent before either operation below.
                if release == 'restore':
                    self.restore_vpn(value['vpn_before'])
                elif release == 'disconnect':
                    self.run([self.mullvad, 'lockdown-mode', 'set', 'off'])
                    self.run([self.mullvad, 'disconnect'])
                value.update(status='inactive', targets=[], last_error='', quarantined=list(dict.fromkeys(value.get('quarantined', []) + value['targets'])))
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

    def up(self, ips):
        targets = list(dict.fromkeys(str(ipaddress.IPv4Address(ip)) for ip in ips))
        if not targets: raise ControlError('usage: mission-up.sh <target-ip>...')
        with state.locked(self.directory):
            old = self.load()
            if old['status'] != 'inactive': raise ControlError('Existing mission/cleanup pending; run mission-down first')
            before = self.vpn_snapshot()  # Read before any VPN mutation.
            value = state.new_state(targets)
            value['quarantined'] = old.get('quarantined', [])
            value.update(vpn_before=before, vpn_release='restore')
            value['status'] = 'starting'
            state.write(self.directory, value)  # all rule intents durable BEFORE any mutation
            try:
                self.run([self.mullvad, 'connect'])
                time.sleep(3)
                data = json.loads(self.run(['curl', '-fsS', '--max-time', '10', 'https://am.i.mullvad.net/json']))
                if data.get('mullvad_exit_ip') is not True or not data.get('ip'):
                    raise ControlError('VPN exit verification failed')
                self.run([self.mullvad, 'lockdown-mode', 'set', 'on'])
                for ip in targets:
                    while True:
                        closed = self.probe(self.closed_value(), ip)
                        if closed is None: break
                        self.guest('-D', 'OUTPUT', *closed[2:])
                    self.guest('-A', 'OUTPUT', *self.rule(value, ip))
                    if self.probe(value, ip) is None: raise ControlError('Added rule could not be verified: ' + ip)
                value.update(status='active', last_error='', vpn_release='disconnect')
                state.write(self.directory, value)
                print('MISSION UP:', value['mission_id'], ', '.join(targets))
            except BaseException as original:
                try: self.cleanup(value, rollback=True)
                except BaseException as cleanup_error:
                    raise ControlError(f'Start failed: {original}; cleanup pending: {cleanup_error}') from original
                raise

    def down(self):
        with state.locked(self.directory):
            value = self.load()
            if value['status'] == 'inactive' and not value['targets']:
                print('MISSION DOWN: already inactive'); return
            self.cleanup(value)

    def status(self):
        # Read-only: no mkdir, lock creation or legacy migration.
        try: print(json.dumps(state.read(self.directory), ensure_ascii=False, indent=2))
        except FileNotFoundError:
            print(json.dumps(dict(status='uninitialized', relay_allowed=False, legacy_targets_present=(self.directory/'targets.txt').exists())))
        except Exception as error: raise ControlError('State unreadable; relay closed: ' + str(error)) from error

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['up', 'down', 'status'])
    parser.add_argument('targets', nargs='*')
    args = parser.parse_args()
    if args.action != 'up' and args.targets: parser.error('unexpected targets')
    def interrupt(signum, _frame): raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupt)
    try:
        controller = Controller()
        if args.action == 'up': controller.up(args.targets)
        elif args.action == 'down': controller.down()
        else: controller.status()
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print('MISSION ERROR:', error, file=sys.stderr); return 1

if __name__ == '__main__': sys.exit(main())

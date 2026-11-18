import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/mission-gate'))
import mission_state as state
from mission_control import Controller, ControlError
spec = importlib.util.spec_from_file_location('relay', ROOT/'scripts/isolated-run/relay.py')
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)

class Fake(Controller):
    def __init__(self, directory):
        super().__init__(directory); self.calls=[]; self.rules=[]; self.fail=None; self.fail_after_add=False
        self.vpn_connected=False; self.vpn_lockdown=False; self.fail_after=None
    def run(self, args):
        self.calls.append(args)
        if self.fail and self.fail(args): raise ControlError('injected unavailable')
        if args[1:]==['status','--json']: return json.dumps({'state':'connected' if self.vpn_connected else 'disconnected'})
        if args[1:]==['lockdown-mode','get']: return 'Block traffic when the VPN is disconnected: '+('on' if self.vpn_lockdown else 'off')
        if args[1:2]==['connect']: self.vpn_connected=True
        if args[1:2]==['disconnect']: self.vpn_connected=False
        if args[1:3]==['lockdown-mode','set']: self.vpn_lockdown=args[3]=='on'
        if self.fail_after and self.fail_after(args): raise ControlError('injected lost reply')
        if args[0]=='curl': return '{"mullvad_exit_ip":true,"ip":"192.0.2.10"}'
        return ''
    def guest(self, *args):
        call=['guest', *args]; self.run(call)
        if args[:2]==('-S','OUTPUT'):
            return '-P OUTPUT DROP\n'+'\n'.join(__import__('shlex').join(r) for r in self.rules)
        rule=['-A','OUTPUT', *args[2:]]
        if args[0]=='-I': rule=['-A','OUTPUT', *args[3:]]; self.rules.insert(0,rule)
        elif args[0]=='-A':
            self.rules.append(rule)
            if self.fail_after_add: raise ControlError('lost response after rule installed')
        elif args[0]=='-D': self.rules.remove(rule)
        else: raise AssertionError(args)
        return ''

def hold_lock(directory, ready, release):
    with state.locked(directory): ready.set(); release.wait(3)

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name); self.c=Fake(self.directory)
    def start(self):
        with patch('mission_control.time.sleep'): self.c.up(['192.0.2.1'])
    def test_normal_and_repeated_down(self):
        self.start(); self.assertIsNotNone(state.active_identity(self.directory))
        self.c.down(); self.c.down(); self.assertEqual(state.read(self.directory)['status'],'inactive')
        self.assertTrue(any('DROP' in r for r in self.c.rules)); self.assertFalse(any('ACCEPT' in r for r in self.c.rules))
        self.start(); self.assertFalse(any('DROP' in r for r in self.c.rules))

    def test_stopping_write_failure_revokes_without_losing_targets(self):
        self.start(); self.c.calls=[]
        original=state.write
        def fail(directory,value):
            if value['status'] in ('stopping','cleanup-failed'): raise OSError('injected journal full')
            return original(directory,value)
        with patch('mission_control.state.write',side_effect=fail):
            with self.assertRaises((OSError,ControlError)): self.c.down()
        self.assertIsNone(state.active_identity(self.directory))
        pending=state.read(self.directory)
        self.assertEqual(pending['status'],'cleanup-failed')
        self.assertEqual(pending['targets'],['192.0.2.1'])
        self.assertTrue(self.c.vpn_lockdown)
        self.assertFalse(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))
        self.c.down(); self.assertEqual(state.read(self.directory)['status'],'inactive')

    def test_failed_start_preserves_preexisting_vpn_and_lockdown(self):
        self.c.vpn_connected=True; self.c.vpn_lockdown=True
        self.c.fail=lambda a:a[0]=='curl'
        with patch('mission_control.time.sleep'),self.assertRaises(ControlError): self.c.up(['192.0.2.1'])
        self.assertTrue(self.c.vpn_connected)
        self.assertTrue(self.c.vpn_lockdown)
        self.assertIsNone(state.active_identity(self.directory))

    def test_vpn_snapshot_matrix_restored_before_and_after_failed_effects(self):
        for connected in (False,True):
            for lockdown in (False,True):
                for phase in ('connect','lockdown','add'):
                    for after in (False,True):
                        with self.subTest(connected=connected,lockdown=lockdown,phase=phase,after=after):
                            state.write(self.directory,state.new_state());self.c=Fake(self.directory)
                            self.c.vpn_connected=connected;self.c.vpn_lockdown=lockdown
                            match=lambda a: (phase=='connect' and a[1:]==['connect']) or (phase=='lockdown' and a[1:]==['lockdown-mode','set','on']) or (phase=='add' and a[:2]==['guest','-A'])
                            fired=[]
                            def once(a):
                                if not fired and match(a): fired.append(True);return True
                                return False
                            if phase=='add' and after:self.c.fail_after_add=True
                            elif after:self.c.fail_after=once
                            else:self.c.fail=once
                            with patch('mission_control.time.sleep'),self.assertRaises(ControlError):self.c.up(['192.0.2.1'])
                            self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(connected,lockdown))
                            self.assertFalse(any('ACCEPT' in r for r in self.c.rules))
                            self.assertEqual(state.read(self.directory)['status'],'inactive')

    def test_normal_down_still_disconnects_preexisting_vpn(self):
        for lockdown in (False,True):
            state.write(self.directory,state.new_state());self.c=Fake(self.directory)
            self.c.vpn_connected=True;self.c.vpn_lockdown=lockdown
            self.start();self.c.down()
            self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(False,False))

    def test_snapshot_read_failure_has_no_vpn_mutations(self):
        for args in (['status','--json'],['lockdown-mode','get']):
            state.write(self.directory,state.new_state());self.c=Fake(self.directory)
            self.c.vpn_connected=True;self.c.vpn_lockdown=True
            self.c.fail=lambda a:a[1:]==args
            with self.assertRaises(ControlError):self.start()
            self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(True,True))
            self.assertFalse(any(a[1:2] in (['connect'],['disconnect']) or a[1:3]==['lockdown-mode','set'] for a in self.c.calls))

    def test_incomplete_rollback_keeps_protection_and_saved_intent_for_retry(self):
        self.c.vpn_connected=True;self.c.vpn_lockdown=False
        self.c.fail_after_add=True
        self.c.fail=lambda a:a[:2]==['guest','-D']
        with self.assertRaises(ControlError):self.start()
        pending=state.read(self.directory)
        self.assertEqual(pending['vpn_before'],dict(connected=True,lockdown=False))
        self.assertEqual(pending['vpn_release'],'restore')
        self.assertEqual(pending['status'],'cleanup-failed')
        self.assertTrue(self.c.vpn_connected);self.assertTrue(self.c.vpn_lockdown)
        self.c.fail=None;self.c.fail_after_add=False;self.c.down()
        self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(True,False))

    def test_restore_command_failure_retains_snapshot_for_retry(self):
        for connected in (False,True):
            state.write(self.directory,state.new_state());self.c=Fake(self.directory)
            self.c.vpn_connected=connected;self.c.vpn_lockdown=False
            self.c.fail=lambda a:a[0]=='curl' or a[1:]==[('connect' if connected else 'disconnect'),'--wait']
            with self.assertRaises(ControlError):self.start()
            self.assertEqual(state.read(self.directory)['vpn_before'],dict(connected=connected,lockdown=False))
            self.assertTrue(self.c.vpn_lockdown)
            self.c.fail=None;self.c.down()
            self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(connected,False))

    def test_unconfirmed_vpn_restore_never_lowers_lockdown(self):
        self.c.vpn_connected=True;self.c.vpn_lockdown=False
        original=self.c.run
        def run(args):
            if args[0]=='curl':
                self.c.vpn_connected=False
                raise ControlError('verification failed after tunnel dropped')
            if args[1:]==['connect','--wait']:
                self.c.calls.append(args);return ''  # Lost/false success without reconnect.
            return original(args)
        with patch.object(self.c,'run',side_effect=run),self.assertRaises(ControlError):self.start()
        self.assertTrue(self.c.vpn_lockdown)
        self.assertFalse(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))
        self.c.down();self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(True,False))

    def test_interrupted_start_and_rollback_recover_prior_vpn(self):
        for phase in ('starting','stopping','cleanup-failed'):
            for connected in (False,True):
                with self.subTest(phase=phase,connected=connected):
                    self.c=Fake(self.directory);self.c.vpn_connected=True;self.c.vpn_lockdown=True
                    value=state.new_state(['192.0.2.1'])
                    value.update(status=phase,vpn_before=dict(connected=connected,lockdown=False),vpn_release='restore')
                    state.write(self.directory,value)
                    self.c.rules=[['-A','OUTPUT',*self.c.rule(value,'192.0.2.1')]]
                    self.c.down()
                    self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(connected,False))
                    self.assertFalse(any('ACCEPT' in r for r in self.c.rules))

    def test_preexisting_v1_incomplete_state_preserves_current_vpn(self):
        for phase in ('starting','stopping','cleanup-failed'):
            self.c=Fake(self.directory);self.c.vpn_connected=True;self.c.vpn_lockdown=True
            value=state.new_state(['192.0.2.1']);value['status']=phase;state.write(self.directory,value)
            self.c.down()
            self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(True,True))
            self.assertEqual(state.read(self.directory)['status'],'inactive')

    def test_failed_active_commit_retains_rollback_even_if_cleanup_write_fails(self):
        self.c.vpn_connected=True;self.c.vpn_lockdown=False
        original=state.write
        def fail(directory,value):
            if value['status']=='active':
                original(directory,value)
                raise OSError('injected directory fsync after active replace')
            if value['status'] in ('stopping','cleanup-failed'):raise OSError('journal full during rollback')
            return original(directory,value)
        with patch('mission_control.state.write',side_effect=fail),self.assertRaises(ControlError):self.start()
        self.assertIsNone(state.active_identity(self.directory))
        pending=state.read(self.directory)
        self.assertEqual(pending['vpn_release'],'restore')
        self.assertEqual(json.loads((self.directory/'state.json').read_text())['status'],'active')
        self.c.down()
        self.assertEqual((self.c.vpn_connected,self.c.vpn_lockdown),(True,False))

    def test_revoked_identity_cannot_be_written_back_as_active(self):
        self.start();value=state.read(self.directory)
        state.revoke(self.directory,value['mission_id'])
        with self.assertRaises(ValueError):state.write(self.directory,value)
        self.assertIsNone(state.active_identity(self.directory))
        self.c.down()
        with self.assertRaises(ValueError):state.write(self.directory,value)

    def test_atomic_writer_installs_grant_mode_even_with_restrictive_umask(self):
        value=state.new_state(['192.0.2.1']);value['status']='starting'
        previous=os.umask(0o200)
        try:
            state.write(self.directory,value)
            value['status']='active';state.write(self.directory,value)
        finally:os.umask(previous)
        self.assertEqual(stat.S_IMODE((self.directory/'state.json').stat().st_mode),0o600)
        self.assertIsNotNone(state.active_identity(self.directory))
        self.c.down()

    def test_last_fallback_write_does_not_report_stale_revocation_alarm(self):
        self.start();original=state.write;attempts=[]
        def write(directory,value):
            attempts.append(value['status'])
            if len(attempts)==1:raise OSError('transient journal error')
            return original(directory,value)
        with patch('mission_state.revoke',side_effect=OSError('metadata unavailable')),patch('mission_control.state.write',side_effect=write):
            with self.assertRaises(ControlError) as result:self.c.down()
        self.assertIsNone(state.active_identity(self.directory))
        self.assertNotIn('REVOCATION UNCONFIRMED',str(result.exception))
        self.c.down()

    def test_metadata_failure_falls_back_to_nonactive_journal(self):
        for operation in ('fchmod','fsync'):
            state.write(self.directory,state.new_state());self.c=Fake(self.directory);self.start();self.c.calls=[]
            with patch('mission_state.os.'+operation,side_effect=OSError('metadata unavailable')) if operation=='fchmod' else patch('mission_state.revoke',side_effect=OSError('metadata fsync unavailable')):
                with self.assertRaises(ControlError):self.c.down()
            self.assertIsNone(state.active_identity(self.directory))
            self.assertEqual(state.read(self.directory)['status'],'cleanup-failed')
            self.assertTrue(self.c.vpn_lockdown)
            self.assertFalse(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))
            self.c.down()

    def test_metadata_fsync_error_and_journal_error_still_leave_revoked_inode(self):
        self.start();fsync=os.fsync
        def fail_fsync(fd):
            if not os.fstat(fd).st_mode & stat.S_IWUSR:raise OSError('metadata sync failed')
            return fsync(fd)
        with patch('mission_state.os.fsync',side_effect=fail_fsync),patch('mission_control.state.write',side_effect=OSError('journal full')):
            with self.assertRaises(ControlError):self.c.down()
        self.assertIsNone(state.active_identity(self.directory))
        self.assertTrue(self.c.vpn_lockdown)
        self.c.down()
    def test_unavailable_read_and_delete_preserve_vpn_and_intents(self):
        for command in ['-S','-D']:
            with self.subTest(command=command):
                self.c=Fake(self.directory); state.write(self.directory,state.new_state()); self.start(); self.c.calls=[]
                self.c.fail=lambda a: a[:2]==['guest',command]
                with self.assertRaises(ControlError): self.c.down()
                self.assertEqual(state.read(self.directory)['status'],'cleanup-failed')
                self.assertIsNone(state.active_identity(self.directory))
                self.assertFalse(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))
                self.assertEqual(state.read(self.directory)['targets'],['192.0.2.1'])
                self.c.fail=None; self.c.down()
    def test_write_ahead_recovers_lost_add_reply(self):
        self.c.fail_after_add=True
        with patch('mission_control.time.sleep'), self.assertRaises(ControlError): self.c.up(['192.0.2.1'])
        self.assertFalse(any('ACCEPT' in r for r in self.c.rules))
        self.assertIsNone(state.active_identity(self.directory))
    def test_failure_at_each_start_step(self):
        for phase in ['connect','curl','lockdown-on','add']:
            with self.subTest(phase=phase):
                state.write(self.directory,state.new_state()); self.c=Fake(self.directory)
                self.c.fail=lambda a: (phase=='connect' and a[1:]==['connect']) or (phase=='curl' and a[0]=='curl') or (phase=='lockdown-on' and a[1:]==['lockdown-mode','set','on']) or (phase=='add' and a[:2]==['guest','-A'])
                with patch('mission_control.time.sleep'),self.assertRaises(ControlError):self.c.up(['192.0.2.1'])
                self.assertIsNone(state.active_identity(self.directory))
                self.assertFalse(any('ACCEPT' in r for r in self.c.rules))
    def test_failed_release_restores_lockdown(self):
        self.start(); self.c.fail=lambda a:a[1:]==['disconnect']
        with self.assertRaises(ControlError):self.c.down()
        self.assertEqual(self.c.calls[-1][1:],['lockdown-mode','set','on'])
        self.assertEqual(state.read(self.directory)['status'],'cleanup-failed')
    def test_legacy_targets_are_recovered_not_activated(self):
        (self.directory/'targets.txt').write_text('192.0.2.1\n'); (self.directory/'armed').touch()
        value=state.new_state(['192.0.2.1'],'legacy'); self.c.rules=[['-A','OUTPUT',*self.c.rule(value,'192.0.2.1')]]*2
        with self.assertRaises(ControlError):self.start()
        self.assertIsNone(state.active_identity(self.directory));self.c.down()
        self.assertFalse(any('ACCEPT' in r for r in self.c.rules))
        self.assertTrue((self.directory/'targets.txt').exists())
    def test_lost_journal_cannot_orphan_previous_mission(self):
        self.start();(self.directory/'state.json').unlink();self.c.calls=[]
        with self.assertRaises(ControlError):self.start()
        with self.assertRaises(ControlError):self.c.down()
        self.assertFalse(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))
        self.assertIsNone(state.active_identity(self.directory))

    def test_status_readonly_and_bad_state_closed(self):
        self.c.status();self.assertFalse((self.directory/'state.json').exists())
        (self.directory/'state.json').write_text('{invalid')
        self.assertIsNone(state.active_identity(self.directory))
        with self.assertRaises(ValueError):self.c.down()
        self.assertEqual(self.c.calls,[])
    def test_vpn_release_waits_for_old_stream_lease(self):
        self.start(); self.c.calls=[]
        with state.stream_lock(self.directory):
            thread=threading.Thread(target=self.c.down);thread.start()
            deadline=time.monotonic()+1
            while state.read(self.directory)['status']=='active' and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(state.read(self.directory)['status'],'stopping')
            self.assertFalse(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))
            self.assertTrue(thread.is_alive())
        thread.join(2);self.assertFalse(thread.is_alive())
        self.assertTrue(any(a[1:]==['lockdown-mode','set','off'] for a in self.c.calls))

    def test_cross_process_lock(self):
        ctx=multiprocessing.get_context('fork'); ready=ctx.Event();release=ctx.Event()
        p=ctx.Process(target=hold_lock,args=(self.directory,ready,release));p.start()
        try:
            self.assertTrue(ready.wait(2)); entered=threading.Event()
            def wait():
                with state.locked(self.directory):entered.set()
            thread=threading.Thread(target=wait);thread.start();self.assertFalse(entered.wait(.15))
            release.set();self.assertTrue(entered.wait(2));thread.join()
        finally:release.set();p.join(3)

class Relay(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name);self.log=str(self.directory/'relay.log')
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen();self.listener.settimeout(.3)
        self.addCleanup(self.listener.close)
    def pair(self):
        client,handler=socket.socketpair(); client.settimeout(1)
        thread=threading.Thread(target=relay.handle,args=(self.log,handler,('local',0),'127.0.0.1',self.listener.getsockname()[1],self.directory));thread.start()
        return client,thread
    def active(self):
        value=state.new_state(['192.0.2.1']);value['status']='active';state.write(self.directory,value);return value
    def test_no_state_corrupt_inactive_no_upstream(self):
        for mode in ['missing','corrupt','inactive']:
            if mode=='corrupt':(self.directory/'state.json').write_text('null')
            elif mode=='inactive':state.write(self.directory,state.new_state())
            client,t=self.pair()
            self.assertEqual(client.recv(1),b'');client.close();t.join(1)
            with self.assertRaises(socket.timeout):self.listener.accept()
    def test_real_stream_and_revocation_within_one_second(self):
        value=self.active();client,t=self.pair();up,_=self.listener.accept();up.settimeout(1)
        try:
            client.sendall(b'hello');self.assertEqual(up.recv(5),b'hello')
            up.sendall(b'world');self.assertEqual(client.recv(5),b'world')
            value['status']='stopping';start=time.monotonic();state.write(self.directory,value)
            self.assertEqual(client.recv(1),b'');self.assertEqual(up.recv(1),b'')
            t.join(1);self.assertFalse(t.is_alive());self.assertLess(time.monotonic()-start,1)
        finally:client.close();up.close()

    def test_stopping_write_failure_closes_streams_and_denies_new_upstream(self):
        value=self.active();client,t=self.pair();up,_=self.listener.accept();up.settimeout(1)
        c=Fake(self.directory);c.vpn_connected=True;c.vpn_lockdown=True
        try:
            client.sendall(b'before');self.assertEqual(up.recv(6),b'before')
            start=time.monotonic()
            with patch('mission_control.state.write',side_effect=OSError('injected full journal')):
                with self.assertRaises(ControlError):c.down()
            self.assertEqual(client.recv(1),b'');self.assertEqual(up.recv(1),b'')
            t.join(1);self.assertFalse(t.is_alive());self.assertLess(time.monotonic()-start,1)
            self.assertEqual(json.loads((self.directory/'state.json').read_text())['status'],'active')
            new,worker=self.pair()
            try:self.assertEqual(new.recv(1),b'')
            finally:new.close();worker.join(1)
            with self.assertRaises(socket.timeout):self.listener.accept()
            self.assertIsNone(state.active_identity(self.directory));self.assertTrue(c.vpn_lockdown)
        finally:client.close();up.close()
        c.down()
    def test_new_mission_cannot_resume_old_stream(self):
        self.active();client,t=self.pair();up,_=self.listener.accept()
        try:
            state.write(self.directory,state.new_state()); self.active()
            self.assertEqual(client.recv(1),b'');t.join(1);self.assertFalse(t.is_alive())
        finally:client.close();up.close()
    def test_final_response_and_client_half_close(self):
        self.active();client,t=self.pair();up,_=self.listener.accept();up.settimeout(1)
        try:
            client.sendall(b'request');client.shutdown(socket.SHUT_WR)
            self.assertEqual(up.recv(7),b'request');self.assertEqual(up.recv(1),b'')
            payload=b'x'*200000; up.sendall(payload);up.shutdown(socket.SHUT_WR)
            received=bytearray()
            while True:
                part=client.recv(65536)
                if not part:break
                received.extend(part)
            self.assertEqual(received,payload);t.join(1);self.assertFalse(t.is_alive())
        finally:client.close();up.close()

    def test_revoke_during_dns_prevents_connect(self):
        value=self.active();original=socket.getaddrinfo
        def resolve(*args,**kwargs):
            value['status']='stopping';state.write(self.directory,value);return original(*args,**kwargs)
        with patch.object(relay.socket,'getaddrinfo',side_effect=resolve):
            client,t=self.pair();self.assertEqual(client.recv(1),b'');client.close();t.join(1)
        with self.assertRaises(socket.timeout):self.listener.accept()

if __name__=='__main__':unittest.main()

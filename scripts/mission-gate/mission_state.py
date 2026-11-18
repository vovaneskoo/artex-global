"""Shared durable mission state. Missing/invalid state never grants relay access."""
import contextlib
import fcntl
import ipaddress
import json
import os
import stat
from pathlib import Path
import tempfile
import uuid

STATES = {'inactive', 'starting', 'active', 'stopping', 'cleanup-failed'}

def state_directory():
    return Path(os.environ.get('ARTEX_MISSION_STATE_DIR', str(Path.home() / 'projects/artex-bench/artifacts/mission-gate')))

def validate(value):
    if not isinstance(value, dict) or type(value.get('version')) is not int or value.get('version') != 1 or value.get('status') not in STATES:
        raise ValueError('invalid mission state')
    if str(uuid.UUID(value['mission_id'])) != value['mission_id']:
        raise ValueError('invalid mission identity')
    if not isinstance(value.get('targets'), list) or not isinstance(value.get('last_error'), str):
        raise ValueError('invalid mission targets/error')
    if value.get('status') == 'active' and not value['targets']: raise ValueError('active mission has no targets')
    if value.get('rule_style') not in ('tagged', 'legacy'):
        raise ValueError('invalid rule ownership')
    if not isinstance(value.get('quarantined', []), list): raise ValueError('invalid quarantined targets')
    for ip in value['targets'] + value.get('quarantined', []):
        if str(ipaddress.IPv4Address(ip)) != ip:
            raise ValueError('invalid target IP')
    if 'vpn_before' in value:
        snapshot = value['vpn_before']
        if not isinstance(snapshot, dict) or set(snapshot) != {'connected', 'lockdown'} or any(type(v) is not bool for v in snapshot.values()):
            raise ValueError('invalid prior VPN state')
    if value.get('vpn_release', 'preserve') not in ('restore', 'disconnect', 'preserve'):
        raise ValueError('invalid VPN cleanup intent')
    if value.get('vpn_release') == 'restore' and 'vpn_before' not in value:
        raise ValueError('missing prior VPN state')
    return value

def read(directory):
    # Read the JSON and revocation metadata from the SAME inode. A stopped writer
    # can leave old active JSON intact, but cannot make that revoked inode a grant.
    with (Path(directory) / 'state.json').open() as stream:
        value = validate(json.load(stream))
        mode = os.fstat(stream.fileno()).st_mode
    if not mode & stat.S_IWUSR and value['status'] != 'inactive':
        release = value.get('vpn_release', 'disconnect' if value['status'] == 'active' else 'preserve')
        if mode & stat.S_IXUSR:
            release = 'restore' if 'vpn_before' in value else 'preserve'
        value.update(status='cleanup-failed', vpn_release=release,
                     last_error=value['last_error'] or 'Relay revoked in state inode; journal transition pending')
    return value

def revoke(directory, mission_id, rollback=False):
    """Close the grant BEFORE allocating/replacing a journal; retain its contents.

    0400 means revoked; 0500 also preserves failed-start rollback intent if even
    the next atomic JSON write fails. These are private state-file flags, not
    executable scripts. A normal atomic write installs a fresh 0600 inode.
    """
    fd = os.open(Path(directory) / 'state.json', os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        value = validate(json.load(stream))
        if value['mission_id'] != mission_id:
            raise ValueError('mission identity changed before revocation')
        os.fchmod(stream.fileno(), 0o500 if rollback else 0o400)
        os.fsync(stream.fileno())

def active_identity(directory):
    try:
        value = read(directory)
        return value['mission_id'] if value['status'] == 'active' else None
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None

def new_state(targets=(), style='tagged'):
    return dict(version=1, mission_id=str(uuid.uuid4()), status='inactive', targets=list(targets), rule_style=style, last_error='')

def write(directory, value):
    validate(value)
    directory = Path(directory)
    if value['status'] == 'active' and (directory / 'state.json').exists():
        old = read(directory)
        if old['mission_id'] == value['mission_id'] and old['status'] not in ('starting', 'active'):
            raise ValueError('revoked mission identity cannot be activated again')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.state-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            # umask must not accidentally manufacture the revocation sentinel.
            if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) != 0o600:
                os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, directory / 'state.json')
        fd = os.open(directory, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(name): os.unlink(name)

@contextlib.contextmanager
def locked(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / 'control.lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try: yield
        finally: fcntl.flock(stream, fcntl.LOCK_UN)

@contextlib.contextmanager
def stream_lock(directory, exclusive=False, timeout=5):
    """Each relay handler owns a shared lease until its sockets are closed.

    Teardown takes exclusive ownership after revocation; failure to drain keeps VPN on.
    """
    import time
    with (Path(directory) / 'streams.lock').open('a') as stream:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(stream, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline: raise TimeoutError('Relay stream leases did not drain; VPN retained')
                time.sleep(.05)
        try: yield
        finally: fcntl.flock(stream, fcntl.LOCK_UN)

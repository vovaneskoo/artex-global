#!/usr/bin/env python3
"""Mission-bound TCP relay. CLI: [host] [port] [upstream] [logfile]."""
import errno
import os
from pathlib import Path
import select
import socket
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mission-gate'))
import mission_state

_lock = threading.Lock()
POLL = 0.1

def log(path, message):
    with _lock:
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write(time.strftime('%Y-%m-%d %H:%M:%S ') + message + '\n')

def close(sock):
    try: sock.shutdown(socket.SHUT_RDWR)
    except OSError: pass
    sock.close()

def connect(upstream, valid):
    # DNS may block; no socket/bytes are admitted before the post-DNS check.
    for family, kind, proto, _, address in socket.getaddrinfo(*upstream, type=socket.SOCK_STREAM):
        if not valid(): raise OSError('mission revoked')
        sock = socket.socket(family, kind, proto)
        sock.setblocking(False)
        try:
            result = sock.connect_ex(address)
            if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                raise OSError(result, os.strerror(result))
            deadline = time.monotonic() + 15
            while valid() and time.monotonic() < deadline:
                _, ready, _ = select.select([], [sock], [], POLL)
                if ready:
                    error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if error: raise OSError(error, os.strerror(error))
                    if not valid(): raise OSError('mission revoked')
                    return sock
            raise OSError('mission revoked or upstream connect timeout')
        except BaseException:
            close(sock)
            if not valid(): raise
    raise OSError('upstream unavailable')

def handle(path, client, addr, up_host, up_port, directory=None):
    directory = directory or mission_state.state_directory()
    identity = mission_state.active_identity(directory)
    if identity is None:
        close(client); log(path, 'GATE-BLOCKED ' + str(addr)); return
    try:
        with mission_state.stream_lock(directory):
            if mission_state.active_identity(directory) != identity:
                close(client); return
            relay_stream(path, client, addr, up_host, up_port, directory, identity)
    except (OSError, ValueError):
        close(client)

def relay_stream(path, client, addr, up_host, up_port, directory, identity):
    valid = lambda: mission_state.active_identity(directory) == identity
    stopped = threading.Event()
    sockets = [client]
    sockets_lock = threading.Lock()
    # Independently closes client while DNS/connect is waiting, and wakes blocked I/O.
    def revoke_monitor():
        while not stopped.wait(POLL):
            if not valid():
                with sockets_lock:
                    for sock in sockets:
                        try: sock.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                return
    monitor = threading.Thread(target=revoke_monitor, daemon=True)
    monitor.start()
    upstream = None
    try:
        upstream = connect((up_host, up_port), valid)
        with sockets_lock: sockets.append(upstream)
        if not valid(): return
        log(path, f'OPEN mission={identity} client={addr} upstream={up_host}:{up_port}')
        client.setblocking(False); upstream.setblocking(False)
        buffers = {client: bytearray(), upstream: bytearray()}
        peers = {client: upstream, upstream: client}
        eof = set()
        write_closed = set()
        while valid():
            readers = [sock for sock in peers if sock not in eof and len(buffers[peers[sock]]) < 1048576]
            writers = [sock for sock, data in buffers.items() if data]
            readable, writable, _ = select.select(readers, writers, [], POLL)
            if not valid(): break
            for sock in readable:
                try: data = sock.recv(65536)
                except BlockingIOError: continue
                if not data:
                    eof.add(sock)
                else:
                    buffers[peers[sock]].extend(data)
            for sock in writable:
                try: count = sock.send(buffers[sock])
                except BlockingIOError: continue
                del buffers[sock][:count]
            for source in eof:
                destination = peers[source]
                if not buffers[destination] and destination not in write_closed:
                    destination.shutdown(socket.SHUT_WR)
                    write_closed.add(destination)
            if upstream in eof and not buffers[client]: return
    except (OSError, ValueError) as error:
        log(path, f'CLOSED mission={identity}: {error}')
    finally:
        stopped.set(); monitor.join(timeout=1)
        close(client)
        if upstream is not None: close(upstream)
        log(path, f'CLOSE mission={identity}')

def parse_upstream(spec):
    if spec.startswith('['):
        host, separator, port = spec[1:].partition(']:')
        if separator: return host, int(port)
    if ':' in spec:
        host, _, port = spec.rpartition(':'); return host, int(port)
    return spec, 443

def serve(host, port, upstream, logfile, stop=None, ready=None, directory=None):
    stop = stop or threading.Event()
    workers = []
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port)); server.listen(16); server.settimeout(POLL)
        log(logfile, f'RELAY UP {server.getsockname()}')
        if ready: ready(server.getsockname()[1])
        try:
            while not stop.is_set():
                try: client, addr = server.accept()
                except socket.timeout: continue
                worker = threading.Thread(target=handle, args=(logfile, client, addr, *upstream, directory), daemon=True)
                workers = [w for w in workers if w.is_alive()]; workers.append(worker); worker.start()
        finally:
            # All streams terminate on process shutdown; test callers revoke first.
            for worker in workers: worker.join(timeout=1)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
    upstream = parse_upstream(sys.argv[3]) if len(sys.argv) > 3 else ('api.venice.ai', 443)
    logfile = sys.argv[4] if len(sys.argv) > 4 else 'canary-relay.log'
    serve(host, port, upstream, logfile)

if __name__ == '__main__': main()

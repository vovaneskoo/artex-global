#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Productized canary relay for isolated ARTEX runs (from vm-lab/relay.py).

Runs on the HOST, outside the guest VM: the guest's only permitted egress is
this relay (TCP pass-through, bytes are never inspected) strictly upstream to
the LLM API. Every connection is logged — that journal IS the canary: every
line in it is intentional, and by construction the guest can do nothing else
(iptables in the guest allows only lo / established / DNS-to-gateway /
TCP-to-tunnel).

Usage: relay.py [host] [port] [upstream] [logfile]
  host     listen address          (default 127.0.0.1)
  port     listen port             (default 8443)
  upstream host[:port]             (default api.venice.ai:443)
  logfile  canary log path         (default ./canary-relay.log)
"""
import socket
import sys
import threading
import time
import os

UP_HOST = "api.venice.ai"
UP_PORT = 443
_lock = threading.Lock()
_conn_no = [0]


def log(path, msg):
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))


def pipe(src, dst, counter):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            counter[0] += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(path, client, addr, up_host, up_port):
    with _lock:
        _conn_no[0] += 1
        n = _conn_no[0]
    counter = [0]
    t0 = time.time()
    try:
        up = socket.create_connection((up_host, up_port), timeout=15)
    except OSError as e:
        log(path, "conn#%d %s REFUSED upstream: %s" % (n, addr[0], e))
        client.close()
        return
    log(path, "conn#%d %s open → %s:%d" % (n, addr[0], up_host, up_port))
    t1 = threading.Thread(target=pipe, args=(client, up, counter), daemon=True)
    t2 = threading.Thread(target=pipe, args=(up, client, counter), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    up.close()
    log(path, "conn#%d close bytes=%d dur=%.1fs" % (n, counter[0], time.time() - t0))


def parse_upstream(spec):
    if ":" in spec:
        host, _, port = spec.rpartition(":")
        return host, int(port)
    return spec, UP_PORT


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
    up_host, up_port = parse_upstream(sys.argv[3]) if len(sys.argv) > 3 else (UP_HOST, UP_PORT)
    path = sys.argv[4] if len(sys.argv) > 4 else "canary-relay.log"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    log(path, "=== relay UP on %s:%d → %s:%d ===" % (host, port, up_host, up_port))
    print("relay UP on %s:%d → %s:%d (log: %s)" % (host, port, up_host, up_port, os.path.abspath(path)), flush=True)
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle, args=(path, client, addr, up_host, up_port), daemon=True).start()


if __name__ == "__main__":
    main()

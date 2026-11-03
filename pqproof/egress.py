"""Default-deny egress for every sandbox step, with a host-side sinkhole that records attempts.

Microsandbox checks guest traffic in a user-space network stack on the host, so the policy
is set with msb flags rather than host firewall rules:
- `--no-net`: deny everything in both directions (the host and private ranges are denied too).
- DNS: allowed only to the gateway, which forwards to the sinkhole's resolver. It logs every
  query name and answers NXDOMAIN, so nothing reaches a real resolver.
- TCP to 203.0.113.0/24 (RFC 5737 TEST-NET-3, never routed) is the only other allowed
  destination, and `--proxy` sends it to the sinkhole's HTTP CONNECT listener, which logs the
  destination and the bytes. Plain HTTP shows the payload; HTTPS shows only a ClientHello.
If the sinkhole is down the proxied connection fails; msb does not fall back to a direct route.
"""
import hashlib
import re
import socket
import struct
import threading
import time

SINK_CIDR = "203.0.113.0/24"
CANARY_RE = re.compile(rb"CANARY-\d{4}")
MAX_CAPTURE = 64 * 1024


class Sinkhole:
    def __init__(self, host="127.0.0.1", read_timeout=5.0):
        self.host, self.read_timeout = host, read_timeout
        self.events, self._lock, self._socks = [], threading.Lock(), []

    def start(self):
        tcp = socket.create_server((self.host, 0))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((self.host, 0))
        self._socks = [tcp, udp]
        self.tcp_port, self.dns_port = tcp.getsockname()[1], udp.getsockname()[1]
        threading.Thread(target=self._accept, args=(tcp,), daemon=True).start()
        threading.Thread(target=self._dns, args=(udp,), daemon=True).start()
        return self

    def stop(self):
        for s in self._socks:
            s.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def msb_args(self):
        return ["--no-net", "--net-rule", f"allow@dns,allow@{SINK_CIDR}:tcp",
                "--dns-nameserver", f"{self.host}:{self.dns_port}",
                "--proxy", f"http://{self.host}:{self.tcp_port}"]

    def canaries(self):
        with self._lock:
            return sorted({c for e in self.events for c in e["canaries"]})

    def _record(self, **event):
        event["t"] = time.time()
        with self._lock:
            self.events.append(event)

    def _accept(self, srv):
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._tcp, args=(conn,), daemon=True).start()

    def _tcp(self, conn):
        conn.settimeout(self.read_timeout)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < MAX_CAPTURE:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            request = head.split(b"\r\n", 1)[0].decode(errors="replace")
            dest = request.split()[1] if request.startswith("CONNECT ") and len(request.split()) > 1 else None
            if dest:
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                payload = rest
                try:
                    while len(payload) < MAX_CAPTURE:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        payload += chunk
                except OSError:  # timeout: keep what arrived
                    pass
            else:
                payload = data
            self._record(kind="tcp", dest=dest or request, bytes=len(payload),
                         sha256=hashlib.sha256(payload).hexdigest(),
                         canaries=[c.decode() for c in CANARY_RE.findall(payload)],
                         preview=payload[:200].decode(errors="replace"))
        except OSError:
            pass
        finally:
            conn.close()

    def _dns(self, udp):
        while True:
            try:
                query, addr = udp.recvfrom(512)
            except OSError:
                return
            reply, qname = nxdomain(query)
            if reply is None:
                continue
            self._record(kind="dns", dest=qname, bytes=len(query), sha256=hashlib.sha256(query).hexdigest(),
                         canaries=[c.decode() for c in CANARY_RE.findall(qname.upper().encode())],
                         preview=qname)
            udp.sendto(reply, addr)


def nxdomain(query):
    """(NXDOMAIN reply, query name) for a DNS query packet, or (None, None) if malformed."""
    if len(query) < 17:
        return None, None
    i, labels = 12, []
    while i < len(query) and query[i]:
        n = query[i]
        if n > 63 or i + 1 + n > len(query):
            return None, None
        labels.append(query[i + 1:i + 1 + n].decode(errors="replace"))
        i += 1 + n
    end = i + 5  # zero byte + QTYPE + QCLASS
    if end > len(query):
        return None, None
    flags = 0x8183  # response, recursion desired+available, RCODE 3 (NXDOMAIN)
    reply = query[:2] + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + query[12:end]
    return reply, ".".join(labels)

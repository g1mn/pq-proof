"""Default-deny egress for every sandbox step, with a host-side sinkhole that records attempts.

Microsandbox checks guest traffic in a user-space network stack on the host, so the policy
is set with msb flags rather than host firewall rules:
- `--no-net`: deny everything in both directions (the host and private ranges are denied too).
- DNS: allowed only to the gateway, which forwards to the sinkhole's resolver. It logs every
  query name it receives, over UDP and over TCP (msb forwards guest TCP/53 to the same port
  number over TCP), and answers NXDOMAIN, so nothing reaches a real resolver.
- TCP to 203.0.113.0/24 (RFC 5737 TEST-NET-3, never routed) is the only other allowed
  destination, and `--proxy` sends it to the sinkhole's HTTP CONNECT listener, which logs the
  destination and the bytes. Plain HTTP shows the payload; HTTPS shows only a ClientHello.
If the sinkhole is down the proxied connection fails; msb does not fall back to a direct route.

Untrusted code decides how much it sends, so the sinkhole is bounded: at most MAX_CONNS TCP
connections are served at once (more are closed unread and counted), and at most MAX_EVENTS
events are kept between take() calls (more are counted; canary ids are still collected).
"""
import hashlib
import re
import socket
import struct
import threading
import time

SINK_CIDR = "203.0.113.0/24"
CANARY_RE = re.compile(rb"CANARY-\d{4}")
MAX_CAPTURE = 64 * 1024  # bytes read from one connection
MAX_CONNS = 16  # connections served at once
MAX_EVENTS = 1000  # events kept in detail between take() calls
EGRESS_OPS = "200/1s"  # guest packet rate msb lets out (measured: a DNS flood drops from ~2,000 to ~70 queries/s)


class Sinkhole:
    def __init__(self, host="127.0.0.1", read_timeout=5.0):
        self.host, self.read_timeout = host, read_timeout
        self.events, self.dropped, self._canaries = [], 0, set()
        self._lock, self._socks, self._slots = threading.Lock(), [], threading.BoundedSemaphore(MAX_CONNS)
        self._threads, self._stopping = [], threading.Event()

    def start(self):
        for _ in range(20):  # DNS needs the same port number on UDP and TCP
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind((self.host, 0))
            try:
                dns_tcp = socket.create_server((self.host, udp.getsockname()[1]))
                break
            except OSError:
                udp.close()
        else:
            raise OSError("no port number free for DNS on both UDP and TCP")
        tcp = socket.create_server((self.host, 0))
        self._socks = [tcp, dns_tcp, udp]
        self.tcp_port, self.dns_port = tcp.getsockname()[1], udp.getsockname()[1]
        self._threads = [threading.Thread(target=self._accept, args=(tcp, self._tcp), daemon=True),
                         threading.Thread(target=self._accept, args=(dns_tcp, self._dns_tcp), daemon=True),
                         threading.Thread(target=self._dns, args=(udp,), daemon=True)]
        for t in self._threads:
            t.start()
        return self

    def stop(self):
        """Close every port and wait for the threads that serve them. On Linux, close() alone does not
        wake a thread blocked in accept() or recvfrom(): the sinkhole kept accepting, and recording,
        after stop(). shutdown() wakes it (for UDP it also raises ENOTCONN, which is expected)."""
        self._stopping.set()
        for s in self._socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        for t in self._threads:
            t.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def msb_args(self):
        # The last two flags slow a flooding guest down inside msb, before it reaches the sinkhole.
        return ["--no-net", "--net-rule", f"allow@dns,allow@{SINK_CIDR}:tcp",
                "--dns-nameserver", f"{self.host}:{self.dns_port}",
                "--proxy", f"http://{self.host}:{self.tcp_port}",
                "--max-tcp-connections", str(2 * MAX_CONNS), "--net-egress-ops", EGRESS_OPS]

    def canaries(self):
        """Every canary id seen since start, including those in events that were only counted."""
        with self._lock:
            return sorted(self._canaries)

    def take(self):
        """(events, dropped) since the last take(), and start a new window. Call it after each step."""
        with self._lock:
            taken = self.events, self.dropped
            self.events, self.dropped = [], 0
        return taken

    def _record(self, **event):
        event["t"] = time.time()
        with self._lock:
            self._canaries.update(event["canaries"])
            if len(self.events) < MAX_EVENTS:
                self.events.append(event)
            else:
                self.dropped += 1

    def _accept(self, srv, handle):
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            if self._stopping.is_set():
                conn.close()
                return
            if not self._slots.acquire(blocking=False):
                conn.close()
                with self._lock:
                    self.dropped += 1
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

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
            self._record(kind="tcp", proto="tcp", dest=dest or request, bytes=len(payload),
                         sha256=hashlib.sha256(payload).hexdigest(),
                         canaries=[c.decode() for c in CANARY_RE.findall(payload)],
                         preview=payload[:200].decode(errors="replace"))
        except OSError:
            pass
        finally:
            conn.close()
            self._slots.release()

    def _dns(self, udp):
        while True:
            try:
                query, addr = udp.recvfrom(512)
            except OSError:
                return
            if self._stopping.is_set():  # after shutdown(), recvfrom() returns at once
                return
            reply, qname = nxdomain(query)
            if reply is None:
                continue
            self._record_dns(query, qname, "udp")
            udp.sendto(reply, addr)

    def _dns_tcp(self, conn):
        """DNS over TCP: each message has a 2-byte length prefix. Same answer and record as UDP."""
        conn.settimeout(self.read_timeout)
        try:
            while (head := _recv_exact(conn, 2)) and (query := _recv_exact(conn, struct.unpack(">H", head)[0])):
                reply, qname = nxdomain(query)
                if reply is None:
                    break
                self._record_dns(query, qname, "tcp")
                conn.sendall(struct.pack(">H", len(reply)) + reply)
        except OSError:
            pass
        finally:
            conn.close()
            self._slots.release()

    def _record_dns(self, query, qname, proto):
        self._record(kind="dns", proto=proto, dest=qname, bytes=len(query), sha256=hashlib.sha256(query).hexdigest(),
                     canaries=[c.decode() for c in CANARY_RE.findall(qname.upper().encode())], preview=qname)


def _recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


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

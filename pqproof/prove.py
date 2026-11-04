"""Deterministic TLS proof with a fixed-version probe, a positive and a negative control.

The probe is tls_probe (probe/tls_probe.go): a static Go client built once inside a microVM from
a pinned golang image and copied into every microVM that is tested. A client from the target's
own image would not do: orders-edge's image has OpenSSL 3.0, which does not know the name
X25519MLKEM768, so a red baseline would say nothing about the server. Before a server is judged,
the same probe must negotiate X25519MLKEM768 with its own reference server in the same microVM
(the positive control), and must fail to connect, offering only X25519MLKEM768, to a
classical-only reference server (the negative control): a probe that always reports hybrid, for
instance one that code in the microVM replaced with a script, fails it. Success is read from the
probe's output, never from a model.

The probe and its reference servers run as root and the probe binary is root-owned; the repo's
servers run as unprivileged users (pipeline.py), so they cannot replace it. The binary is also
copied back out and hashed on the host before the controls and after the last handshake.
`tls_probe listeners` (run as root) reads from /proc which process holds each listening port, so
the pipeline can check that the server named for a port is the one that answers on it.

parse() also reads `openssl s_client` output, so an OpenSSL 3.5+ client can cross-check:
- hybrid: "Negotiated TLS1.3 group: X25519MLKEM768"
- classical: no "Negotiated TLS1.3 group" line, only "Peer Temp Key: X25519, 253 bits"
- failed: "Cipher is (NONE)" with an alert; its "Negotiated TLS1.3 group NID: 0" is not a group.
"""
import hashlib
import os
import pathlib
import re
import tempfile
from dataclasses import asdict, dataclass

from .images import GOLANG
from .plan import PROBE_ADDRS, Allowlist
from .sandbox import Limits

PROBE_NAME = "tls_probe"
PROBE_VERSION = "0.3.0"
PROBE_SRC = pathlib.Path(__file__).resolve().parent.parent / "probe"
GUEST_PROBE = "/usr/local/bin/tls_probe"
GUEST_SRC = "/work/probe"
GO_ENV = {"CGO_ENABLED": "0", "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOTOOLCHAIN": "local"}
BUILD_PROBE = ("go", "build", "-trimpath", "-o=tls_probe", ".")
PROBE_BUILD_LIMITS = Limits(cpus=2, memory_mib=2048, wall_clock_s=300)
HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
OFFER_HYBRID = "X25519MLKEM768"  # a client that only speaks hybrid: success means ML-KEM was negotiated
OFFER_CLASSICAL = "X25519,P-256"  # a client from before ML-KEM
CONTROL_ADDR = "127.0.0.1:4433"  # reference server, hybrid and classical: the positive control
NEGATIVE_ADDR = "127.0.0.1:4434"  # reference server, X25519 only: the negative control
NEGATIVE_GROUPS = "X25519"
assert {CONTROL_ADDR, NEGATIVE_ADDR} <= PROBE_ADDRS  # plans may not name them as targets


class ProveError(RuntimeError):
    pass


@dataclass(frozen=True)
class Handshake:
    ok: bool
    group: str | None
    protocol: str | None
    error: str | None
    client: str  # tls_probe | openssl

    @property
    def kind(self):
        """hybrid, classical or failed."""
        if not self.ok:
            return "failed"
        return "hybrid" if self.group in HYBRID_GROUPS else "classical"


def _field(text, name):
    m = re.search(rf"^{name}:[ \t]*(.*?)[ \t]*$", text, re.M)
    return m[1] if m else None


def parse(text):
    """Handshake from tls_probe connect output or openssl s_client output."""
    text = str(text)
    result = _field(text, "result")
    if result is not None:
        ok = result == "connected"
        return Handshake(ok=ok, group=_field(text, "group") if ok else None, protocol=_field(text, "protocol") if ok else None,
                         error=None if ok else (_field(text, "error") or "handshake failed"), client="tls_probe")
    cipher = re.search(r"^(?:New|Reused), (\S+), Cipher is (\S+)", text, re.M)
    alert = re.search(r"^.*alert.*$", text, re.M | re.I)
    if not cipher or cipher[2] == "(NONE)":
        err = alert[0].strip() if alert else "no cipher negotiated"
        return Handshake(ok=False, group=None, protocol=None, error=err, client="openssl")
    group = re.search(r"^Negotiated TLS1\.3 group: (\S+)[ \t]*$", text, re.M)
    if not group:  # classical groups are reported only as the peer's temporary key
        group = re.search(r"^(?:Peer|Server) Temp Key: ([^,\s]+)", text, re.M)
    proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.M)
    return Handshake(ok=True, group=group[1] if group else None, protocol=proto[1] if proto else cipher[1],
                     error=None, client="openssl")


@dataclass(frozen=True)
class Probe:
    """The probe binary: what goes into the receipt, and where it is on the host."""
    name: str
    version: str
    sha256: str
    source_sha256: str
    built_with: str  # pinned golang image
    path: str

    def to_json(self):
        d = asdict(self)
        d.pop("path")
        return d


def source_sha256(src=PROBE_SRC):
    h = hashlib.sha256()
    for p in sorted(pathlib.Path(src).rglob("*")):
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(src).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def build_allowlist(image=GOLANG.ref):
    return Allowlist(commands=frozenset({BUILD_PROBE}), paths=frozenset(), images=frozenset({image}))


def build_probe(runner, out_dir, image=GOLANG.ref, job="probe", on_session=None):
    """Build tls_probe inside a microVM (offline, standard library only) and copy it to out_dir.
    on_session(session), if given, is called once the microVM is gone (for the receipt)."""
    with runner.session(build_allowlist(image), job, "build", image, PROBE_BUILD_LIMITS) as s:
        s.copy_in(PROBE_SRC, GUEST_SRC)
        r = s.exec(list(BUILD_PROBE), env=GO_ENV, workdir=GUEST_SRC)
        if r.exit_code != 0:
            raise ProveError(f"probe build failed (exit {r.exit_code}): {r.stderr[-2000:]}")
        path = s.copy_out(f"{GUEST_SRC}/tls_probe", out_dir)
    if on_session:
        on_session(s)
    data = pathlib.Path(path).read_bytes()
    return Probe(name=PROBE_NAME, version=PROBE_VERSION, sha256=hashlib.sha256(data).hexdigest(),
                 source_sha256=source_sha256(), built_with=image, path=path)


def tls_dir_files(tls_dir):
    return {k: f"{tls_dir}/{k}.pem" for k in ("ca", "cert", "key")}


def connect_argv(target, groups, tls_dir, servername="localhost"):
    return [PROBE_NAME, "connect", f"-groups={groups}", f"-ca={tls_dir}/ca.pem", f"-servername={servername}",
            "-wait=10s", target]


def serve_argv(addr, groups, tls_dir):
    return [PROBE_NAME, "serve", f"-addr={addr}", f"-groups={groups}", f"-cert={tls_dir}/cert.pem",
            f"-key={tls_dir}/key.pem"]


REFERENCES = ((CONTROL_ADDR, f"{OFFER_HYBRID},X25519"), (NEGATIVE_ADDR, NEGATIVE_GROUPS))


def port(addr):
    return int(addr.rsplit(":", 1)[1])


def listeners_argv(addrs):
    """tls_probe listeners for the reference servers' ports and the targets' ports."""
    ports = sorted({port(a) for a in addrs} | {port(a) for a, _ in REFERENCES})
    return [PROBE_NAME, "listeners", "-ports=" + ",".join(map(str, ports)), "-wait=10s"]


LISTEN_LINE = re.compile(r"listen: (?P<addr>\S+):(?P<port>[0-9]+) uid=(?P<uid>[0-9]+) inode=(?P<inode>[0-9]+) "
                         r"pid=(?P<pid>[0-9]+) exe=(?P<exe>\S+)")


def listeners(session, addrs):
    """(Exec, [line dict]) from tls_probe listeners, run as root: every process that holds a
    listening socket on one of the ports. Lines it cannot parse are dropped (they cannot vouch
    for a server); the raw output stays in the Exec."""
    r = session.exec(listeners_argv(addrs))
    out = []
    for line in str(r.stdout).splitlines():
        m = LISTEN_LINE.fullmatch(line)
        if m:
            out.append(dict(m.groupdict(), port=int(m["port"]), line=line))
    return r, out


def probe_allowlist(targets, tls_dir, servername="localhost", hosts="localhost,127.0.0.1"):
    """The control plane's fixed probe commands for one prove microVM (targets: addresses)."""
    cmds = {(PROBE_NAME, "version"), (PROBE_NAME, "cert", f"-hosts={hosts}", tls_dir),
            tuple(listeners_argv(targets))}
    cmds |= {tuple(serve_argv(addr, groups, tls_dir)) for addr, groups in REFERENCES}
    cmds.add(tuple(connect_argv(CONTROL_ADDR, OFFER_HYBRID, tls_dir)))
    for groups in (OFFER_HYBRID, OFFER_CLASSICAL):
        cmds.add(tuple(connect_argv(NEGATIVE_ADDR, groups, tls_dir)))
    for t in targets:
        for groups in (OFFER_HYBRID, OFFER_CLASSICAL):
            cmds.add(tuple(connect_argv(t, groups, tls_dir, servername)))
    return Allowlist(commands=frozenset(cmds), paths=frozenset(), images=frozenset())


def install_probe(session, probe, tls_dir, hosts="localhost,127.0.0.1"):
    """Copy the probe into the microVM, record its version line and write a test CA and server cert."""
    session.copy_in(probe.path, GUEST_PROBE)
    v = session.exec([PROBE_NAME, "version"])
    if v.exit_code != 0 or not str(v.stdout).startswith(f"{PROBE_NAME} {PROBE_VERSION} "):
        raise ProveError(f"probe does not run in this microVM: {v.stderr[-500:]}")
    c = session.exec([PROBE_NAME, "cert", f"-hosts={hosts}", tls_dir])
    if c.exit_code != 0:
        raise ProveError(f"probe could not write test certificates: {c.stderr[-500:]}")
    return str(v.stdout).strip()


def verify_probe(session, probe, dest_dir):
    """None if the probe in the microVM is still the binary PQ-Proof built, else why not. The file
    is copied out and hashed on the host, so no tool inside the microVM takes part."""
    os.makedirs(dest_dir)
    try:
        data = pathlib.Path(session.copy_out(GUEST_PROBE, dest_dir)).read_bytes()
    except (OSError, RuntimeError) as e:
        return f"{GUEST_PROBE} could not be read back from the microVM: {e}"
    got = hashlib.sha256(data).hexdigest()
    if got != probe.sha256:
        return f"{GUEST_PROBE} changed in the microVM (sha256 {got}, built {probe.sha256}, {len(data)} bytes)"
    return None


def start_references(session, tls_dir):
    """Start the probe's two reference servers. Call it before any server of the repo starts, so
    none of them can take the reference addresses first."""
    for addr, groups in REFERENCES:
        session.start(serve_argv(addr, groups, tls_dir))


def controls(session, tls_dir):
    """Run both controls: {'positive': (Handshake, Exec), 'negative_hybrid': ..., 'negative_classical': ...}."""
    out = {}
    for name, addr, groups in (("positive", CONTROL_ADDR, OFFER_HYBRID), ("negative_hybrid", NEGATIVE_ADDR, OFFER_HYBRID),
                               ("negative_classical", NEGATIVE_ADDR, OFFER_CLASSICAL)):
        r = session.exec(connect_argv(addr, groups, tls_dir))
        out[name] = (parse(r.stdout), r)
    return out


def control_problem(results):
    """Why no server verdict is valid in this microVM, or None when both controls hold:
    - positive: offering only X25519MLKEM768 to the hybrid reference server negotiates X25519MLKEM768;
    - negative: offering only X25519MLKEM768 to the X25519-only reference server fails, and a
      classical client connects to it with X25519."""
    (pos, pr), (neg, nr), (cls, cr) = results["positive"], results["negative_hybrid"], results["negative_classical"]
    if pos.kind != "hybrid" or pos.group != OFFER_HYBRID:
        return f"positive control failed (expected {OFFER_HYBRID} from the reference server):\n{pr.stdout}{pr.stderr}"
    if neg.kind != "failed":
        return ("negative control failed: a hybrid-only client reported a connection to the X25519-only reference "
                f"server, so the probe's output cannot be trusted in this microVM:\n{nr.stdout}{nr.stderr}")
    if cls.kind != "classical" or cls.group != NEGATIVE_GROUPS:
        return f"negative control failed (expected a classical X25519 handshake):\n{cr.stdout}{cr.stderr}"
    return None



def probe_target(session, target, tls_dir, servername="localhost"):
    """{'hybrid': (Handshake, Exec), 'classical': (Handshake, Exec)} for one server address."""
    out = {}
    for name, groups in (("hybrid", OFFER_HYBRID), ("classical", OFFER_CLASSICAL)):
        r = session.exec(connect_argv(target, groups, tls_dir, servername))
        out[name] = (parse(r.stdout), r)
    return out

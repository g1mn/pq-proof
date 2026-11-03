"""Deterministic TLS proof with a fixed-version probe and a positive control.

The probe is tls_probe (probe/tls_probe.go): a static Go client built once inside a microVM from
a pinned golang image and copied into every microVM that is tested. A client from the target's
own image would not do: orders-edge's image has OpenSSL 3.0, which does not know the name
X25519MLKEM768, so a red baseline would say nothing about the server. Before a server is judged,
the same probe must negotiate X25519MLKEM768 with its own reference server in the same microVM
(the positive control). Success is read from the probe's output, never from a model.

parse() also reads `openssl s_client` output, so an OpenSSL 3.5+ client can cross-check:
- hybrid: "Negotiated TLS1.3 group: X25519MLKEM768"
- classical: no "Negotiated TLS1.3 group" line, only "Peer Temp Key: X25519, 253 bits"
- failed: "Cipher is (NONE)" with an alert; its "Negotiated TLS1.3 group NID: 0" is not a group.
"""
import hashlib
import pathlib
import re
import tempfile
from dataclasses import asdict, dataclass

from .images import GOLANG
from .plan import PROBE_ADDRS, Allowlist
from .sandbox import Limits

PROBE_NAME = "tls_probe"
PROBE_VERSION = "0.1.0"
PROBE_SRC = pathlib.Path(__file__).resolve().parent.parent / "probe"
GUEST_PROBE = "/usr/local/bin/tls_probe"
GUEST_SRC = "/work/probe"
GO_ENV = {"CGO_ENABLED": "0", "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOTOOLCHAIN": "local"}
BUILD_PROBE = ("go", "build", "-trimpath", "-o=tls_probe", ".")
HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
OFFER_HYBRID = "X25519MLKEM768"  # a client that only speaks hybrid: success means ML-KEM was negotiated
OFFER_CLASSICAL = "X25519,P-256"  # a client from before ML-KEM
CONTROL_ADDR = "127.0.0.1:4433"
assert CONTROL_ADDR in PROBE_ADDRS  # plans may not name it as a target


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


def build_probe(runner, out_dir, image=GOLANG.ref, job="probe"):
    """Build tls_probe inside a microVM (offline, standard library only) and copy it to out_dir."""
    with runner.session(build_allowlist(image), job, "build", image,
                        Limits(cpus=2, memory_mib=2048, wall_clock_s=300)) as s:
        s.copy_in(PROBE_SRC, GUEST_SRC)
        r = s.exec(list(BUILD_PROBE), env=GO_ENV, workdir=GUEST_SRC)
        if r.exit_code != 0:
            raise ProveError(f"probe build failed (exit {r.exit_code}): {r.stderr[-2000:]}")
        path = s.copy_out(f"{GUEST_SRC}/tls_probe", out_dir)
    data = pathlib.Path(path).read_bytes()
    return Probe(name=PROBE_NAME, version=PROBE_VERSION, sha256=hashlib.sha256(data).hexdigest(),
                 source_sha256=source_sha256(), built_with=image, path=path)


def tls_dir_files(tls_dir):
    return {k: f"{tls_dir}/{k}.pem" for k in ("ca", "cert", "key")}


def connect_argv(target, groups, tls_dir, servername="localhost"):
    return [PROBE_NAME, "connect", f"-groups={groups}", f"-ca={tls_dir}/ca.pem", f"-servername={servername}",
            "-wait=10s", target]


def probe_allowlist(targets, tls_dir, servername="localhost", hosts="localhost,127.0.0.1"):
    """The control plane's fixed probe commands for one prove microVM."""
    cmds = {(PROBE_NAME, "version"), (PROBE_NAME, "cert", f"-hosts={hosts}", tls_dir),
            (PROBE_NAME, "serve", f"-addr={CONTROL_ADDR}", f"-groups={OFFER_HYBRID},X25519",
             f"-cert={tls_dir}/cert.pem", f"-key={tls_dir}/key.pem")}
    cmds.add(tuple(connect_argv(CONTROL_ADDR, OFFER_HYBRID, tls_dir)))
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


def positive_control(session, tls_dir):
    """The probe must negotiate X25519MLKEM768 with its own reference server in this microVM."""
    session.start([PROBE_NAME, "serve", f"-addr={CONTROL_ADDR}", f"-groups={OFFER_HYBRID},X25519",
                   f"-cert={tls_dir}/cert.pem", f"-key={tls_dir}/key.pem"])
    r = session.exec(connect_argv(CONTROL_ADDR, OFFER_HYBRID, tls_dir))
    h = parse(r.stdout)
    if h.kind != "hybrid" or h.group != OFFER_HYBRID:
        raise ProveError(f"positive control failed, so no server verdict is valid in this microVM: {r.stdout}{r.stderr}")
    return h, r


def probe_target(session, target, tls_dir, servername="localhost"):
    """{'hybrid': (Handshake, Exec), 'classical': (Handshake, Exec)} for one server address."""
    out = {}
    for name, groups in (("hybrid", OFFER_HYBRID), ("classical", OFFER_CLASSICAL)):
        r = session.exec(connect_argv(target, groups, tls_dir, servername))
        out[name] = (parse(r.stdout), r)
    return out

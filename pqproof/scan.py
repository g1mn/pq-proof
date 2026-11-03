"""Cryptography inventory (CBOM) of a repo snapshot: nginx configs, Go code, Dockerfiles, go.mod.

The scanner only reads files. It never runs the target repo's code, it does not follow symlinks
(a symlink in the snapshot could point anywhere on the host), and it reads at most MAX_FILE bytes
of a file. Vendored code, test files and .git are skipped: they do not set the service's TLS.

Each row is one place that matters for the migration:
- key-exchange: a TLS group list without X25519MLKEM768 (classical only), or with it (hybrid).
- base-image: a runtime image whose OpenSSL has no ML-KEM (OpenSSL 3.5 added it).
- toolchain: a go.mod `go` line below 1.24, which keeps Go's pre-1.24 default key exchanges
  (GODEBUG tlsmlkem=0) even after a curve pin is removed; or tlsmlkem=0 set outright (a go.mod
  godebug line or block, `godebug default=go1.N` with N < 24, `//go:debug`, a GODEBUG variable in
  a Dockerfile, shell, YAML or env file).
- signature: RSA or ECDSA signatures (JWT, certificates). Reported, never patched: signature
  migration is out of scope.
Rows are static findings. Whether a server really negotiates X25519MLKEM768 is decided by the
probe (prove.py), not by this module. Comments are blanked before matching (line numbers stay), so a
commented-out pin is not a row. nginx directives are read to their `;`, across lines. Go group
lists are read wherever a []tls.CurveID literal appears (field, assignment or variable). A runtime
image whose tag names no known distribution gets blocks_hybrid None: unknown, not "does not block".
Row text goes into the model's context, so text taken from the repo is bounded: group names and
image references outside a narrow character set or length read "unrecognized".
"""
import os
import re
import stat
from dataclasses import asdict, dataclass, replace

MAX_FILE = 1 << 20
PATH_SAFE = re.compile(r"[A-Za-z0-9._/-]{1,200}")
PATH_UNSAFE = re.compile(r"[^A-Za-z0-9._/-]")
SKIP_DIRS = {".git", "vendor", "node_modules"}
HYBRID = "X25519MLKEM768"
NIST_KEX = "quantum-vulnerable: deprecated after 2030, disallowed after 2035 (NIST IR 8547, Table 4)"
NIST_SIG = "quantum-vulnerable: deprecated after 2030, disallowed after 2035 (NIST IR 8547, Table 2)"
NIST_PQ = "includes ML-KEM-768 (NIST IR 8547, Table 5)"

# Go's names for TLS groups, and the names OpenSSL (nginx ssl_ecdh_curve) uses for the same groups.
GO_CURVES = {"CurveP256": "P-256", "CurveP384": "P-384", "CurveP521": "P-521", "X25519": "X25519",
             "X25519MLKEM768": HYBRID, "SecP256r1MLKEM768": "SecP256r1MLKEM768",
             "SecP384r1MLKEM1024": "SecP384r1MLKEM1024"}
OPENSSL_GROUPS = {"prime256v1": "P-256", "secp256r1": "P-256", "p-256": "P-256", "secp384r1": "P-384",
                  "p-384": "P-384", "secp521r1": "P-521", "p-521": "P-521", "x25519": "X25519",
                  "x448": "X448", "x25519mlkem768": HYBRID, "secp256r1mlkem768": "SecP256r1MLKEM768",
                  "secp384r1mlkem1024": "SecP384r1MLKEM1024"}
# Base image tag -> the OpenSSL its distribution ships. Static knowledge; the probe has the last word.
DISTRO_OPENSSL = [
    (re.compile(r"(^|-)bullseye($|-)"), "Debian 11 (bullseye) ships OpenSSL 1.1.1, which has no ML-KEM", False),
    (re.compile(r"(^|-)bookworm($|-)"), "Debian 12 (bookworm) ships OpenSSL 3.0, which has no ML-KEM", False),
    (re.compile(r"(^|-)trixie($|-)"), "Debian 13 (trixie) ships OpenSSL 3.5, which has ML-KEM", True),
]

NGINX_GROUPS = re.compile(r"(?:^|[;{}\s])((?:ssl_ecdh_curve)|(?:proxy_)?ssl_conf_command\s+(?:Groups|Curves))\s+([^;{}]+);",
                          re.I)
GO_CURVE_LIST = re.compile(r"\[\]tls\.CurveID\s*\{([^}]*)\}")
GO_MOD_GODEBUG = re.compile(r"^[ \t]*godebug[ \t]+(?:\(([^)]*)\)|(\S+))", re.M)
GO_DEBUG_DIRECTIVE = re.compile(r"^//go:debug[ \t]+(\S+)", re.M)
GODEBUG_VAR = re.compile(r"\bGODEBUG['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_.,=]+)")
GODEBUG_FILES = re.compile(r"(?:Dockerfile.*|.*\.Dockerfile|Makefile|.*\.(?:mk|sh|bash|env|ya?ml|service|toml|ini|conf)|\.env.*)")
GROUP_NAME = re.compile(r"[A-Za-z0-9-]{1,32}")  # what an OpenSSL or Go group name looks like
IMAGE_REF = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?")
GO_MOD_GO = re.compile(r"^go\s+1\.(\d+)(?:\.\d+)?\s*$", re.M)
FROM = re.compile(r"^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)(?:[ \t]+AS[ \t]+(\S+))?[ \t]*$", re.I | re.M)
JWT_RSA = re.compile(r"SigningMethod(RS|PS)(256|384|512)\b|[\"'](RS|PS)(256|384|512)[\"']")
JWT_EC = re.compile(r"SigningMethodES(256|384|512)\b|[\"']ES(256|384|512)[\"']")


@dataclass(frozen=True)
class Row:
    path: str
    line: int
    component: str  # nginx | go | go.mod | dockerfile
    kind: str  # key-exchange | base-image | toolchain | signature
    algorithm: str
    detail: str
    nist: str
    blocks_hybrid: bool | None  # true when this row keeps the service off X25519MLKEM768; None: unknown
    auto_fix: bool  # false for what PQ-Proof reports but never patches (signatures)

    def to_json(self):
        return asdict(self)


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _blank(m):
    return re.sub(r"[^\n]", " ", m[0])


def blank_comments(text, style):
    """Comments replaced by spaces, newlines kept (line numbers stay). style: "slash" for Go and
    go.mod (// and /* */; "//go:" directives are kept), "hash" for nginx, shell, YAML, Dockerfile."""
    if style == "slash":
        text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.S)
        return re.sub(r"(?<![:\"'])//(?!go:)[^\n]*", _blank, text)
    return re.sub(r"#[^\n]*", _blank, text)


def _group(name, table):
    """A group's canonical name, the name itself if it looks like one, else "unrecognized"."""
    name = name.strip()
    return table.get(name if table is GO_CURVES else name.lower()) or (name if GROUP_NAME.fullmatch(name) else "unrecognized")


def _toolchain_row(path, line, component, setting):
    return Row(path=path, line=line, component=component, kind="toolchain", algorithm=setting,
               detail=f"{setting} turns off Go's {HYBRID} default (GODEBUG tlsmlkem=0)",
               nist=NIST_KEX, blocks_hybrid=True, auto_fix=True)


def _turns_off_mlkem(settings):
    """True for a godebug setting list that sets tlsmlkem=0 or defaults to Go before 1.24."""
    for item in re.split(r"[\s,]+", settings):
        key, _, value = item.partition("=")
        if key == "tlsmlkem" and value == "0":
            return True
        m = re.fullmatch(r"go1\.(\d+)(?:\.\d+)?", value) if key == "default" else None
        if m and int(m[1]) < 24:
            return True
    return False


def _files(root):
    """(relative path, text) of regular files under root, without following symlinks."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
                continue
            with open(full, "rb") as f:
                data = f.read(MAX_FILE)
            yield os.path.relpath(full, root).replace(os.sep, "/"), data.decode("utf-8", errors="replace")


def _groups_row(path, line, component, names, detail_prefix):
    hybrid = HYBRID in names
    return Row(path=path, line=line, component=component, kind="key-exchange",
               algorithm=", ".join(names) or "(empty)",
               detail=f"{detail_prefix}: {'offers' if hybrid else 'no'} {HYBRID}",
               nist=NIST_PQ if hybrid else NIST_KEX, blocks_hybrid=not hybrid, auto_fix=True)


def scan_nginx(path, text):
    rows = []
    text = blank_comments(text, "hash")
    for m in NGINX_GROUPS.finditer(text):
        names = [_group(g, OPENSSL_GROUPS) for g in m[2].strip().split(":") if g.strip()]
        directive = re.sub(r"\s+", " ", m[1])
        rows.append(_groups_row(path, _line_of(text, m.start(1)), "nginx", names, f"{directive} pins the TLS groups"))
    return rows


def scan_go(path, text):
    rows = []
    for m in GO_DEBUG_DIRECTIVE.finditer(text):
        if _turns_off_mlkem(m[1]):
            rows.append(_toolchain_row(path, _line_of(text, m.start()), "go", f"//go:debug {m[1]}"))
    text = blank_comments(text, "slash")
    for m in GO_CURVE_LIST.finditer(text):
        names = [_group(tok, GO_CURVES) for tok in re.findall(r"tls\.([A-Za-z0-9_]+)", m[1])]
        rows.append(_groups_row(path, _line_of(text, m.start()), "go", names, "a []tls.CurveID list (CurvePreferences) pins the TLS groups"))
    for rx, alg in ((JWT_RSA, "RSA"), (JWT_EC, "ECDSA")):
        for m in rx.finditer(text):
            name = m[0].strip("\"'").replace("SigningMethod", "")
            rows.append(Row(path=path, line=_line_of(text, m.start()), component="go", kind="signature",
                            algorithm=f"JWT {name} ({alg})", detail="token signature; out of scope for automatic fixes",
                            nist=NIST_SIG, blocks_hybrid=False, auto_fix=False))
    return rows


def scan_go_mod(path, text):
    text = blank_comments(text, "slash")
    rows = []
    m = GO_MOD_GO.search(text)
    if m and int(m[1]) < 24:
        rows.append(Row(path=path, line=_line_of(text, m.start()), component="go.mod", kind="toolchain",
                        algorithm=f"go 1.{m[1]}",
                        detail=f"go 1.{m[1]} < 1.24 keeps Go's pre-1.24 default key exchanges (GODEBUG tlsmlkem=0), "
                               f"so {HYBRID} stays off once a curve pin is removed",
                        nist=NIST_KEX, blocks_hybrid=True, auto_fix=True))
    for m in GO_MOD_GODEBUG.finditer(text):
        body = m[1] if m[1] is not None else m[2]
        for off, line in enumerate(body.split("\n")):
            if line.strip() and _turns_off_mlkem(line):
                at = m.start(1 if m[1] is not None else 2) + sum(len(x) + 1 for x in body.split("\n")[:off])
                rows.append(_toolchain_row(path, _line_of(text, at), "go.mod", f"godebug {line.strip()}"))
    return rows


def scan_godebug_var(path, text):
    """GODEBUG=...tlsmlkem=0 in a Dockerfile, shell, YAML, env or config file (comments skipped)."""
    text = blank_comments(text, "hash")
    return [_toolchain_row(path, _line_of(text, m.start()), "config", "GODEBUG " + m[1])
            for m in GODEBUG_VAR.finditer(text) if _turns_off_mlkem(m[1].replace(",", " "))]


def dockerfile_images(text):
    """[(line, image, stage name or None)] for each FROM, in order."""
    return [(_line_of(text, m.start()), m[1], m[2]) for m in FROM.finditer(text)]


def scan_dockerfile(path, text):
    images = dockerfile_images(text)
    if not images:
        return []
    line, image, _ = images[-1]  # the runtime stage; build stages do not serve TLS
    if not IMAGE_REF.fullmatch(image):
        image = "unrecognized image reference"
    tag = image.split("@", 1)[0].rsplit(":", 1)[1] if ":" in image.split("@", 1)[0] else ""
    for rx, why, has_mlkem in DISTRO_OPENSSL:
        if rx.search(tag):
            return [Row(path=path, line=line, component="dockerfile", kind="base-image", algorithm=image,
                        detail=f"runtime base image: {why}", nist=NIST_PQ if has_mlkem else NIST_KEX,
                        blocks_hybrid=not has_mlkem, auto_fix=True)]
    return [Row(path=path, line=line, component="dockerfile", kind="base-image", algorithm=image,
                detail="runtime base image: OpenSSL version unknown from the tag; the probe decides",
                nist="unknown", blocks_hybrid=None, auto_fix=True)]


def scan(root):
    """CBOM rows for a snapshot directory, in path order."""
    rows = []
    for path, text in _files(root):
        name = path.rsplit("/", 1)[-1]
        if name.endswith(".conf") and "ssl_" in text:
            rows += scan_nginx(path, text)
        elif name.endswith(".go") and not name.endswith("_test.go"):
            rows += scan_go(path, text)
        elif name == "go.mod":
            rows += scan_go_mod(path, text)
        elif name == "Dockerfile" or name.endswith(".Dockerfile") or name.startswith("Dockerfile."):
            rows += scan_dockerfile(path, text)
        if GODEBUG_FILES.fullmatch(name) and "GODEBUG" in text:
            rows += scan_godebug_var(path, text)
    return [r if PATH_SAFE.fullmatch(r.path) else replace(r, path=PATH_UNSAFE.sub("?", r.path)[:200]) for r in rows]

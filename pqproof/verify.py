"""Deterministic check for TLS-weakening changes in a patch.

The allowlist (plan.py) says which files may change, never what goes into them, and the model's
input includes text from the target repo (its files, its build errors), so a prompt injection can
ask for certificate verification to be turned off. This check reads each changed file before and
after the patch, with comments removed, and refuses the patch when a rule goes the wrong way:
- "added": a weakening construct appears more often after the patch (InsecureSkipVerify, a
  verification callback, rejectUnauthorized: false, verify=False, CERT_NONE, proxy_ssl_verify off,
  TLS 1.0/1.1 by name or as a number, a weak cipher suite, a GODEBUG setting that brings back
  legacy TLS ...);
- "removed": a verification setting appears less often. nginx's proxy_ssl_verify is off by
  default, so deleting `proxy_ssl_verify on;` turns upstream verification off as surely as
  writing `off`; the same goes for a trusted-CA file, client-certificate verification, Go's
  RootCAs or ClientCAs left out of a replaced tls.Config, and a MinVersion line;
- "changed": a trust setting gets a value the file did not have (another CA file, another
  RootCAs expression): trusting different CAs is not part of a key-exchange migration;
- "lowered": the lowest value of a setting goes down (Go MinVersion, the go.mod go line, whose
  older defaults include TLS 1.0 servers and RSA key exchange).
Counts, not lines, so moving a setting within a file is fine and commenting it out is not. It is a
deny list for the changes a key-exchange migration never needs; anything it does not name passes,
and the probe still decides whether the key exchange works. What it cannot see is listed in the
README's "Known limits": it reads text, not nginx's block structure (a setting moved into a
location no request reaches keeps its count), and not values built at run time (reflect, names or
numbers composed from parts, settings in files the patch does not touch).
"""
import re

GO, GOMOD, NGINX, PY, JS, ANY = "go", "go.mod", "nginx", "python", "js", "any"

# TLS versions as Go writes them (crypto/tls constants) and as numbers.
GO_VERSIONS = {"VersionSSL30": 0x0300, "VersionTLS10": 0x0301, "VersionTLS11": 0x0302, "VersionTLS12": 0x0303,
               "VersionTLS13": 0x0304}
LEGACY_NUMBER = r"(?:0[xX]0*30[0-2]|76[89]|770)"  # 0x0300 (SSL 3.0) .. 0x0302 (TLS 1.1)
# GODEBUG settings that bring back what newer Go turned off: TLS 1.0/1.1 servers, RSA key exchange,
# 3DES, the unsafe EKM, SHA-1 signatures in TLS 1.2 and in certificates.
LEGACY_GODEBUG = r"\b(?:tls10server|tlsrsakex|tls3des|tlsunsafeekm|tlssha1|x509sha1)\s*=\s*1\b"
GODEBUG_DEFAULT = re.compile(r"\bdefault\s*=\s*go1\.(\d+)")
GODEBUG_DEFAULT_MIN = 23  # Go 1.22 turned off tls10server and tlsrsakex by default, Go 1.23 tls3des
# OpenSSL cipher string tokens (nginx ssl_ciphers, proxy_ssl_ciphers, ssl_conf_command CipherString)
# that enable a weak suite. A token after ! or - removes suites, so it never counts.
OPENSSL_CIPHERS = re.compile(r"\b(?:(?:proxy_)?ssl_ciphers|ssl_conf_command\s+CipherString)\s+([^;]+);")
WEAK_OPENSSL_TOKEN = re.compile(
    r"(?i)(?:ALL|COMPLEMENTOFALL|COMPLEMENTOFDEFAULT|LOW|EXP(?:ORT)?(?:40|56)?|[ae]?NULL|kRSA|RSA|"
    r"@SECLEVEL=0|.*(?:3DES|DES-CBC|RC4|RC2|NULL|EXP-|MD5).*|(?:AES|CAMELLIA|ARIA|SEED|IDEA)[A-Z0-9-]*-SHA[0-9]*)")
NGINX_TRUST = re.compile(r"\b((?:proxy_)?ssl_trusted_certificate|ssl_client_certificate)\s+([^;]+);")
GO_TRUST = re.compile(r"\b(RootCAs|ClientCAs)\s*[:=]\s*([^,;\n}]+)")
GO_MIN_VERSION = re.compile(r"\bMinVersion\s*[:=]\s*(?:uint16\s*\(\s*)?(?:tls\.(Version\w+)|(0[xX][0-9a-fA-F]+|[0-9]+))\b")
GO_MOD_GO = re.compile(r"^go\s+1\.(\d+)(?:\.\d+)?\s*$", re.M)


def _weak_ciphers(text):
    n = 0
    for m in OPENSSL_CIPHERS.finditer(text):
        for token in re.split(r"[:,\s]+", m[1].strip().strip("'\"")):
            if token and token[0] not in "!-" and WEAK_OPENSSL_TOKEN.fullmatch(token.lstrip("+")):
                n += 1
    return n


def _old_godebug_default(text):
    return sum(1 for m in GODEBUG_DEFAULT.finditer(text) if int(m[1]) < GODEBUG_DEFAULT_MIN)


def _nginx_trust(text):
    return {f"{m[1]} {m[2].strip()}" for m in NGINX_TRUST.finditer(text)}


def _go_trust(text):
    return {f"{m[1]}: {m[2].strip()}" for m in GO_TRUST.finditer(text)}


def _go_min_versions(text):
    out = []
    for m in GO_MIN_VERSION.finditer(text):
        if m[1]:
            if m[1] in GO_VERSIONS:
                out.append(GO_VERSIONS[m[1]])
        else:
            out.append(int(m[2], 16) if m[2][:2].lower() == "0x" else int(m[2], 10))
    return out


def _go_lines(text):
    return [int(m[1]) for m in GO_MOD_GO.finditer(text)]


# (rule, file kind, mode, pattern). Patterns are regular expressions, or functions of the text that
# return a count ("added", "removed"), a set of values ("changed") or a list of numbers ("lowered").
# Patterns run on text with comments removed.
RULES = [
    ("InsecureSkipVerify", GO, "added", r"\bInsecureSkipVerify\b"),
    ("VerifyPeerCertificate callback", GO, "added", r"\bVerifyPeerCertificate\b"),
    ("VerifyConnection callback", GO, "added", r"\bVerifyConnection\b"),
    ("client certificates no longer verified", GO, "added",
     r"\b(?:NoClientCert|RequestClientCert|RequireAnyClientCert|VerifyClientCertIfGiven)\b"),
    ("TLS 1.0/1.1 or SSL 3.0 allowed", GO, "added", r"\btls\.Version(?:SSL30|TLS10|TLS11)\b"),
    ("TLS version below 1.2 written as a number", GO, "added",
     rf"\b(?:Min|Max)Version\s*[:=]\s*(?:uint16\s*\(\s*)?{LEGACY_NUMBER}\b"),
    ("MinVersion lowered", GO, "lowered", _go_min_versions),
    ("MinVersion removed", GO, "removed", r"\bMinVersion\s*[:=]"),
    ("weak cipher suite (3DES, RC4, NULL, EXPORT or RSA key exchange)", GO, "added",
     r"\btls\.TLS_\w*(?:_3DES_|_RC4_|_NULL_|EXPORT)\w*|\btls\.TLS_RSA_WITH_\w+|\btls\.InsecureCipherSuites\b"),
    ("RootCAs removed", GO, "removed", r"\bRootCAs\b"),
    ("ClientCAs removed", GO, "removed", r"\bClientCAs\b"),
    ("trusted CA pool changed", GO, "changed", _go_trust),
    ("system CA pool added", GO, "added", r"\bx509\.SystemCertPool\b"),
    ("RequireAndVerifyClientCert removed", GO, "removed", r"\bRequireAndVerifyClientCert\b"),
    ("go line lowered (older Go defaults include TLS 1.0 servers and RSA key exchange)", GOMOD, "lowered", _go_lines),
    ("proxy_ssl_verify off", NGINX, "added", r"\bproxy_ssl_verify\s+off\s*;"),
    ("proxy_ssl_verify on removed (nginx's default is off)", NGINX, "removed", r"\bproxy_ssl_verify\s+on\s*;"),
    ("proxy_ssl_trusted_certificate removed", NGINX, "removed", r"\bproxy_ssl_trusted_certificate\s+\S"),
    ("ssl_trusted_certificate removed", NGINX, "removed", r"(?<!proxy_)\bssl_trusted_certificate\s+\S"),
    ("trusted CA file changed", NGINX, "changed", _nginx_trust),
    ("ssl_verify_client off or optional_no_ca", NGINX, "added", r"\bssl_verify_client\s+(?:off|optional_no_ca)\s*;"),
    ("ssl_verify_client on removed", NGINX, "removed", r"\bssl_verify_client\s+on\s*;"),
    ("ssl_client_certificate removed", NGINX, "removed", r"\bssl_client_certificate\s+\S"),
    ("TLS 1.0/1.1 or SSLv3 in a protocol list", NGINX, "added",
     r"\b(?:ssl|proxy_ssl)_protocols\s[^;]*\b(?:SSLv[23]|TLSv1(?:\.1)?)(?![.\d])"),
    ("TLS 1.0/1.1 or SSLv3 as MinProtocol", NGINX, "added",
     r"\bssl_conf_command\s+MinProtocol\s+(?:SSLv3|TLSv1(?:\.1)?)(?![.\d])"),
    ("weak cipher suite (3DES, RC4, NULL, EXPORT, RSA key exchange or security level 0)", NGINX, "added", _weak_ciphers),
    ("system CA bundle referenced", ANY, "added",
     r"/etc/(?:ssl|pki/tls)/certs(?:/[\w.-]+)?|\bca-(?:certificates|bundle)\.crt\b"),
    ("GODEBUG brings back legacy TLS (tls10server, tlsrsakex, tls3des, tlsunsafeekm, tlssha1, x509sha1)", ANY, "added",
     LEGACY_GODEBUG),
    (f"godebug default before Go 1.{GODEBUG_DEFAULT_MIN} (legacy TLS defaults)", ANY, "added", _old_godebug_default),
    ("rejectUnauthorized: false", JS, "added", r"\brejectUnauthorized\s*:\s*false\b"),
    ("NODE_TLS_REJECT_UNAUTHORIZED=0", ANY, "added", r"\bNODE_TLS_REJECT_UNAUTHORIZED['\"\]]*\s*[:=]?\s*['\"]?0"),
    ("verify=False", PY, "added", r"\bverify\s*=\s*False\b"),
    ("check_hostname = False", PY, "added", r"\bcheck_hostname\s*=\s*False\b"),
    ("CERT_NONE", ANY, "added", r"\bCERT_NONE\b"),
    ("unverified SSL context", PY, "added", r"\b_create_unverified_context\b"),
    ("curl --insecure or -k", ANY, "added", r"\bcurl\b[^\n]*\s(?:--insecure|-k)(?=\s|$)|(?:^|\s)--insecure(?=\s|$)"),
]


def kind_of(path):
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".go"):
        return GO
    if name == "go.mod":
        return GOMOD
    if name.endswith(".conf") or name == "nginx.conf":
        return NGINX
    if name.endswith(".py"):
        return PY
    if name.endswith((".js", ".mjs", ".cjs", ".ts")):
        return JS
    return ANY


def strip_comments(text, kind):
    """Text without comments, so a setting cannot be disabled by commenting it out unnoticed.
    Go's //go: directives are kept: //go:debug sets GODEBUG. Rough on purpose: quoted strings are
    not parsed, which can only hide text on both sides alike."""
    if kind in (GO, GOMOD, JS):
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        return re.sub(r"(?<![:\"'])//(?!go:)[^\n]*", "", text)
    if kind in (NGINX, PY, ANY):
        return re.sub(r"#[^\n]*", "", text)
    return text


def _short(values, limit=3, width=80):
    shown = [v if len(v) <= width else v[:width] + "..." for v in sorted(values)[:limit]]
    return "[" + ", ".join(shown) + (", ..." if len(values) > limit else "") + "]"


def _shown(n, gomod):
    if gomod:
        return f"go 1.{n}"
    return {v: k for k, v in GO_VERSIONS.items()}.get(n, f"0x{n:04x}")


def weakening(changed):
    """Why a patch weakens TLS: ["path: rule (before ..., after ...)"], [] when it does not.
    changed is {path: (text before, text after)} as loop.apply_edits returns it."""
    out = []
    for path in sorted(changed):
        kind = kind_of(path)
        before, after = (strip_comments(t, kind) for t in changed[path])
        for name, rule_kind, mode, pattern in RULES:
            if rule_kind not in (kind, ANY):
                continue
            if callable(pattern):
                b, a = pattern(before), pattern(after)
            else:
                b, a = len(re.findall(pattern, before, re.M)), len(re.findall(pattern, after, re.M))
            if mode == "changed":
                if a - b:
                    out.append(f"{path}: {name} (before {_short(b)}, after {_short(a)})")
            elif mode == "lowered":
                if b and a and min(a) < min(b):
                    out.append(f"{path}: {name} (before {_shown(min(b), kind == GOMOD)}, after {_shown(min(a), kind == GOMOD)})")
            elif (mode == "added" and a > b) or (mode == "removed" and a < b):
                out.append(f"{path}: {name} (before {b}, after {a})")
    return out

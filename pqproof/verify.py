"""Deterministic check for TLS-weakening changes in a patch.

The allowlist (plan.py) says which files may change, never what goes into them, and the model's
input includes text from the target repo (its files, its build errors), so a prompt injection can
ask for certificate verification to be turned off. This check reads each changed file before and
after the patch, with comments removed, and refuses the patch when a rule's count goes the wrong way:
- "added": a weakening construct appears more often after the patch (InsecureSkipVerify, a
  verification callback, rejectUnauthorized: false, verify=False, CERT_NONE, proxy_ssl_verify off,
  TLS 1.0/1.1 ...);
- "removed": a verification setting appears less often. nginx's proxy_ssl_verify is off by
  default, so deleting `proxy_ssl_verify on;` turns upstream verification off as surely as
  writing `off`; the same goes for a trusted-CA file, client-certificate verification, and Go's
  RootCAs or ClientCAs left out of a replaced tls.Config.
Counts, not lines, so moving a setting within a file is fine and commenting it out is not. It is a
deny list for the changes a key-exchange migration never needs; anything it does not name passes,
and the probe still decides whether the key exchange works.
"""
import re

GO, NGINX, PY, JS, ANY = "go", "nginx", "python", "js", "any"

# (rule, file kind, mode, pattern). Patterns run on text with comments removed.
RULES = [
    ("InsecureSkipVerify", GO, "added", r"\bInsecureSkipVerify\b"),
    ("VerifyPeerCertificate callback", GO, "added", r"\bVerifyPeerCertificate\b"),
    ("VerifyConnection callback", GO, "added", r"\bVerifyConnection\b"),
    ("client certificates no longer verified", GO, "added",
     r"\b(?:NoClientCert|RequestClientCert|RequireAnyClientCert|VerifyClientCertIfGiven)\b"),
    ("TLS 1.0/1.1 or SSL 3.0 allowed", GO, "added", r"\btls\.Version(?:SSL30|TLS10|TLS11)\b"),
    ("RootCAs removed", GO, "removed", r"\bRootCAs\b"),
    ("ClientCAs removed", GO, "removed", r"\bClientCAs\b"),
    ("RequireAndVerifyClientCert removed", GO, "removed", r"\bRequireAndVerifyClientCert\b"),
    ("proxy_ssl_verify off", NGINX, "added", r"\bproxy_ssl_verify\s+off\s*;"),
    ("proxy_ssl_verify on removed (nginx's default is off)", NGINX, "removed", r"\bproxy_ssl_verify\s+on\s*;"),
    ("proxy_ssl_trusted_certificate removed", NGINX, "removed", r"\bproxy_ssl_trusted_certificate\s+\S"),
    ("ssl_verify_client off or optional_no_ca", NGINX, "added", r"\bssl_verify_client\s+(?:off|optional_no_ca)\s*;"),
    ("ssl_verify_client on removed", NGINX, "removed", r"\bssl_verify_client\s+on\s*;"),
    ("ssl_client_certificate removed", NGINX, "removed", r"\bssl_client_certificate\s+\S"),
    ("TLS 1.0/1.1 or SSLv3 in a protocol list", NGINX, "added", r"\b(?:ssl|proxy_ssl)_protocols\s[^;]*\b(?:SSLv3|TLSv1(?:\.1)?)(?![.\d])"),
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
    if name.endswith(".conf") or name == "nginx.conf":
        return NGINX
    if name.endswith(".py"):
        return PY
    if name.endswith((".js", ".mjs", ".cjs", ".ts")):
        return JS
    return ANY


def strip_comments(text, kind):
    """Text without comments, so a setting cannot be disabled by commenting it out unnoticed.
    Rough on purpose: quoted strings are not parsed, which can only hide text on both sides alike."""
    if kind in (GO, JS):
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        return re.sub(r"(?<![:\"'])//[^\n]*", "", text)
    if kind in (NGINX, PY, ANY):
        return re.sub(r"#[^\n]*", "", text)
    return text


def weakening(changed):
    """Why a patch weakens TLS: ["path: rule (before N, after M)"], [] when it does not.
    changed is {path: (text before, text after)} as loop.apply_edits returns it."""
    out = []
    for path in sorted(changed):
        kind = kind_of(path)
        before, after = (strip_comments(t, kind) for t in changed[path])
        for name, rule_kind, mode, pattern in RULES:
            if rule_kind not in (kind, ANY):
                continue
            b, a = len(re.findall(pattern, before, re.M)), len(re.findall(pattern, after, re.M))
            if (mode == "added" and a > b) or (mode == "removed" and a < b):
                out.append(f"{path}: {name} (before {b}, after {a})")
    return out

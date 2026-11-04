#!/usr/bin/env bash
# Copy PQ-Proof (and the orders-edge fixture) to the VX1 host. Run it on your own machine.
#
#   deploy/upload.sh [-i SSH_KEY] [--fixture PATH] [--key FILE] root@HOST
#
# No Git credentials go to the host. Each repository's committed HEAD is streamed with
# `git archive | ssh HOST tar -x` into /opt/pqproof/<repo>/<commit> (root-owned, read-only for
# the control plane), and /opt/pqproof/<repo>/current points at it. A commit that is already
# there is not sent again; uncommitted changes are never sent.
# --fixture PATH: the e2e run snapshots its repo with `git clone`, so on the host the fixture's
#   files become a git repository at the source's own commit (fetched from a `git bundle` sent
#   over ssh), so a receipt names a commit the reader can find; the files on the host must match
#   it. Its origin is the source's origin as https without credentials (what a receipt names as
#   the repository; nothing is ever fetched from it). It belongs to the control plane's user
#   (pqproof), because git refuses to clone a repository that another user owns ("dubious
#   ownership").
# --key FILE: the Vultr Serverless Inference key file goes to /etc/pqproof/inference.env with
#   scp (directory 700, file 600, both root). Only its variable names are printed.
set -euo pipefail

OPT=${PQPROOF_OPT:-/opt/pqproof}
ETC=${PQPROOF_ETC:-/etc/pqproof}
OWNER=${PQPROOF_KEY_OWNER:-root:root}  # user:group of /etc/pqproof and the key file
FIXTURE_OWNER=${PQPROOF_FIXTURE_OWNER:-pqproof:pqproof}  # user:group of the fixture's host repository
SSH=${PQPROOF_SSH:-ssh}
SCP=${PQPROOF_SCP:-scp}
SELF=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)

opts=(-o BatchMode=yes)
fixture='' key='' host=''
while [ $# -gt 0 ]; do
  case "$1" in
    -i) opts+=(-i "$2"); shift 2 ;;
    --fixture) fixture=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) host=$1; shift ;;
  esac
done
[ -n "$host" ] || { echo "usage: $0 [-i SSH_KEY] [--fixture PATH] [--key FILE] root@HOST" >&2; exit 2; }

remote() { "$SSH" "${opts[@]}" "$host" "$1"; }

send() {  # send REPO_DIR NAME [fixture]
  local src=$1 name=$2 rev tree dest
  rev=$(git -C "$src" rev-parse --short=12 HEAD)
  tree=$(git -C "$src" rev-parse 'HEAD^{tree}')
  if [ -n "$(git -C "$src" status --porcelain --untracked-files=no)" ]; then
    echo "note: $name has uncommitted changes; only HEAD $rev is sent"
  fi
  dest=$OPT/$name/$rev
  if remote "test -d '$dest'"; then
    echo "$name $rev: already on the host"
  else
    # tar.umask 0022: directories 755 and files 644 on the host (git archive's default is 0002)
    git -C "$src" -c tar.umask=0022 archive --format=tar HEAD | remote "set -e; install -d -m 755 '$OPT/$name';
      t=\$(mktemp -d '$OPT/$name/.part.XXXXXX'); chmod 755 \"\$t\";
      tar -x --no-same-owner -C \"\$t\"; mv \"\$t\" '$dest'"
    echo "$name $rev: sent"
  fi
  if [ -n "${3:-}" ]; then
    local commit url
    commit=$(git -C "$src" rev-parse HEAD)
    url=$(git -C "$src" remote get-url origin 2>/dev/null | sed -E 's#^git@([A-Za-z0-9.-]+):#https://\1/#;
      s#^ssh://git@([A-Za-z0-9.-]+)(:[0-9]+)?/#https://\1/#; s#^(https://)[^/@]*@#\1#; s#\.git/?$##' |
      grep -E '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)+$' || true)
    # safe.directory: on a second run the repository already belongs to FIXTURE_OWNER, not to us
    git -C "$src" bundle create --quiet - HEAD | remote "set -e; cd '$dest'; g() { git -c safe.directory='$dest' \"\$@\"; };
      b=\$(mktemp); trap 'rm -f \"\$b\"' EXIT; cat > \"\$b\";
      [ -d .git ] || g init -q;
      if [ \"\$(g rev-parse -q --verify HEAD || true)\" != '$commit' ]; then
        g fetch -q \"\$b\" HEAD; g update-ref refs/heads/main '$commit'; g symbolic-ref HEAD refs/heads/main; g reset -q; fi;
      if [ -n \"\$(g status --porcelain --untracked-files=no)\" ]; then
        echo \"tree mismatch: the files on the host differ from commit $commit\" >&2; exit 1; fi;
      got=\$(g rev-parse 'HEAD^{tree}');
      if [ \"\$got\" != '$tree' ]; then echo \"tree mismatch: \$got on the host, $tree here\" >&2; exit 1; fi;
      g remote remove origin 2>/dev/null || true; if [ -n '$url' ]; then g remote add origin '$url'; fi;
      chown -R '$FIXTURE_OWNER' '$dest'; chmod -R go-w '$dest'"
    echo "$name $rev: local repository on the host at commit $commit, tree $tree matches${url:+, origin $url}"
  fi
  remote "ln -sfn '$rev' '$OPT/$name/current'"
}

send "$SELF" pq-proof
if [ -n "$fixture" ]; then
  send "$fixture" "$(basename "$(git -C "$fixture" rev-parse --show-toplevel)")" fixture
fi

if [ -n "$key" ]; then
  [ -f "$key" ] || { echo "no key file: $key" >&2; exit 1; }
  remote "install -d -m 700 -o '${OWNER%%:*}' -g '${OWNER##*:}' '$ETC'"
  "$SCP" -q "${opts[@]}" "$key" "$host:$ETC/inference.env"
  remote "chown '$OWNER' '$ETC/inference.env' && chmod 600 '$ETC/inference.env' &&
    { stat -c '%n %U:%G %a %s bytes' '$ETC/inference.env' 2>/dev/null || stat -f '%N %Su:%Sg %Lp %z bytes' '$ETC/inference.env'; } &&
    echo \"variables: \$(grep -v '^#' '$ETC/inference.env' | cut -s -d= -f1 | tr '\n' ' ')\""
fi

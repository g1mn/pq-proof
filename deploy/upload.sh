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
#   files are committed once into a fresh local repository with no remote. Its tree hash must
#   equal the source commit's tree hash, so the host builds exactly the files of that commit.
#   It belongs to the control plane's user (pqproof), because git refuses to clone a repository
#   that another user owns ("dubious ownership").
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
    # safe.directory: on a second run the repository already belongs to FIXTURE_OWNER, not to us
    remote "set -e; cd '$dest'; g() { git -c safe.directory='$dest' \"\$@\"; };
      if [ ! -d .git ]; then g init -q; g add -A -f;
        g -c user.name=pqproof-deploy -c user.email=deploy@localhost commit -q -m 'snapshot of $name $rev'; fi;
      got=\$(g rev-parse 'HEAD^{tree}');
      if [ \"\$got\" != '$tree' ]; then echo \"tree mismatch: \$got on the host, $tree here\" >&2; exit 1; fi;
      chown -R '$FIXTURE_OWNER' '$dest'; chmod -R go-w '$dest'"
    echo "$name $rev: local repository on the host, tree $tree matches"
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

#!/usr/bin/env bash
# Prepare a Vultr VX1 host (Ubuntu 24.04, x86_64) for PQ-Proof. Run it as root on the host,
# after deploy/upload.sh has copied this repository there; running it again changes nothing.
#
#   ssh root@HOST bash /opt/pqproof/pq-proof/current/deploy/vx1-setup.sh
#
# What it does, and nothing else:
# - apt: refreshes the package lists and installs pending updates, security updates included,
#   plus git, python3 (3.12 on 24.04), curl and ufw if missing. Docker is not installed: every
#   step runs in a Microsandbox microVM.
# - sshd: keys only (no password or keyboard-interactive login, root only with a key). It
#   refuses to touch sshd while root has no authorized key, so it cannot lock you out.
# - ufw: incoming traffic is denied except 22/tcp. The demo site's 443 is opened by the demo
#   deployment, not here.
# - time zone: UTC.
# - a system user, pqproof, in the kvm group, runs the control plane and its microVMs. The
#   inference key stays in /etc/pqproof (root, 600) and reaches the control plane on stdin.
# - Microsandbox MSB_VERSION, from the official installer, run only when its SHA-256 is the one
#   reviewed below and only when msb is not already at that version.
set -euo pipefail

MSB_VERSION=0.7.13
# SHA-256 of https://install.microsandbox.dev as read before use on 2026-11-04. It installs the
# latest release; if the script changes, read the new one before you update this value.
MSB_INSTALL_SHA256=800af0b3ee6343f25a8f4bb95e1b7cc300cf08812a47aaad4c9fa6e577032be7
SVC_USER=pqproof
SVC_HOME=/var/lib/pqproof

say() { printf '== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
  echo "warning: written for Ubuntu 24.04, this is ${PRETTY_NAME:-unknown}" >&2
fi

say "apt: package lists, pending updates (security included), git python3 curl ufw"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
apt-get -y -q install --no-install-recommends ca-certificates curl git python3 ufw
if [ -f /var/run/reboot-required ]; then
  echo "note: the updates need a reboot to take full effect (/var/run/reboot-required)"
fi

say "sshd: keys only"
[ -s /root/.ssh/authorized_keys ] || die "root has no authorized SSH key; not touching sshd"
grep -qE '^Include /etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config ||
  die "/etc/ssh/sshd_config does not include sshd_config.d/*.conf"
conf=/etc/ssh/sshd_config.d/00-pqproof.conf
want='# PQ-Proof host: SSH keys only. sshd keeps the first value it reads for each option,
# so this file must sort before 50-cloud-init.conf (which turns password login on).
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes'
if [ "$(cat "$conf" 2>/dev/null || true)" != "$want" ]; then
  printf '%s\n' "$want" > "$conf.new"
  chmod 644 "$conf.new"
  mv "$conf.new" "$conf"
  if ! sshd -t; then
    mv "$conf" "$conf.rejected"
    die "sshd -t rejected $conf (moved to $conf.rejected); sshd was not reloaded"
  fi
  systemctl reload-or-restart ssh
fi
effective=$(sshd -T)
for kv in "passwordauthentication no" "kbdinteractiveauthentication no" \
          "permitrootlogin (prohibit-password|without-password)" "pubkeyauthentication yes"; do
  grep -qxE "$kv" <<<"$effective" || die "sshd -T does not show '$kv'"
done
grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) ' <<<"$effective"

say "ufw: deny incoming except 22/tcp"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw default deny routed >/dev/null
ufw allow 22/tcp >/dev/null
ufw --force enable >/dev/null
others=$(ufw status | awk 'NR > 4 && NF && $1 != "22/tcp"')
if [ -n "$others" ]; then
  printf 'warning: ufw has rules besides 22/tcp (left as they are):\n%s\n' "$others" >&2
fi
ufw status verbose

say "time zone: UTC"
tz=$(timedatectl show -p Timezone --value)
if [ "$tz" != UTC ] && [ "$tz" != Etc/UTC ]; then
  timedatectl set-timezone Etc/UTC
fi
timedatectl show -p Timezone --value

say "user $SVC_USER (kvm group), /etc/pqproof and /opt/pqproof"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$SVC_HOME" --shell /usr/sbin/nologin "$SVC_USER"
fi
usermod -aG kvm "$SVC_USER"
chmod 700 "$SVC_HOME"
install -d -m 700 -o root -g root /etc/pqproof
install -d -m 755 -o root -g root /opt/pqproof
id "$SVC_USER"

say "Microsandbox $MSB_VERSION for $SVC_USER"
msb=$SVC_HOME/.microsandbox/bin/msb
have=$( [ -x "$msb" ] && runuser -u "$SVC_USER" -- "$msb" --version 2>/dev/null | awk '{print $2}' || true)
if [ "$have" != "$MSB_VERSION" ]; then
  tmp=$(mktemp -d)
  trap 'rm -f "$tmp/install.sh"; rmdir "$tmp"' EXIT
  curl -fsSL https://install.microsandbox.dev -o "$tmp/install.sh"
  got=$(sha256sum "$tmp/install.sh" | awk '{print $1}')
  [ "$got" = "$MSB_INSTALL_SHA256" ] ||
    die "install.microsandbox.dev changed (sha256 $got): read the new script, then update MSB_INSTALL_SHA256"
  chmod 755 "$tmp"
  chmod 644 "$tmp/install.sh"
  runuser -u "$SVC_USER" -- env -i HOME="$SVC_HOME" PATH=/usr/bin:/bin sh -c 'cd "$HOME" && sh "$1"' sh "$tmp/install.sh"
  have=$(runuser -u "$SVC_USER" -- "$msb" --version | awk '{print $2}')
  [ "$have" = "$MSB_VERSION" ] || die "the installer gave msb $have, expected $MSB_VERSION"
fi
echo "msb $have at $msb"
runuser -u "$SVC_USER" -- env -i HOME="$SVC_HOME" PATH="$SVC_HOME/.local/bin:/usr/bin:/bin" "$msb" doctor

say "python3"
python3 -c 'import sys; assert sys.version_info >= (3, 12), sys.version; print(sys.version.split()[0])'
echo "done"

#!/usr/bin/env bash
# Publish the demo site on the VX1 host: recorded runs only, replayed in the browser. Run it as root
# on the host after deploy/upload.sh and deploy/vx1-setup.sh; running it again changes nothing.
#
#   ssh root@HOST bash /opt/pqproof/pq-proof/current/deploy/demo-site.sh DOMAIN RUN_ID...
#
# - publishes each RUN_ID's receipt/ (from the control plane's /var/lib/pqproof/runs) to
#   /srv/pqproof/runs, root-owned and read-only, after receipt.verify() passes on it
# - a system user, pqweb (no shell, no key, not in kvm), runs the viewer from
#   deploy/pqproof-web.service on 127.0.0.1:8080; nothing on this site starts a run or calls a model
# - nginx and certbot from Ubuntu: a Let's Encrypt certificate for DOMAIN (http-01, webroot, no
#   e-mail sent), renewed by certbot's timer with an nginx reload; deploy/nginx-demo.conf in front
# - ufw: 80/tcp and 443/tcp open (22/tcp stays), at most 100 connections at once per IPv4 address to them
set -euo pipefail

DOMAIN=${1:?usage: demo-site.sh DOMAIN RUN_ID...}
shift
[ $# -gt 0 ] || { echo "usage: demo-site.sh DOMAIN RUN_ID..." >&2; exit 2; }
SRC=/var/lib/pqproof/runs
PUB=/srv/pqproof/runs
HERE=$(cd "$(dirname "$0")" && pwd)
APP=$(dirname "$HERE")

say() { printf '== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
[[ $DOMAIN =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "not a host name: $DOMAIN"

say "apt: nginx certbot"
export DEBIAN_FRONTEND=noninteractive
dpkg -s nginx certbot >/dev/null 2>&1 || { apt-get update -q; apt-get -y -q install --no-install-recommends nginx certbot; }

say "user pqweb"
id -u pqweb >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin pqweb
id pqweb

say "published runs: $*"
install -d -m 755 -o root -g root /srv/pqproof "$PUB"
for id in "$@"; do
  [[ $id =~ ^[A-Za-z0-9._-]+$ ]] || die "bad run id: $id"
  [ -f "$SRC/$id/receipt/receipt.json" ] || die "no receipt: $SRC/$id/receipt"
  tmp=$(mktemp -d "$PUB/.part.XXXXXX")
  cp -R --no-preserve=ownership "$SRC/$id/receipt" "$tmp/receipt"
  chown -R root:root "$tmp"; chmod -R u=rwX,go=rX "$tmp"
  (cd "$APP" && python3 -m pqproof verify-receipt "$tmp/receipt" >/dev/null) || { rm -rf "$tmp"; die "$id: receipt check failed"; }
  rm -rf "$PUB/$id.old"; [ -e "$PUB/$id" ] && mv "$PUB/$id" "$PUB/$id.old"
  mv "$tmp" "$PUB/$id"; rm -rf "$PUB/$id.old"
  echo "$id: published, receipt check passed"
done

say "viewer: pqproof-web.service"
install -m 644 "$HERE/pqproof-web.service" /etc/systemd/system/pqproof-web.service
systemctl daemon-reload
systemctl enable -q pqproof-web
systemctl restart pqproof-web
for _ in $(seq 50); do curl -fs -o /dev/null http://127.0.0.1:8080/api/runs && break; sleep 0.2; done
curl -fsS http://127.0.0.1:8080/api/runs | python3 -c 'import json,sys; d=json.load(sys.stdin); print("runs:", [(r["id"], r["verdict"], r["verified"]) for r in d["runs"]], "live:", d["live_runs"])'

say "nginx: $DOMAIN"
install -d -m 755 /var/www/letsencrypt
conf=/etc/nginx/sites-available/pqproof
put_conf() {  # put_conf full|http
  if [ "$1" = full ]; then sed "s/__DOMAIN__/$DOMAIN/g" "$HERE/nginx-demo.conf"
  else sed -e '/^# -- https/,$d' -e "s/__DOMAIN__/$DOMAIN/g" "$HERE/nginx-demo.conf"; fi > "$conf.new"
  mv "$conf.new" "$conf"
  ln -sfn "$conf" /etc/nginx/sites-enabled/pqproof
  rm -f /etc/nginx/sites-enabled/default
  nginx -t -q || die "nginx -t rejected $conf"
  systemctl reload-or-restart nginx
}
cert=/etc/letsencrypt/live/$DOMAIN/fullchain.pem

say "ufw: 80/tcp 443/tcp, at most 100 connections at once per IPv4 address"
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
# nginx's limit_conn counts requests, not connections that have not sent a whole request yet, so one address could
# otherwise hold every worker connection; the kernel caps them per address instead (IPv6 serves no demo name)
if ! grep -q pqproof-connlimit /etc/ufw/before.rules; then
  sed -i '/^# End required lines/a -A ufw-before-input -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 100 --connlimit-mask 32 -m comment --comment pqproof-connlimit -j REJECT --reject-with tcp-reset' /etc/ufw/before.rules
  ufw reload >/dev/null || die "ufw reload failed after adding the connection cap to /etc/ufw/before.rules"
fi
iptables -S ufw-before-input | grep -q pqproof-connlimit || die "the per-address connection cap is not in effect"

if [ ! -f "$cert" ]; then
  put_conf http
  say "certificate: Let's Encrypt for $DOMAIN"
  certbot certonly -n -q --agree-tos --register-unsafely-without-email --webroot -w /var/www/letsencrypt -d "$DOMAIN" \
    --deploy-hook "systemctl reload nginx"
fi
put_conf full
openssl x509 -in "$cert" -noout -subject -issuer -enddate
systemctl list-timers certbot.timer --no-pager | sed -n '1,2p'
ufw status | awk 'NR > 4 && NF {print $1}' | sort -u | tr '\n' ' '; echo
echo "done: https://$DOMAIN/"

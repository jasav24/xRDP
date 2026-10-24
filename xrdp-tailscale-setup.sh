#!/usr/bin/env bash
# xrdp-tailscale-setup.sh — Ubuntu 24.04 desktop over RDP, reachable ONLY from
# your tailnet. Run as root on a machine you provision yourself.
#
#   sudo TS_AUTHKEY_FILE=/root/ts.key DESKTOP_USER=builder ./xrdp-tailscale-setup.sh
#
# Required before it will run:
#   TS_AUTHKEY_FILE  path to a 0600 file holding the Tailscale auth key.
#                    Never passed on a command line (it would show up in every
#                    `ps` on the box) and never stored in a CI secret that gets
#                    echoed into a job log.
# Optional:
#   DESKTOP_USER   default: builder
#   TS_HOSTNAME    default: lab-<short host id>
#   ALLOW_SSH_FROM tail|any   default: tail
#   DESKTOP_PASSWORD_FILE  path to a 0600 file holding the password for
#                    DESKTOP_USER. Unset = the account is created locked and
#                    you set the password yourself with `sudo passwd`.
#                    The value is read on stdin by chpasswd, so it never
#                    appears in argv, `ps`, a log or shell history.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO" >&2' ERR

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# A CI runner is not a server. GitHub-hosted machines are ephemeral, have no
# inbound path, and turning one into a remote-access host is outside the
# Actions usage policy, so refuse rather than half-provision something that
# dies at job teardown with an admin listener briefly live.
# Checked before the root test on purpose: `sudo` strips GITHUB_ACTIONS unless
# -E is used, and a runner user invoking this with sudo would otherwise get a
# confusing "run as root" answer instead of the real reason.
if [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${RUNNER_TEMP:-}" ]; then
  die "this is a CI runner, not a host you own. Provision an Ubuntu VM at your provider and run this there."
fi

[ "$(id -u)" = 0 ] || die "run as root (sudo -E preserves the env vars you set)"

. /etc/os-release
[ "${ID:-}" = ubuntu ] || die "tested on Ubuntu 24.04 only; this is ${ID:-unknown}"

: "${TS_AUTHKEY_FILE:?set TS_AUTHKEY_FILE to the path of your auth-key file}"
DESKTOP_USER="${DESKTOP_USER:-builder}"
TS_HOSTNAME="${TS_HOSTNAME:-lab-$(hostname -s | tr -cd 'a-zA-Z0-9' | cut -c1-8)}"
ALLOW_SSH_FROM="${ALLOW_SSH_FROM:-tail}"

[ -f "$TS_AUTHKEY_FILE" ] || die "$TS_AUTHKEY_FILE does not exist"
[ "$(stat -c '%a' "$TS_AUTHKEY_FILE")" = 600 ] || die "$TS_AUTHKEY_FILE must be mode 600 (chmod 600 it first)"
[ -s "$TS_AUTHKEY_FILE" ] || die "$TS_AUTHKEY_FILE is empty"

log "installing desktop + xrdp"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq --no-install-recommends \
  xfce4 xfce4-terminal xfce4-goodies xorg xorgxrdp xrdp dbus-x11 \
  ufw curl ca-certificates

log "creating the desktop account"
if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$DESKTOP_USER"
  if [ -z "${DESKTOP_PASSWORD_FILE:-}" ]; then
    echo "No password was generated or printed anywhere. Set one yourself, in your"
    echo "own terminal, so it never lands in a shell history or a log:"
    echo "    sudo passwd $DESKTOP_USER"
  fi
else
  log "user $DESKTOP_USER already exists"
fi

# The explicit request wins over the "leave it alone" default: an existing
# account gets its password set too, because that is the only way a CI-driven
# provision can be re-run to fix a lost password.
if [ -n "${DESKTOP_PASSWORD_FILE:-}" ]; then
  [ -f "$DESKTOP_PASSWORD_FILE" ] || die "$DESKTOP_PASSWORD_FILE does not exist"
  [ "$(stat -c '%a' "$DESKTOP_PASSWORD_FILE")" = 600 ] || die "$DESKTOP_PASSWORD_FILE must be mode 600"
  [ -s "$DESKTOP_PASSWORD_FILE" ] || die "$DESKTOP_PASSWORD_FILE is empty"
  # chpasswd splits on the FIRST colon, so a password containing ':' is safe.
  { printf '%s:' "$DESKTOP_USER"; tr -d '\n' < "$DESKTOP_PASSWORD_FILE"; printf '\n'; } | chpasswd
  passwd -S "$DESKTOP_USER" | awk '{print "  login state:", $2}'
  PW_LEN=$(tr -d '\n' < "$DESKTOP_PASSWORD_FILE" | wc -c)
  if [ "$PW_LEN" -lt 12 ]; then
    echo "  WARNING: the password is under 12 characters. That is survivable only"
    echo "  because this script binds 3389 to tailscale0 and denies it everywhere"
    echo "  else - see the firewall block below. If you ever widen that, or expose"
    echo "  3389 through a reverse proxy, replace this password first: an RDP listener"
    echo "  with a short password on a public address gets brute-forced for ransomware."
  fi
fi

# xrdp's /etc/xrdp/startwm.sh only honours ~/.xsession when it is *executable*;
# a 644 file is skipped silently and you get a black screen after login.
if [ ! -f "/home/$DESKTOP_USER/.xsession" ]; then
  printf '#!/bin/sh\nexec startxfce4\n' > "/home/$DESKTOP_USER/.xsession"
fi
chmod 755 "/home/$DESKTOP_USER/.xsession"
chown "$DESKTOP_USER:$DESKTOP_USER" "/home/$DESKTOP_USER/.xsession"

log "hardening /etc/xrdp/xrdp.ini"
if ! grep -q 'xrdp-setup-applied' /etc/xrdp/xrdp.ini; then
  cp -a /etc/xrdp/xrdp.ini "/etc/xrdp/xrdp.ini.bak.$(date +%s)"
  sed -i -E 's/^security_layer=.*/security_layer=negotiate/; s/^crypt_level=.*/crypt_level=high/' /etc/xrdp/xrdp.ini
  sed -i -E 's/^#?allow_channels=.*/allow_channels=<rdpsnd,cliprdr>/; s/^#?NeverResetPassword=.*/NeverResetPassword=true/' /etc/xrdp/xrdp.ini
  printf '\n# tls + high crypt enforced by xrdp-tailscale-setup.sh (xrdp-setup-applied)\n' >> /etc/xrdp/xrdp.ini
fi
# Report, don't assume. These seds are pattern matches against a file whose
# exact keys vary by xrdp release, and a sed that matches nothing fails silently
# - which would leave you believing NLA + high crypt were on.
log "effective xrdp.ini settings"
grep -E '^(security_layer|crypt_level|allow_channels|NeverResetPassword)=' /etc/xrdp/xrdp.ini \
  | sed 's/^/  /' || echo "  (none of those keys are present - xrdp is using its defaults)"
# The certificate and its key must not be world-readable or the RDP session is
# readable by any local account.
chmod 640 /etc/xrdp/cert.pem /etc/xrdp/key.pem 2>/dev/null || true
chgrp xrdp /etc/xrdp/key.pem 2>/dev/null || true

systemctl enable --now xrdp
systemctl restart xrdp

log "installing tailscale"
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi

# TS_AUTHKEY is read from the environment, so the key never appears in argv.
umask 077
TS_AUTHKEY="$(< "$TS_AUTHKEY_FILE")"
export TS_AUTHKEY
tailscale up --hostname="$TS_HOSTNAME" --ssh > /tmp/ts-up.log 2>&1 || {
  cat /tmp/ts-up.log; die "tailscale up failed (see the message above)"
}
unset TS_AUTHKEY

for i in $(seq 1 12); do
  TS_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
  [ -n "$TS_IP" ] && break
  sleep 5
done
[ -n "${TS_IP:-}" ] || die "no tailscale IPv4 after 60s; check 'tailscale status' and the key's expiry"

log "firewall: 3389 and 22 reachable on tailscale0 only"
# Existing rules are kept on purpose: `ufw --force reset` would silently delete
# whatever you configured before, and on a box you already use that is a
# self-inflicted outage.
ufw default deny incoming
ufw default allow outgoing
# Explicit deny first keeps the rule honest even if the allow is edited later.
ufw deny in proto tcp to any port 3389 comment 'rdp off the public net'
ufw allow in on tailscale0 to any port 3389 proto tcp comment 'rdp over the tailnet'
if [ "$ALLOW_SSH_FROM" = any ]; then
  ufw allow in on eth0 to any port 22 proto tcp comment 'ssh (you asked for public ssh)'
else
  ufw allow in on tailscale0 to any port 22 proto tcp comment 'ssh over the tailnet'
  # Keep the session you are in right now alive: if you are SSHed in over the
  # public interface, locking 22 to tailscale0 would cut you off mid-script.
  if [ -n "${SSH_CLIENT:-}" ]; then
    SRC_IP="${SSH_CLIENT%% *}"
    SRC_IF="$(ip route get "$SRC_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    if [ -n "${SRC_IF:-}" ] && [ "$SRC_IF" != tailscale0 ]; then
      ufw allow in on "$SRC_IF" to any port 22 proto tcp comment "kept: your live ssh path ($SRC_IP)"
      echo "  NOTE: port 22 stays reachable on $SRC_IF because you are connected there now."
      echo "        Remove that rule once you have confirmed Tailscale SSH works."
    fi
  fi
fi
# Tailscale SSH needs to accept inbound from the tailnet; the interface rule
# above is what actually lets it through.
ufw --force enable

TS_IFACE_IP="$TS_IP"
log "done"
cat <<EOF

  RDP is up, and reachable ONLY at the tailnet address.

    address   $TS_IFACE_IP:3389
    hostname  $TS_HOSTNAME
    user      $DESKTOP_USER      ($( [ -n "${DESKTOP_PASSWORD_FILE:-}" ] && echo "password set from your file" || echo "no password set here; run: sudo passwd $DESKTOP_USER" ))

  From a client machine on the same tailnet:
      mstsc /v:$TS_IFACE_IP
    or Remmina / FreeRDP:    rdp://$TS_IFACE_IP

  Check what is actually exposed, from this box:
      ss -ltnp | grep -E ':3389|:22'
      sudo ufw status numbered
      tailscale status

  Check from OUTSIDE the tailnet (a different network, not this machine):
      nc -zvw3 $TS_IFACE_IP 3389      -> must fail
      nc -zvw3 <public-ip> 3389      -> must fail

  Left as your decision, deliberately not automated here:
   - fail2ban: unnecessary while 3389 is tail-only, required the moment you
     widen it.
   - Tailscale SSH is already enabled (--ssh), so you can admin this box with
     keys and no password at all; consider using it instead of RDP.
   - key file at $TS_AUTHKEY_FILE: rotate the auth key in the Tailscale admin
     console once you are in, since a reusable key that lives on disk is the
     weakest link here.
EOF

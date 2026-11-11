#!/usr/bin/env bash
# WindPulse red-team demo — TARGET-PI setup. Run this ON each Pi you will use as a demo
# target (with sudo). It makes a password-login demo account and ensures sshd accepts
# password logins, so the Kali attacker can try to log in and the WindPulse agent can
# report those attempts to the hub.
#
#   FOR YOUR OWN DEMO CLUSTER ONLY. It intentionally enables password SSH for the demo.
#
# Usage:
#   sudo ./pi-demo-setup.sh [username] <password>
#   sudo DEMO_PW='choose-a-password' ./pi-demo-setup.sh
#
# Give Pi-1 a password you will hand to Kali, and Pi-2 a DIFFERENT password you keep secret.
set -euo pipefail

USER_NAME="${1:-pidemo}"
PASSWORD="${2:-${DEMO_PW:-}}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./pi-demo-setup.sh [username] <password>" >&2
  exit 2
fi
if [ -z "$PASSWORD" ]; then
  echo "No password given. Pass it as the 2nd argument or set DEMO_PW." >&2
  echo "  sudo ./pi-demo-setup.sh $USER_NAME 'choose-a-password'" >&2
  exit 2
fi

echo "[*] Installing openssh-server ..."
apt-get update -y
apt-get install -y openssh-server

echo "[*] Creating demo account '$USER_NAME' ..."
id "$USER_NAME" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$USER_NAME"
echo "$USER_NAME:$PASSWORD" | chpasswd

echo "[*] Enabling password SSH logins (needed so the demo logins are attempted) ..."
conf=/etc/ssh/sshd_config
if grep -qE '^\s*#?\s*PasswordAuthentication' "$conf"; then
  sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/' "$conf"
else
  echo 'PasswordAuthentication yes' >> "$conf"
fi
# Some systems also carry an override drop-in that turns it off again.
if [ -d /etc/ssh/sshd_config.d ]; then
  echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-windpulse-demo.conf
fi

systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd
systemctl restart ssh 2>/dev/null || systemctl restart sshd

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "[done] '$USER_NAME' can now log in by password on ${IP:-this-pi}:22"
echo "       Make sure the WindPulse agent is running here so logins reach the hub:"
echo "         systemctl status devmon-agent   # (or however you run the agent)"

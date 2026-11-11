#!/usr/bin/env bash
# Prove the Pi-to-Pi channel protects data IN TRANSIT (Scenarios 1 & 3).
# It sends a known secret to the peer over the mutually-authenticated SSH mesh while
# capturing the packets, then shows the secret never appears in plaintext on the wire.
# Run as root on the SENDING Pi (tcpdump needs root):
#
#   sudo PEER=pi-02 ./prove-encrypted-channel.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

PEER="${PEER:-pi-02}"
SECRET="${SECRET:-WINDPULSE-SECRET-$(date +%s)}"
CAP="/tmp/wp-capture.pcap"
ASUSER="${SUDO_USER:-$USER}"   # run ssh as the real user (has the cluster key), not root

# resolve the peer's IP from the user's ssh config
PIP="$(sudo -u "$ASUSER" ssh -G "$PEER" 2>/dev/null | awk '/^hostname /{print $2; exit}')"
PIP="${PIP:-$PEER}"

echo "== capturing SSH traffic to $PEER ($PIP) =="
tcpdump -i any -w "$CAP" "host $PIP and port 22" >/dev/null 2>&1 &
TPID=$!
sleep 1

echo "== sending the secret over the mesh: $SECRET =="
printf '%s\n' "$SECRET" | sudo -u "$ASUSER" ssh -o BatchMode=yes "$PEER" "cat > /tmp/wp-received.txt"
sleep 1
kill "$TPID" 2>/dev/null || true; wait "$TPID" 2>/dev/null || true

echo
echo "== is the secret visible in the captured packets? =="
if strings "$CAP" | grep -q "$SECRET"; then
  echo "  !! FOUND in plaintext on the wire — channel is NOT secure"
else
  echo "  NOT found on the wire — the traffic is ENCRYPTED (data-in-transit protected)"
fi

echo
echo "== the peer received it fine (decrypted only at the authenticated endpoint): =="
sudo -u "$ASUSER" ssh -o BatchMode=yes "$PEER" 'cat /tmp/wp-received.txt'
echo
echo "(capture saved at $CAP — open with: tcpdump -r $CAP -A | less)"

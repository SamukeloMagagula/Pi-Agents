#!/usr/bin/env bash
# WindPulse Scenario-2 defence: detect an SSH brute-force and BLOCK the source.
# A self-contained fail2ban-style guard — no packages to install; uses journalctl +
# iptables, which are already on the Pi. Run as root on each Pi you want to defend:
#
#   sudo ./watch-block.sh
#   sudo THRESHOLD=5 WINDOW=60 WHITELIST="155.238.182.43" ./watch-block.sh
#
# WHITELIST protects your own management IPs from being banned (space-separated).
# Bans go in a dedicated chain; undo everything with:  sudo ./watch-block.sh --flush
set -euo pipefail

CHAIN="WINDPULSE_BLOCK"
THRESHOLD="${THRESHOLD:-5}"     # failed logins before a ban
WINDOW="${WINDOW:-60}"         # within this many seconds
WHITELIST="${WHITELIST:-}"     # IPs never to ban (your laptop/hub, etc.)

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

if [ "${1:-}" = "--flush" ]; then
  iptables -D INPUT -j "$CHAIN" 2>/dev/null || true
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "watch-block: all WindPulse bans removed."
  exit 0
fi

# one-time chain setup
iptables -N "$CHAIN" 2>/dev/null || true
iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT -j "$CHAIN"

is_white() { for w in $WHITELIST; do [ "$1" = "$w" ] && return 0; done; return 1; }

ban() {
  local ip="$1"
  is_white "$ip" && { echo "$(date +%T) skip $ip (whitelisted)"; return; }
  iptables -C "$CHAIN" -s "$ip" -j DROP 2>/dev/null && return   # already banned
  iptables -A "$CHAIN" -s "$ip" -j DROP
  echo "$(date +%T)  BLOCKED $ip  (>= $THRESHOLD failed logins in ${WINDOW}s)"
}

echo "watch-block: defending SSH. ban >= $THRESHOLD failures / ${WINDOW}s. whitelist: ${WHITELIST:-none}"
echo "(Ctrl-C to stop; 'sudo $0 --flush' to clear bans)"

declare -A hits
# follow live auth events (sshd and the newer sshd-session identifier)
stdbuf -oL journalctl -f -n0 -t sshd -t sshd-session -o cat 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    *"Failed password"*|*"Invalid user"*|*"authentication failure"*|*"Connection closed by invalid user"*|*"Connection closed by authenticating user"*)
      ip=$(printf '%s\n' "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
      [ -z "$ip" ] && continue
      now=$(date +%s)
      hits[$ip]="${hits[$ip]:-} $now"
      keep=""; cnt=0
      for t in ${hits[$ip]}; do
        if [ $(( now - t )) -le "$WINDOW" ]; then keep="$keep $t"; cnt=$((cnt+1)); fi
      done
      hits[$ip]="$keep"
      [ "$cnt" -ge "$THRESHOLD" ] && ban "$ip"
      ;;
  esac
done

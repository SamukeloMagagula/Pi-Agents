#!/usr/bin/env bash
# Run on each Pi: bridge the local agent to the hub over HTTPS/443, so the agent
# works on a network that only allows outbound 443 (e.g. campus wifi).
#
#   agent (127.0.0.1:LOCAL_PORT) --> websocat --> wss://DOMAIN/agentws (443) --> hub
#
# Point the agent at the bridge:  in agent.ini  [hub] host = 127.0.0.1 , port = LOCAL_PORT
#
# websocat must already be installed (download it on an UNFILTERED network first — on
# campus the TLS interception blocks the download):
#   curl -fsSL https://github.com/vi/websocat/releases/latest/download/websocat.aarch64-unknown-linux-musl \
#        -o ~/.local/bin/websocat && chmod +x ~/.local/bin/websocat
set -euo pipefail

DOMAIN="${DOMAIN:-sxmukelo.co.za}"
LOCAL_PORT="${LOCAL_PORT:-5555}"
LOG="${LOG:-$HOME/agent-bridge.log}"

command -v websocat >/dev/null 2>&1 || { echo "websocat not found — install it first (see header)"; exit 1; }

# NOTE on the campus TLS proxy: it intercepts 443, so the wss certificate you see is the
# SCHOOL'S, not your VPS's. The proper way to verify is to install the school's root CA on
# this Pi (then remove the --insecure note below is unnecessary). Do NOT blanket-disable
# verification unless you accept that the first hop is the school's proxy.

echo "[*] starting bridge: 127.0.0.1:${LOCAL_PORT}  <->  wss://${DOMAIN}/agentws"
nohup websocat -b --exit-on-eof "tcp-l:127.0.0.1:${LOCAL_PORT}" "wss://${DOMAIN}/agentws" \
  >>"$LOG" 2>&1 &
echo "    pid $! (log: $LOG)"
echo
echo "Now set the agent's hub to the bridge and start it:"
echo "    [hub] host = 127.0.0.1   port = ${LOCAL_PORT}   fingerprint = <hub fingerprint>"
echo "    python -m devmon.agent --config agent.ini"

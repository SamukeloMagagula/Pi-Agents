#!/usr/bin/env bash
# WindPulse — bring a set of Raspberry Pis up as a cluster, from one command.
#
# Run this ONCE on your laptop (or any control box that can SSH to the Pis). It:
#   1. names every node pi-01, pi-02, ...                 (hostname)
#   2. teaches every node the others' name + IP           (/etc/hosts)
#   3. installs ONE shared cluster key on every node, so any Pi can reach any
#      other passwordless, by name:   ssh pi-03           (key + ~/.ssh/config)
#   4. verifies the mesh: from pi-01 it SSHes to every peer and prints its hostname
#
#   FOR YOUR OWN CLUSTER. Needs a sudo account that already exists on each Pi
#   (default: pi). Pi OS gives that account passwordless sudo, which this relies on.
#
# Usage:
#   export CLUSTER_NODES="192.168.1.21 192.168.1.22 192.168.1.23"   # all Pi IPs
#   export ADMIN_USER=pi                      # a sudo account on every Pi
#   # export ADMIN_PASSWORD='...'             # only if the Pis use password SSH (needs sshpass)
#   ./cluster-up.sh
#
# After it runs, from ANY Pi you can do:  ssh pi-02 'hostname' , ping pi-03 , etc.
set -euo pipefail

NODES_RAW="${CLUSTER_NODES:?set CLUSTER_NODES=\"ip1 ip2 ip3 ...\" (all the Pi IPs)}"
ADMIN_USER="${ADMIN_USER:-pi}"
WORK="${CLUSTER_DIR:-$HOME/.windpulse-cluster}"

# split on spaces and/or commas
read -ra NODES <<< "${NODES_RAW//,/ }"
[ "${#NODES[@]}" -ge 1 ] || { echo "no nodes in CLUSTER_NODES"; exit 2; }

# ssh / scp, with a password only if one was given
OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=8)
if [ -n "${ADMIN_PASSWORD:-}" ]; then
  command -v sshpass >/dev/null || { echo "ADMIN_PASSWORD set but sshpass missing: sudo apt install -y sshpass"; exit 2; }
  SSH=(sshpass -p "$ADMIN_PASSWORD" ssh "${OPTS[@]}")
  SCP=(sshpass -p "$ADMIN_PASSWORD" scp "${OPTS[@]}")
else
  SSH=(ssh "${OPTS[@]}"); SCP=(scp "${OPTS[@]}")
fi

name_for(){ printf 'pi-%02d' "$1"; }

# node name list, e.g. "pi-01 pi-02 pi-03"
NAMES=(); for i in "${!NODES[@]}"; do NAMES+=("$(name_for $((i+1)))"); done
NAMES_STR="${NAMES[*]}"

# 1) one shared cluster keypair (reused on re-runs)
mkdir -p "$WORK"; chmod 700 "$WORK"
KEY="$WORK/cluster_key"
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -C 'windpulse-cluster' -f "$KEY" >/dev/null
PUB="$(cat "$KEY.pub")"
echo "[*] cluster key: $KEY"

# 2) the /etc/hosts block every node will carry (idempotent, between markers)
HOSTS_BLOCK="# >>> windpulse-cluster >>>"
for i in "${!NODES[@]}"; do HOSTS_BLOCK+=$'\n'"${NODES[$i]} $(name_for $((i+1)))"; done
HOSTS_BLOCK+=$'\n'"# <<< windpulse-cluster <<<"

# 3) configure each node
for i in "${!NODES[@]}"; do
  ip="${NODES[$i]}"; NAME="$(name_for $((i+1)))"
  echo
  echo "=== $NAME ($ip) ============================================"

  if ! "${SSH[@]}" "$ADMIN_USER@$ip" true 2>/dev/null; then
    echo "  ! cannot SSH to $ADMIN_USER@$ip — check the IP, ADMIN_USER and keys/ADMIN_PASSWORD; skipping"
    continue
  fi

  echo "  [1/4] hostname -> $NAME"
  "${SSH[@]}" "$ADMIN_USER@$ip" "sudo hostnamectl set-hostname $NAME" || echo "    (hostname set failed — passwordless sudo?)"

  echo "  [2/4] /etc/hosts (cluster members)"
  printf '%s\n' "$HOSTS_BLOCK" | "${SSH[@]}" "$ADMIN_USER@$ip" \
    "sudo sed -i '/# >>> windpulse-cluster >>>/,/# <<< windpulse-cluster <<</d' /etc/hosts && sudo tee -a /etc/hosts >/dev/null"

  echo "  [3/4] shared cluster key + ssh config"
  "${SSH[@]}" "$ADMIN_USER@$ip" \
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && \
     grep -qF '$PUB' ~/.ssh/authorized_keys || echo '$PUB' >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys"
  "${SCP[@]}" "$KEY" "$ADMIN_USER@$ip:.ssh/cluster_key" >/dev/null
  "${SSH[@]}" "$ADMIN_USER@$ip" \
    "chmod 600 ~/.ssh/cluster_key && \
     printf 'Host pi-*\n  User %s\n  IdentityFile ~/.ssh/cluster_key\n  StrictHostKeyChecking accept-new\n' '$ADMIN_USER' > ~/.ssh/config && \
     chmod 600 ~/.ssh/config"

  echo "  [4/4] ensure sshd is up"
  "${SSH[@]}" "$ADMIN_USER@$ip" "sudo systemctl enable --now ssh 2>/dev/null || sudo systemctl enable --now sshd 2>/dev/null || true"
  echo "  $NAME ready."
done

# 4) verify the mesh from the first node
echo
echo "=== verify: from ${NAMES[0]} (${NODES[0]}), SSH to every node by name ==="
"${SSH[@]}" "$ADMIN_USER@${NODES[0]}" \
  "for n in $NAMES_STR; do printf '  %-7s -> ' \"\$n\"; ssh -o BatchMode=yes -o ConnectTimeout=6 \"\$n\" hostname 2>/dev/null || echo UNREACHABLE; done"

cat <<EOF

================================ CLUSTER UP ================================
Nodes: $NAMES_STR
From any Pi you can now reach the others by name, no password:
    ssh pi-02 'uptime'      ping pi-03      scp file pi-01:~

Re-run this any time you add or re-image a Pi (just update CLUSTER_NODES).
===========================================================================
EOF

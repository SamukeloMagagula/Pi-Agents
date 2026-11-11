#!/bin/sh
# Install or update the devmon agent on a Raspberry Pi or Linux machine.
# Run as root from a copy of this repository:
#   sudo ./deploy/agent/install.sh --hub 192.168.1.10 --fingerprint XXXX-...-XXXX [--port 55555] [--kind pi|linux]
#        [--no-firewall-log] [--no-fixer] [--no-watchdog]
# Safe to run again: it updates the code and the hub settings, and keeps the agent's key.
# It also:
# - turns on the firewall's logging of blocked packets (for port-scan detection);
#   --no-firewall-log leaves the firewall untouched, gossip rules included
# - installs the fixer, the root service that carries out self-healing actions;
#   --no-fixer leaves it out, so this device is monitored but never fixed
# - turns on the hardware watchdog, so a frozen system reboots itself; --no-watchdog skips it
set -eu

HUB=""
FP=""
PORT=55555
KIND=""
FWLOG=1
FIXER=1
WATCHDOG=1

usage() {
    echo "usage: sudo $0 --hub HOST --fingerprint FP [--port 55555] [--kind pi|linux] [--no-firewall-log] [--no-fixer] [--no-watchdog]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --hub) HUB="${2:-}"; shift 2 ;;
        --fingerprint) FP="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; shift 2 ;;
        --kind) KIND="${2:-}"; shift 2 ;;
        --no-firewall-log) FWLOG=0; shift ;;
        --no-fixer) FIXER=0; shift ;;
        --no-watchdog) WATCHDOG=0; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

[ -n "$HUB" ] && [ -n "$FP" ] || usage
case "$KIND" in ""|pi|linux) ;; *) echo "--kind must be pi or linux" >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Run this as root (sudo)." >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$REPO/src/devmon/agent/__main__.py" ] || { echo "Can't find the devmon source next to this script." >&2; exit 1; }

PY="$(command -v python3 || true)"
[ -n "$PY" ] || { echo "python3 is not installed." >&2; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || { echo "Python 3.9 or newer is needed; found $("$PY" --version 2>&1)." >&2; exit 1; }

# Debian and Raspberry Pi OS ship venv without pip until python3-venv is installed.
if ! "$PY" -c 'import ensurepip, venv' 2>/dev/null; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "Installing python3-venv..."
        # A freshly flashed Pi has stale package lists; installing without this often 404s.
        apt-get update -qq || true
        apt-get install -y python3-venv
    else
        echo "Python's venv module is missing; install it with your package manager." >&2
        exit 1
    fi
fi

echo "==> Service account"
if ! id devmon >/dev/null 2>&1; then
    NOLOGIN="$(command -v nologin || echo /sbin/nologin)"
    useradd --system --home-dir /var/lib/devmon --no-create-home --shell "$NOLOGIN" devmon
fi
# Pi: vcgencmd (temperature fallback) needs the video group.
if getent group video >/dev/null 2>&1; then
    usermod -a -G video devmon
fi
# Attack detection reads the SSH, MariaDB and kernel logs; both groups only allow reading.
for g in adm systemd-journal; do
    if getent group "$g" >/dev/null 2>&1; then
        usermod -a -G "$g" devmon
    fi
done

echo "==> Folders"
install -d -o root -g root -m 0755 /opt/devmon
install -d -o root -g devmon -m 0750 /etc/devmon
install -d -o devmon -g devmon -m 0700 /var/lib/devmon
# The security helper's results: written by root only, readable by the agent.
install -d -o root -g root -m 0755 /var/lib/devmon-helper
# A scratch area for jobs, sticky like /tmp; disk cleanup may empty it.
install -d -o root -g root -m 1777 /var/tmp/devmon-scratch

echo "==> Code"
rm -rf /opt/devmon/src.new
mkdir -p /opt/devmon/src.new
cp -R "$REPO/src/devmon" /opt/devmon/src.new/
find /opt/devmon/src.new -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf /opt/devmon/src
mv /opt/devmon/src.new /opt/devmon/src
cp "$REPO/requirements/agent.txt" /opt/devmon/requirements-agent.txt

echo "==> Python environment (this can take a few minutes on a Pi)"
[ -x /opt/devmon/venv/bin/python ] || "$PY" -m venv /opt/devmon/venv
/opt/devmon/venv/bin/python -m pip install --quiet --upgrade pip
/opt/devmon/venv/bin/python -m pip install --quiet -r /opt/devmon/requirements-agent.txt
SITE="$(/opt/devmon/venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
echo /opt/devmon/src > "$SITE/devmon.pth"
chmod -R a+rX /opt/devmon

echo "==> Settings"
/opt/devmon/venv/bin/python "$REPO/deploy/agent/write_agent_ini.py" \
    --path /etc/devmon/agent.ini --hub "$HUB" --port "$PORT" --fingerprint "$FP" \
    --key-path /var/lib/devmon/agent.key --kind "$KIND"
chown root:devmon /etc/devmon/agent.ini
chmod 0640 /etc/devmon/agent.ini

# Create the key (as devmon, so the service owns it) before the service starts, so the two
# never race to create it.
FPRINT="$(cd / && runuser -u devmon -- /opt/devmon/venv/bin/python -m devmon.agent \
    --config /etc/devmon/agent.ini --show-fingerprint)"

echo "==> Service"
install -o root -g root -m 0644 "$REPO/deploy/agent/devmon-agent.service" /etc/systemd/system/devmon-agent.service
systemctl daemon-reload
systemctl enable devmon-agent.service >/dev/null
systemctl restart devmon-agent.service

echo "==> Security helper (root, hourly)"
install -o root -g root -m 0644 "$REPO/deploy/agent/devmon-helper.service" /etc/systemd/system/devmon-helper.service
install -o root -g root -m 0644 "$REPO/deploy/agent/devmon-helper.timer" /etc/systemd/system/devmon-helper.timer
systemctl daemon-reload
systemctl enable --now devmon-helper.timer >/dev/null
# First run now, in the background, so the dashboard has results without waiting an hour.
systemctl start --no-block devmon-helper.service

echo "==> Fixer (root, self-healing actions)"
if [ "$FIXER" -eq 0 ]; then
    systemctl disable --now devmon-fixer.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/devmon-fixer.service
    systemctl daemon-reload
    echo "Skipped (--no-fixer): the dashboard shows this device's faults but never fixes them."
else
    if [ ! -f /etc/devmon/fixer.ini ]; then
        install -o root -g root -m 0644 "$REPO/deploy/agent/fixer.example.ini" /etc/devmon/fixer.ini
    fi
    # Blocking attackers uses nftables; the package only adds the nft command.
    if ! command -v nft >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        echo "Installing nftables (the nft command, for blocking attackers)..."
        apt-get install -y --no-install-recommends nftables >/dev/null || \
            echo "Could not install nftables: blocking attackers will fail on this device."
    fi
    install -o root -g root -m 0644 "$REPO/deploy/agent/devmon-fixer.service" /etc/systemd/system/devmon-fixer.service
    systemctl daemon-reload
    systemctl enable devmon-fixer.service >/dev/null
    systemctl restart devmon-fixer.service
    # The agent reports whether it has a fixer when it connects.
    systemctl restart devmon-agent.service
    echo "Fixer running. Its limits are in /etc/devmon/fixer.ini."
fi

echo "==> Hardware watchdog"
if [ "$WATCHDOG" -eq 0 ]; then
    rm -f /etc/systemd/system.conf.d/devmon-watchdog.conf
    echo "Skipped (--no-watchdog)."
elif [ -e /dev/watchdog ] || [ -e /dev/watchdog0 ]; then
    mkdir -p /etc/systemd/system.conf.d
    # 15 s is the most the Raspberry Pi's watchdog allows; other boards accept it too.
    printf '[Manager]\nRuntimeWatchdogSec=15\nRebootWatchdogSec=2min\n' \
        > /etc/systemd/system.conf.d/devmon-watchdog.conf
    systemctl daemon-reexec
    echo "On: if the system freezes for 15 s, the hardware reboots it."
else
    echo "No hardware watchdog (/dev/watchdog) found. On a Pi, add dtparam=watchdog=on to"
    echo "/boot/firmware/config.txt (or /boot/config.txt), reboot, and run this installer again."
fi

echo "==> Firewall logging (for port-scan detection)"
if [ "$FWLOG" -eq 0 ]; then
    echo "Skipped (--no-firewall-log): port-scan detection stays off on this device."
elif command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        # Gossip between the agents: signed heartbeats on UDP 55556, from the local network only.
        for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
            ufw allow from "$net" to any port 55556 proto udp comment "devmon gossip" >/dev/null
        done
        echo "ufw allows devmon gossip (UDP 55556) from the local network."
    fi
    LEVEL="$(sed -n 's/^LOGLEVEL=//p' /etc/ufw/ufw.conf 2>/dev/null | tr -d "\"'" | head -n 1)"
    if [ "$LEVEL" = "off" ]; then
        # "low" logs blocked packets only, rate-limited by the kernel.
        ufw logging low >/dev/null
        echo "ufw now logs blocked packets."
    else
        echo "ufw already logs blocked packets (${LEVEL:-low})."
    fi
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    echo "firewalld: allow UDP 55556 from your network yourself for gossip between devices."
    if [ "$(firewall-cmd --get-log-denied)" = "off" ]; then
        firewall-cmd --set-log-denied=unicast >/dev/null
        echo "firewalld now logs denied packets."
    else
        echo "firewalld already logs denied packets."
    fi
else
    echo "No ufw or running firewalld: port-scan detection stays off until a firewall"
    echo "logs the packets it blocks (see docs/RUNNING.md, Checkpoint 5)."
fi

echo
echo "The agent is installed and running."
echo "This device's fingerprint: $FPRINT"
echo "On the dashboard's Devices page, approve the pending device only if its fingerprint matches."
echo "Logs: journalctl -u devmon-agent -f"
echo "Security helper: systemctl list-timers devmon-helper; results in /var/lib/devmon-helper/status.json"
if [ "$FIXER" -eq 1 ]; then
    echo "Fixer: journalctl -u devmon-fixer -f; limits in /etc/devmon/fixer.ini"
fi

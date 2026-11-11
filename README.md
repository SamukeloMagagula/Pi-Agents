# Pi-Agents — WindPulse Monitoring Agent & Node Defences

The **agent** that runs on each monitored node (Raspberry Pi, cloud VM, or any Linux/Windows
machine), plus the node-side defences: encryption at rest, intrusion blocking, and the secure
Pi-to-Pi mesh.

Each agent periodically samples the node (CPU, memory, temperature, service state, open ports,
auth-log events) and streams encrypted, mutually authenticated messages to the hub — see the
sibling [sxmukelo](https://github.com/SamukeloMagagula/sxmukelo) repo.

This repo is one of three that make up WindPulse:

| Repo | Role |
|---|---|
| [sxmukelo](https://github.com/SamukeloMagagula/sxmukelo) | The hub: detection, correlation, dashboard |
| **Pi-Agents** (this repo) | The agent + node defences |
| [Kali-agent](https://github.com/SamukeloMagagula/Kali-agent) | The scoped red-team attack kit |

## Layout

```
src/devmon/
  agent/         the agent: collectors, buffering, self-healing client, gossip, root fixer
    collectors/  system, MariaDB, ports, security and event collectors
  shared/        code shared with the hub: secure link, message formats, keys, network rules
tests/           pytest suite for agent/ and shared/
deploy/agent/    agent installers (Linux, Windows), systemd units, the root fixer, example configs
tools/
  vault.py                   encryption at rest — the key stays on the hub, this Pi holds only ciphertext
  watch-block.sh              fail2ban-style guard: detects and firewall-blocks a brute-force source
  prove-encrypted-channel.sh  tcpdump proof the node-to-node mesh is ciphertext in transit
  cluster-up.sh               form a passwordless SSH mesh across the node fleet
  pi-agent-bridge.sh          tunnel the agent channel inside HTTPS/443 for restrictive networks
  pi-demo-setup.sh            create a demo account + enable password SSH, for the attack demo
  fault-inject.py             fault-injection harness for self-healing experiments
```

## Install the agent

```sh
sudo deploy/agent/install.sh --hub <HUB_HOST> --fingerprint <HUB_FINGERPRINT>
```

This also installs the **fixer** (a root service carrying out self-healing actions —
restarting services, blocking attackers), turns on firewall logging for port-scan detection,
and arms the hardware watchdog so a frozen node reboots itself. See the installer's own
`--help` for `--no-fixer` / `--no-firewall-log` / `--no-watchdog` to skip any of those.

## Node defences

```sh
# encryption at rest: the key never touches the Pi
python3 tools/vault.py gen-key vault.key        # on the HUB only
python3 tools/vault.py encrypt --key vault.key  secret.csv secret.enc

# intrusion blocking
sudo ./tools/watch-block.sh                     # detect + firewall-block a brute-force source

# prove the node-to-node channel is encrypted
sudo PEER=pi-02 ./tools/prove-encrypted-channel.sh
```

## Cluster mesh

```sh
export CLUSTER_NODES="192.168.1.21 192.168.1.22 192.168.1.23"
export ADMIN_USER=pi
./tools/cluster-up.sh
```
Forms a passwordless SSH mesh — `ssh pi-02`, `ping pi-03`, `scp file pi-02:~` — between every
node in the fleet.

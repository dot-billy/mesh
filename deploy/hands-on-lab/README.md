# Persistent hands-on Mesh hosts

These are privileged Fedora 42 Docker containers with real systemd, SSH,
`mesh-agent`, and Nebula. They are mock hosts for hands-on testing, not a
production isolation boundary.

The containers use the isolated `mesh-hands-on-lab` Docker bridge:

| Host | Underlay | Overlay | LAN SSH |
| --- | --- | --- | --- |
| `mesh-lab-lighthouse` | `192.0.2.10` | `10.93.0.10` | `10.46.0.34:2222` |
| `mesh-lab-member` | `192.0.2.11` | `10.93.0.11` | `10.46.0.34:2223` |

Both expose SSH only through the host LAN address. Root SSH is disabled. The
`mesh-lab` account is in `wheel`, so use `sudo` for system state and root-owned
Mesh files. This workstation's `/home/uwadmin/.ssh/id_ed25519.pub` is
authorized on both hosts, and separate test passwords are retained in the
mode-`0600` `/home/uwadmin/.local/share/mesh-hands-on-lab/access.json`.

```bash
ssh -p 2222 mesh-lab@10.46.0.34
ssh -p 2223 mesh-lab@10.46.0.34
```

Useful local access:

```bash
docker exec -it mesh-lab-lighthouse bash
docker exec -it mesh-lab-member bash
```

Useful checks after login:

```bash
sudo systemctl status mesh-agent mesh-nebula
sudo journalctl -u mesh-agent -u mesh-nebula
ip addr show nebula1
ping -c 3 <peer-overlay-ip>
```

The host installs `99-mesh-hands-on-lab.conf` under `/etc/sysctl.d` because the
local Kubernetes cluster already exceeds the distribution default inotify
instance limit. The setting is narrowly scoped to the instance count and is
required for these systemd containers to survive host and Docker restarts.

The live Mesh inventory is the `hands-on-lab` network (`10.93.0.0/24`) with
`lab-lighthouse` and `lab-member`. The sanitized deployment receipt is
`/home/uwadmin/.local/share/mesh-hands-on-lab/deployment.json`.

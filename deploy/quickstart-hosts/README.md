# Persistent quickstart hosts

The two original quickstart proofs used temporary hosts and retained their
control-plane inventory. These four privileged Fedora 42 Docker containers
make that inventory hands-on and persistent:

| Network | Host | Underlay | Overlay | SSH |
| --- | --- | --- | --- | --- |
| `quickstart-live-3` | `mesh-quickstart-live-lighthouse` | `192.0.3.10` | `10.91.0.10` | `10.46.0.34:2230` |
| `quickstart-live-3` | `mesh-quickstart-live-member` | `192.0.3.11` | `10.91.0.11` | `10.46.0.34:2231` |
| `quickstart-online-1` | `mesh-quickstart-online-lighthouse` | `192.0.4.10` | `10.92.0.12` | `10.46.0.34:2232` |
| `quickstart-online-1` | `mesh-quickstart-online-member` | `192.0.4.11` | `10.92.0.13` | `10.46.0.34:2233` |

Both pairs are isolated on separate Docker bridges. The signed Nebula
configurations retain the proof endpoint `192.0.2.1:4242`; the
`mesh-quickstart-underlay.service` unit maps that endpoint to each pair's
lighthouse and restores the mapping after container restarts. The host
`mesh-quickstart-docker-nat.service` adds two exact source-NAT exemptions so
Nebula sees each member's real underlay address during its return handshake.

The online pair uses `.12` and `.13` because replacing the private identities
destroyed with the original temporary hosts revoked `.10` and `.11`. The
revoked records remain as certificate-blocklist authority until their
certificates expire and the control plane permits archival.

SSH uses the `mesh-lab` account. This workstation's
`/home/uwadmin/.ssh/id_ed25519.pub` is authorized. Test passwords are stored
outside the workspace in the mode-`0600`
`/home/uwadmin/.local/share/mesh-quickstart-hosts/access.json`.

These are mock hosts, not a production isolation boundary. They run with
Docker `--privileged` so systemd and Nebula can access `/dev/net/tun`.

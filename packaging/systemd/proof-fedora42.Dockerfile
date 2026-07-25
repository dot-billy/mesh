# Pinned clean-host fixture for scripts/linux-install-smoke.sh. This image is
# privileged only when the harness starts its isolated systemd container; it
# contains no Mesh binaries, keys, manifests, or pre-created install state.
FROM fedora@sha256:99e203b80b1c3d8f7e161ec10a68fd02b081ef83a3963553e513c82846b97814

LABEL io.mesh.systemd-proof="fedora42-v5"

RUN dnf -y install systemd iproute iputils procps-ng curl coreutils findutils inotify-tools sed python3 openssl ca-certificates sudo && \
    systemctl mask getty@tty1.service systemd-vconsole-setup.service && \
    dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

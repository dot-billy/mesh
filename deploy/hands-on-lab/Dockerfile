FROM mesh-systemd-proof:fedora42

RUN dnf --assumeyes install openssh-server \
    && dnf clean all \
    && systemctl enable sshd.service

COPY sshd_config /etc/ssh/sshd_config.d/90-mesh-hands-on-lab.conf

LABEL io.mesh.hands-on-lab="fedora42-ssh-v1"


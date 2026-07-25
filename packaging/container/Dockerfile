# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The multi-platform Go 1.26.5 index is pinned so the build input cannot drift
# under the human-readable tag. Override only as part of an audited update.
ARG GO_IMAGE=docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /out/mesh-server ./cmd/mesh-server && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /out/mesh-healthcheck ./cmd/mesh-healthcheck && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /out/mesh-kube-init ./cmd/mesh-kube-init && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /out/nebula-cert github.com/slackhq/nebula/cmd/nebula-cert

RUN go version -m /out/nebula-cert | grep -Eq '^[[:space:]]*mod[[:space:]]+github.com/slackhq/nebula[[:space:]]+v1.10.3([[:space:]]|$)' && \
    install -d -m 0555 /rootfs/run/secrets /rootfs/run/tls && \
    install -d -m 0700 /rootfs/var/lib/mesh && \
    install -d -m 01777 /rootfs/tmp && \
    touch /rootfs/run/secrets/admin.token /rootfs/run/secrets/master.key \
      /rootfs/run/tls/server.crt /rootfs/run/tls/server.key /rootfs/run/tls/ca.crt && \
    chmod 0400 /rootfs/run/secrets/admin.token /rootfs/run/secrets/master.key \
      /rootfs/run/tls/server.key && \
    chmod 0444 /rootfs/run/tls/server.crt /rootfs/run/tls/ca.crt

FROM scratch

LABEL org.opencontainers.image.title="Mesh control plane" \
      org.opencontainers.image.description="Security-first Slack Nebula lifecycle control plane"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /rootfs/ /
COPY --from=build --chown=65532:65532 /out/mesh-server /out/mesh-healthcheck /out/mesh-kube-init /out/nebula-cert /usr/local/bin/

ENV NEBULA_CERT_BINARY=/usr/local/bin/nebula-cert
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/mesh-server"]

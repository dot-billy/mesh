# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

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
      go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /out/mesh-origin ./cmd/mesh-origin && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /out/mesh-healthcheck ./cmd/mesh-healthcheck && \
    install -d -m 0555 /rootfs/run/origin /rootfs/run/tls /rootfs/srv/repository && \
    touch /rootfs/run/origin/index.json /rootfs/run/tls/server.crt /rootfs/run/tls/server.key /rootfs/run/tls/ca.crt && \
    chmod 0400 /rootfs/run/tls/server.key && \
    chmod 0444 /rootfs/run/origin/index.json /rootfs/run/tls/server.crt /rootfs/run/tls/ca.crt

FROM scratch
LABEL org.opencontainers.image.title="Mesh release origin" \
      org.opencontainers.image.description="Explicit digest-verified public courier for threshold-authenticated Mesh releases"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /rootfs/ /
COPY --from=build --chown=65532:65532 /out/mesh-origin /out/mesh-healthcheck /usr/local/bin/

USER 65532:65532
EXPOSE 8444
ENTRYPOINT ["/usr/local/bin/mesh-origin"]

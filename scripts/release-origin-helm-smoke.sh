#!/usr/bin/env bash
set -Eeuo pipefail

chart="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../packaging/helm/mesh-release-origin" && pwd -P)"
if ! command -v helm >/dev/null 2>&1; then
  printf 'release-origin-helm-smoke: helm is required\n' >&2
  exit 77
fi

work_dir="$(mktemp -d)"
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  case "${work_dir}" in
    /tmp/tmp.*) rm -rf -- "${work_dir}" ;;
    *) printf 'release-origin-helm-smoke: refusing to remove %s\n' "${work_dir}" >&2; status=1 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
base=(
  --set-string image.repository=registry.example.test/mesh/release-origin
  --set-string image.digest="${digest}"
  --set-string publicURL=https://releases.example.test
  --set-string publicHost=releases.example.test
  --set-string tls.secretName=mesh-release-tls
)

helm lint "${chart}" "${base[@]}"
helm template origin "${chart}" --namespace mesh-system "${base[@]}" >"${work_dir}/origin.yaml"

for required in \
  'image: "registry.example.test/mesh/release-origin@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
  '--public-url=https://releases.example.test' \
  '--root=/srv/generation/repository' \
  '--index=/srv/generation/origin-index.json' \
  'runAsUser: 65532' \
  'runAsNonRoot: true' \
  'fsGroup: 65532' \
  'defaultMode: 0440' \
  'readOnlyRootFilesystem: true' \
  'automountServiceAccountToken: false' \
  'readOnly: true' \
  'claimName: origin-mesh-release-origin'; do
  grep -Fq -- "${required}" "${work_dir}/origin.yaml" || {
    printf 'release-origin-helm-smoke: render is missing %s\n' "${required}" >&2
    exit 1
  }
done

if helm template invalid "${chart}" >/dev/null 2>&1; then
  printf 'release-origin-helm-smoke: chart accepted missing image, origin, and TLS authority\n' >&2
  exit 1
fi
if helm template multi "${chart}" "${base[@]}" --set replicaCount=2 >/dev/null 2>&1; then
  printf 'release-origin-helm-smoke: multiple replicas accepted a single-writer access mode\n' >&2
  exit 1
fi

helm template existing "${chart}" --namespace mesh-system "${base[@]}" \
  --set-string content.existingClaim=mesh-release-content \
  --set ingress.enabled=true \
  --set-string ingress.className=traefik \
  --set-string ingress.tlsSecretName=mesh-edge-tls \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}]' \
  >"${work_dir}/existing.yaml"
for required in \
  'claimName: mesh-release-content' \
  'kind: Ingress' \
  'secretName: mesh-edge-tls' \
  'kind: NetworkPolicy'; do
  grep -Fq -- "${required}" "${work_dir}/existing.yaml" || {
    printf 'release-origin-helm-smoke: existing-claim render is missing %s\n' "${required}" >&2
    exit 1
  }
done
if grep -Fq 'kind: PersistentVolumeClaim' "${work_dir}/existing.yaml"; then
  printf 'release-origin-helm-smoke: existing-claim render unexpectedly owns a PVC\n' >&2
  exit 1
fi

printf 'release-origin Helm chart smoke passed\n'

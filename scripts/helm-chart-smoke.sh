#!/usr/bin/env bash
set -euo pipefail

chart="$(cd "$(dirname "${BASH_SOURCE[0]}")/../packaging/helm/mesh-control-plane" && pwd)"
if ! command -v helm >/dev/null 2>&1; then
  echo "helm-chart-smoke: helm is required" >&2
  exit 77
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "${work_dir}"' EXIT

digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
base=(
  --set-string image.repository=registry.example.test/mesh/control-plane
  --set-string image.digest="${digest}"
  --set-string publicURL=https://mesh.example.test
  --set-string publicHost=mesh.example.test
  --set-string credentials.secretName=mesh-credentials
  --set-string tls.secretName=mesh-tls
)

helm lint "${chart}" "${base[@]}"
helm template json "${chart}" --namespace mesh-system "${base[@]}" >"${work_dir}/json.yaml"

for required in \
  'image: "registry.example.test/mesh/control-plane@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  'command: ["/usr/local/bin/mesh-kube-init"]' \
  'add: ["CHOWN", "DAC_OVERRIDE", "FOWNER"]' \
  'runAsUser: 65532' \
  'readOnlyRootFilesystem: true' \
  'automountServiceAccountToken: false' \
  'type: Recreate' \
  'medium: Memory' \
  'claimName: json-mesh-control-plane'; do
  grep -Fq -- "${required}" "${work_dir}/json.yaml" || {
    echo "helm-chart-smoke: JSON render is missing ${required}" >&2
    exit 1
  }
done
if grep -Eq 'name: (MESH_ADMIN_TOKEN|MESH_MASTER_KEY)' "${work_dir}/json.yaml"; then
  echo "helm-chart-smoke: recovery credentials leaked into container environment" >&2
  exit 1
fi

if helm template invalid "${chart}" >/dev/null 2>&1; then
  echo "helm-chart-smoke: chart accepted missing image, origin, and Secret authority" >&2
  exit 1
fi
if helm template invalid "${chart}" "${base[@]}" --set replicaCount=2 >/dev/null 2>&1; then
  echo "helm-chart-smoke: JSON storage accepted multiple replicas" >&2
  exit 1
fi

helm template postgres "${chart}" --namespace mesh-system "${base[@]}" \
  --set storage.backend=postgres \
  --set storage.postgres.secretName=mesh-postgres \
  --set replicaCount=2 >"${work_dir}/postgres.yaml"
for required in \
  'type: RollingUpdate' \
  'replicas: 2' \
  '--postgres-source-dir=/input/postgres' \
  '--postgres-dsn-file=/run/mesh/private/postgres.dsn' \
  'secretName: mesh-postgres'; do
  grep -Fq -- "${required}" "${work_dir}/postgres.yaml" || {
    echo "helm-chart-smoke: PostgreSQL render is missing ${required}" >&2
    exit 1
  }
done
if grep -Fq 'kind: PersistentVolumeClaim' "${work_dir}/postgres.yaml"; then
  echo "helm-chart-smoke: PostgreSQL render unexpectedly owns a JSON PVC" >&2
  exit 1
fi

helm template identity "${chart}" --namespace mesh-system "${base[@]}" \
  --set identity.enabled=true \
  --set identity.secretName=mesh-identity \
  --set ingress.enabled=true \
  --set ingress.tlsSecretName=mesh-edge-tls \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-system"}}}]' \
  >"${work_dir}/identity.yaml"
for required in \
  '--identity-source-dir=/input/identity' \
  '--identity-config=/run/mesh/private/identity.json' \
  'secretName: mesh-identity' \
  'kind: Ingress' \
  'secretName: mesh-edge-tls' \
  'kind: NetworkPolicy'; do
  grep -Fq -- "${required}" "${work_dir}/identity.yaml" || {
    echo "helm-chart-smoke: identity/edge render is missing ${required}" >&2
    exit 1
  }
done

echo "helm chart smoke passed"

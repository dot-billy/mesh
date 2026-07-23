#!/usr/bin/env bash
set -Eeuo pipefail

readonly script_name="$(basename "$0")"
readonly repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
readonly chart="${repository_root}/packaging/helm/mesh-control-plane"
readonly image="${MESH_HELM_KUBERNETES_IMAGE:-mesh-control-plane:helm-contract-verified}"
readonly target_node="${MESH_HELM_KUBERNETES_NODE:-k8s-01}"

work_dir=""
namespace=""
loader_ready=false
release_installed=false
image_imported=false
port_forward_pid=""
host_archive=""
imported_ref="docker.io/library/mesh-control-plane:helm-contract-verified"
imported_digest_ref=""
local_pv_name=""
local_pv_path=""

say() { printf '%s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*" >&2; exit 77; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

stop_port_forward() {
  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
    port_forward_pid=""
  fi
}

remove_cluster_resources() {
  stop_port_forward
  if [[ "${release_installed}" == true ]]; then
    helm uninstall mesh --namespace "${namespace}" --wait --timeout 2m >/dev/null 2>&1 || true
    release_installed=false
  fi
  if [[ "${loader_ready}" == true ]]; then
    if [[ "${image_imported}" == true ]]; then
      image_refs=("${imported_ref}")
      if [[ -n "${imported_digest_ref}" ]]; then
        image_refs+=("${imported_digest_ref}")
      fi
      kubectl exec --namespace "${namespace}" loader -- \
        chroot /host /var/lib/rancher/rke2/bin/ctr \
        --address /run/k3s/containerd/containerd.sock \
        --namespace k8s.io images remove "${image_refs[@]}" >/dev/null 2>&1 || true
      image_imported=false
    fi
    if [[ -n "${host_archive}" ]]; then
      kubectl exec --namespace "${namespace}" loader -- \
        chroot /host rm -f -- "${host_archive}" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "${namespace}" ]]; then
    kubectl delete pvc mesh-data --namespace "${namespace}" --wait=true --timeout=60s >/dev/null 2>&1 || true
  fi
  if [[ -n "${local_pv_name}" ]]; then
    kubectl delete pv "${local_pv_name}" --wait=true --timeout=60s >/dev/null 2>&1 || true
  fi
  if [[ "${loader_ready}" == true ]]; then
    case "${local_pv_path}" in
      /var/lib/mesh-helm-smoke/mesh-helm-smoke-*)
        kubectl exec --namespace "${namespace}" loader -- \
          chroot /host rm -rf -- "${local_pv_path}" >/dev/null 2>&1 || true
        ;;
      "") ;;
      *) printf 'Refusing to remove unexpected local-PV path %s\n' "${local_pv_path}" >&2 ;;
    esac
  fi
  if [[ -n "${namespace}" ]]; then
    kubectl delete namespace "${namespace}" --wait=true --timeout=2m >/dev/null 2>&1 || true
    loader_ready=false
  fi
}

cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  remove_cluster_resources
  case "${work_dir}" in
    /tmp/mesh-helm-kubernetes-smoke.*) rm -rf -- "${work_dir}" ;;
    "") ;;
    *) printf 'Refusing to remove unexpected work directory %s\n' "${work_dir}" >&2 ;;
  esac
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"
  trap - ERR
  printf 'ERROR: %s failed at line %s\n' "${script_name}" "${line}" >&2
  if [[ -n "${namespace}" ]]; then
    kubectl get pods,pvc --namespace "${namespace}" -o wide >&2 2>/dev/null || true
    kubectl describe pods --namespace "${namespace}" >&2 2>/dev/null || true
    kubectl logs --namespace "${namespace}" --selector app.kubernetes.io/name=mesh-control-plane \
      --all-containers --tail=120 >&2 2>/dev/null || true
  fi
  exit "${status}"
}

pick_loopback_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

start_port_forward() {
  stop_port_forward
  kubectl port-forward --namespace "${namespace}" --address 127.0.0.1 \
    service/mesh-mesh-control-plane "${local_port}:443" \
    >"${work_dir}/port-forward.log" 2>&1 &
  port_forward_pid=$!
  for _ in {1..40}; do
    if grep -Fq "Forwarding from 127.0.0.1:${local_port}" "${work_dir}/port-forward.log"; then
      return
    fi
    if ! kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
      cat "${work_dir}/port-forward.log" >&2
      die "port-forward exited before becoming ready"
    fi
    sleep 0.25
  done
  die "port-forward did not become ready"
}

api_request() {
  local method="$1"
  local path="$2"
  local output="$3"
  shift 3
  curl --silent --show-error --fail --noproxy '*' \
    --request "${method}" \
    --resolve "${public_host}:${local_port}:127.0.0.1" \
    --cacert "${work_dir}/tls/tls.crt" \
    --connect-timeout 2 --max-time 15 \
    --header "Authorization: Bearer ${admin_token}" \
    --output "${output}" \
    "$@" \
    "https://${public_host}:${local_port}${path}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in docker helm kubectl openssl curl python3 sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 || skip "${command_name} is unavailable"
done
docker info >/dev/null 2>&1 || skip "Docker daemon is unavailable"
kubectl get node "${target_node}" >/dev/null 2>&1 || skip "target node ${target_node} is unavailable"
[[ "$(kubectl get node "${target_node}" -o jsonpath='{.status.nodeInfo.architecture}')" == amd64 ]] || \
  skip "target node is not linux/amd64"
[[ "$(kubectl auth can-i create namespaces)" == yes ]] || skip "cluster namespace creation is unavailable"
docker image inspect "${image}" >/dev/null 2>&1 || skip "candidate image ${image} is unavailable"

work_dir="$(mktemp -d /tmp/mesh-helm-kubernetes-smoke.XXXXXX)"
install -d -m 0700 "${work_dir}/credentials" "${work_dir}/tls"
umask 077
namespace="mesh-helm-smoke-$(date -u +%H%M%S)-$RANDOM"
host_archive="/tmp/${namespace}-image.tar"
local_pv_name="${namespace}-data"
local_pv_path="/var/lib/mesh-helm-smoke/${namespace}"
public_host="mesh-helm-smoke.example.test"
local_port="$(pick_loopback_port)"
[[ "${local_port}" =~ ^[0-9]+$ ]] || die "kernel returned an invalid loopback port"

image_id="$(docker image inspect "${image}" --format '{{.Id}}')"
[[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Docker returned an invalid image ID"
image_digest="${image_id#sha256:}"
imported_digest_ref="docker.io/library/mesh-control-plane@${image_id}"

security_receipt="${MESH_HELM_SECURITY_RECEIPT:-}"
if [[ -z "${security_receipt}" ]]; then
  security_receipt="$(python3 - "${repository_root}/bin/image-security" "${image_id}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
wanted = sys.argv[2]
matches = []
if root.is_dir():
    for path in root.glob("*/receipt.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if document.get("schema") == "mesh-image-security-receipt-v1" and document.get("image", {}).get("docker_image_id") == wanted:
            matches.append(path)
if matches:
    print(max(matches, key=lambda item: item.stat().st_mtime))
PY
)"
fi
[[ -n "${security_receipt}" && -f "${security_receipt}" ]] || die "no matching image-security receipt is available"

python3 - "${security_receipt}" "${image_id}" <<'PY'
import datetime as dt
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
assert document["schema"] == "mesh-image-security-receipt-v1"
assert document["image"]["docker_image_id"] == sys.argv[2]
assert document["image"]["platform"] == "linux/amd64"
assert document["image"]["filesystem_entry_count"] == 23
completed = dt.datetime.fromisoformat(document["verified_at"].replace("Z", "+00:00"))
now = dt.datetime.now(dt.timezone.utc)
assert completed <= now + dt.timedelta(minutes=5)
assert now - completed <= dt.timedelta(hours=24)
PY

admin_token="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')"
master_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')"
[[ ${#admin_token} -eq 43 && ${#master_key} -eq 43 ]] || die "credential generation failed"
printf '%s\n' "${admin_token}" >"${work_dir}/credentials/admin.token"
printf '%s\n' "${master_key}" >"${work_dir}/credentials/master.key"
chmod 0400 "${work_dir}/credentials/admin.token" "${work_dir}/credentials/master.key"
unset master_key

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj "/CN=${public_host}" \
  -addext "subjectAltName=DNS:${public_host}" \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "${work_dir}/tls/tls.key" \
  -out "${work_dir}/tls/tls.crt" >/dev/null 2>&1
cp -- "${work_dir}/tls/tls.crt" "${work_dir}/tls/ca.crt"
chmod 0400 "${work_dir}/tls/tls.key"
chmod 0444 "${work_dir}/tls/tls.crt" "${work_dir}/tls/ca.crt"

say "Creating isolated proof namespace and node-local image loader"
kubectl create namespace "${namespace}" >/dev/null
kubectl run loader --namespace "${namespace}" --image=busybox:latest \
  --image-pull-policy=IfNotPresent --restart=Never \
  --overrides="{\"spec\":{\"nodeName\":\"${target_node}\",\"automountServiceAccountToken\":false,\"hostPID\":true,\"containers\":[{\"name\":\"loader\",\"image\":\"busybox:latest\",\"imagePullPolicy\":\"IfNotPresent\",\"command\":[\"sleep\",\"900\"],\"securityContext\":{\"privileged\":true,\"allowPrivilegeEscalation\":true},\"volumeMounts\":[{\"name\":\"host-root\",\"mountPath\":\"/host\"}]}],\"volumes\":[{\"name\":\"host-root\",\"hostPath\":{\"path\":\"/\",\"type\":\"Directory\"}}]}}" >/dev/null
kubectl wait --namespace "${namespace}" --for=condition=Ready pod/loader --timeout=60s >/dev/null
loader_ready=true
kubectl exec --namespace "${namespace}" loader -- \
  chroot /host test -x /var/lib/rancher/rke2/bin/ctr

say "Importing the security-gated image into the selected node"
docker image save --output "${work_dir}/image.tar" "${image}"
kubectl cp "${work_dir}/image.tar" "${namespace}/loader:/host${host_archive}" >/dev/null
kubectl exec --namespace "${namespace}" loader -- \
  chroot /host /var/lib/rancher/rke2/bin/ctr \
  --address /run/k3s/containerd/containerd.sock \
  --namespace k8s.io images import "${host_archive}" >/dev/null
image_imported=true
kubectl exec --namespace "${namespace}" loader -- \
  chroot /host /var/lib/rancher/rke2/bin/ctr \
  --address /run/k3s/containerd/containerd.sock \
  --namespace k8s.io images tag "${imported_ref}" "${imported_digest_ref}" >/dev/null
imported_images="$(kubectl exec --namespace "${namespace}" loader -- \
  chroot /host /var/lib/rancher/rke2/bin/ctr \
  --address /run/k3s/containerd/containerd.sock \
  --namespace k8s.io images list --quiet)"
grep -Fxq "${imported_ref}" <<<"${imported_images}" || die "containerd did not retain the imported image reference"
grep -Fxq "${imported_digest_ref}" <<<"${imported_images}" || die "containerd did not retain the digest-only image reference"

say "Creating private credential and TLS Secrets"
kubectl create secret generic mesh-credentials --namespace "${namespace}" \
  --from-file=admin.token="${work_dir}/credentials/admin.token" \
  --from-file=master.key="${work_dir}/credentials/master.key" >/dev/null
kubectl create secret generic mesh-tls --namespace "${namespace}" \
  --from-file=tls.crt="${work_dir}/tls/tls.crt" \
  --from-file=tls.key="${work_dir}/tls/tls.key" \
  --from-file=ca.crt="${work_dir}/tls/ca.crt" >/dev/null

say "Creating one proof-owned node-local PersistentVolume"
kubectl exec --namespace "${namespace}" loader -- \
  chroot /host mkdir -p -- "${local_pv_path}"
kubectl exec --namespace "${namespace}" loader -- \
  chroot /host chmod 0700 -- "${local_pv_path}"
kubectl create -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${local_pv_name}
  labels:
    mesh.example.test/proof: helm-kubernetes-smoke
spec:
  capacity:
    storage: 256Mi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  local:
    path: ${local_pv_path}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - ${target_node}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mesh-data
  namespace: ${namespace}
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  storageClassName: ""
  volumeName: ${local_pv_name}
  resources:
    requests:
      storage: 256Mi
EOF

say "Installing the exact digest through Helm and the proof-owned PVC"
helm upgrade --install mesh "${chart}" --namespace "${namespace}" \
  --set-string image.repository=docker.io/library/mesh-control-plane \
  --set-string image.digest="${image_id}" \
  --set image.pullPolicy=Never \
  --set-string publicURL="https://${public_host}:${local_port}" \
  --set-string publicHost="${public_host}" \
  --set-string credentials.secretName=mesh-credentials \
  --set-string tls.secretName=mesh-tls \
  --set-string storage.persistence.existingClaim=mesh-data \
  --set-string 'nodeSelector.kubernetes\.io/hostname'="${target_node}" \
  --rollback-on-failure --wait --timeout 4m >/dev/null
release_installed=true

pod_name="$(kubectl get pods --namespace "${namespace}" --selector app.kubernetes.io/name=mesh-control-plane -o jsonpath='{.items[0].metadata.name}')"
pod_uid_before="$(kubectl get pod --namespace "${namespace}" "${pod_name}" -o jsonpath='{.metadata.uid}')"
pvc_uid_before="$(kubectl get pvc --namespace "${namespace}" mesh-data -o jsonpath='{.metadata.uid}')"
[[ -n "${pod_uid_before}" && -n "${pvc_uid_before}" ]] || die "Helm did not create exact pod/PVC identities"
[[ "$(kubectl get pod --namespace "${namespace}" "${pod_name}" -o jsonpath='{.spec.nodeName}')" == "${target_node}" ]] || \
  die "Mesh pod was not pinned to the imported-image node"
[[ "$(kubectl get pvc --namespace "${namespace}" mesh-data -o jsonpath='{.status.phase}')" == Bound ]] || \
  die "proof-owned PVC is not bound"

kubectl get pod --namespace "${namespace}" "${pod_name}" -o json >"${work_dir}/pod-before.json"
python3 - "${work_dir}/pod-before.json" "${image_id}" <<'PY'
import json
import pathlib
import sys

pod = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert pod["spec"]["automountServiceAccountToken"] is False
init = pod["spec"]["initContainers"][0]
main = pod["spec"]["containers"][0]
assert init["securityContext"]["capabilities"] == {"add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"], "drop": ["ALL"]}
assert main["securityContext"]["runAsUser"] == 65532
assert main["securityContext"]["runAsGroup"] == 65532
assert main["securityContext"]["runAsNonRoot"] is True
assert main["securityContext"]["readOnlyRootFilesystem"] is True
assert main["securityContext"]["capabilities"] == {"drop": ["ALL"]}
status = pod["status"]["containerStatuses"][0]
assert status["ready"] is True
assert status["imageID"].endswith("@" + sys.argv[2]), status["imageID"]
PY

start_port_forward
ready_body="$(curl --silent --show-error --fail --noproxy '*' \
  --resolve "${public_host}:${local_port}:127.0.0.1" \
  --cacert "${work_dir}/tls/tls.crt" \
  "https://${public_host}:${local_port}/readyz")"
[[ "${ready_body}" == '{"status":"ready"}' ]] || die "cluster readiness returned an unexpected body"

say "Creating authoritative network state through the deployed API"
api_request POST /api/v1/networks "${work_dir}/created-network.json" \
  --header 'Content-Type: application/json' \
  --data-binary '{"name":"helm-kubernetes-proof","cidr":"10.254.253.0/24"}'
network_id="$(python3 - "${work_dir}/created-network.json" <<'PY'
import json
import pathlib
import sys
network = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert network["name"] == "helm-kubernetes-proof"
assert network["cidr"] == "10.254.253.0/24"
assert network["config_revision"] == 1
assert isinstance(network["id"], str) and network["id"]
print(network["id"])
PY
)"

say "Replacing the pod and proving the same PVC retains authoritative state"
stop_port_forward
kubectl delete pod --namespace "${namespace}" "${pod_name}" --wait=true --timeout=90s >/dev/null
kubectl rollout status deployment/mesh-mesh-control-plane --namespace "${namespace}" --timeout=3m >/dev/null
pod_name_after="$(kubectl get pods --namespace "${namespace}" --selector app.kubernetes.io/name=mesh-control-plane -o jsonpath='{.items[0].metadata.name}')"
pod_uid_after="$(kubectl get pod --namespace "${namespace}" "${pod_name_after}" -o jsonpath='{.metadata.uid}')"
pvc_uid_after="$(kubectl get pvc --namespace "${namespace}" mesh-data -o jsonpath='{.metadata.uid}')"
[[ "${pod_uid_after}" != "${pod_uid_before}" ]] || die "pod replacement retained the old pod identity"
[[ "${pvc_uid_after}" == "${pvc_uid_before}" ]] || die "pod replacement changed the PVC identity"

start_port_forward
api_request GET /api/v1/networks "${work_dir}/networks-after-restart.json"
python3 - "${work_dir}/networks-after-restart.json" "${network_id}" <<'PY'
import json
import pathlib
import sys
networks = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matches = [item for item in networks if item.get("id") == sys.argv[2]]
assert len(matches) == 1
assert matches[0]["name"] == "helm-kubernetes-proof"
assert matches[0]["cidr"] == "10.254.253.0/24"
assert matches[0]["config_revision"] == 1
PY

cluster_version="$(kubectl version -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')"
kube_context="$(kubectl config current-context)"
security_receipt_sha256="$(sha256sum "${security_receipt}" | awk '{print $1}')"
chart_sha256="$(find "${chart}" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

say "Removing every proof-owned cluster resource and imported image reference"
stop_port_forward
helm uninstall mesh --namespace "${namespace}" --wait --timeout 2m >/dev/null
release_installed=false
kubectl wait --namespace "${namespace}" --for=delete pod \
  --selector app.kubernetes.io/name=mesh-control-plane --timeout=90s >/dev/null 2>&1 || true
kubectl delete pvc mesh-data --namespace "${namespace}" --wait=true --timeout=60s >/dev/null
kubectl delete pv "${local_pv_name}" --wait=true --timeout=60s >/dev/null
kubectl exec --namespace "${namespace}" loader -- chroot /host rm -rf -- "${local_pv_path}"
if kubectl exec --namespace "${namespace}" loader -- chroot /host test -e "${local_pv_path}" >/dev/null 2>&1; then
  die "proof-owned local-PV directory survived cleanup"
fi
local_pv_name=""
local_pv_path=""
kubectl exec --namespace "${namespace}" loader -- \
  chroot /host /var/lib/rancher/rke2/bin/ctr \
  --address /run/k3s/containerd/containerd.sock \
  --namespace k8s.io images remove "${imported_digest_ref}" "${imported_ref}" >/dev/null
image_imported=false
remaining_images="$(kubectl exec --namespace "${namespace}" loader -- \
  chroot /host /var/lib/rancher/rke2/bin/ctr \
  --address /run/k3s/containerd/containerd.sock \
  --namespace k8s.io images list --quiet)"
if grep -Fxq "${imported_ref}" <<<"${remaining_images}" || grep -Fxq "${imported_digest_ref}" <<<"${remaining_images}"; then
  die "imported image reference survived cleanup"
fi
kubectl exec --namespace "${namespace}" loader -- chroot /host rm -f -- "${host_archive}"
host_archive=""
kubectl delete namespace "${namespace}" --wait=true --timeout=2m >/dev/null
loader_ready=false
if kubectl get namespace "${namespace}" >/dev/null 2>&1; then
  die "proof namespace survived cleanup"
fi

evidence_dir="${repository_root}/bin/helm-kubernetes/${image_digest}-${completed_at//[: -]/}"
mkdir -m 0700 -p "${evidence_dir}"
python3 - "${evidence_dir}/receipt.json" <<PY
import json
import os

receipt = {
    "schema": "mesh-helm-kubernetes-smoke-receipt-v1",
    "completed_at": "${completed_at}",
    "cluster": {"context": "${kube_context}", "server_version": "${cluster_version}", "node": "${target_node}", "storage": "proof-owned node-local PersistentVolume"},
    "image": {"reference": "${image}", "digest": "${image_id}", "security_receipt_sha256": "${security_receipt_sha256}"},
    "chart_sha256": "${chart_sha256}",
    "state": {"network_id": "${network_id}", "network_name": "helm-kubernetes-proof", "cidr": "10.254.253.0/24", "revision": 1},
    "persistence": {"pod_uid_before": "${pod_uid_before}", "pod_uid_after": "${pod_uid_after}", "pvc_uid": "${pvc_uid_before}"},
    "proofs": [
        "exact security-gated image imported and named by its digest through node-local containerd",
        "Helm values schema and digest-only image selection",
        "projected Secret materialization under the exact init capability set",
        "non-root capability-free read-only-root control plane without a service-account token",
        "node-local PVC binding and verified native TLS readiness",
        "authoritative network creation through the deployed HTTPS API",
        "new pod identity with the same PVC and exact authoritative state after restart",
        "namespace, Helm release, PVC, PV directory, host archive, and imported image reference cleanup",
    ],
}
raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
descriptor = os.open("${evidence_dir}/receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
try:
    os.write(descriptor, raw)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY

admin_token=""
say "PASS: native Kubernetes Helm deployment, exact image, projected Secrets, node-local PVC persistence, pod replacement, API state, and cleanup verified"
say "Evidence: ${evidence_dir}"

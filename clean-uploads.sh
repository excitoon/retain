#!/usr/bin/env bash
set -euo pipefail

# Config (override via env or flags)
NAMESPACE="${NAMESPACE:-registry}"           # Kubernetes namespace
SELECTOR="${SELECTOR:-app=registry}"         # Label selector to find registry pod
CONTAINER="${CONTAINER:-}"                   # Container name (auto-detect if empty)
REGISTRY_ROOT="${REGISTRY_ROOT:-/var/lib/registry/docker/registry/v2/repositories}"
OLDER_THAN_MIN="${OLDER_THAN_MIN:-60}"       # Consider uploads inactive after N minutes
DRY_RUN="${DRY_RUN:-true}"                   # true|false
CLEAN_EMPTY_DIRS="${CLEAN_EMPTY_DIRS:-true}" # true|false (post-cleanup, delete empty dirs)

usage() {
  echo "Usage: NAMESPACE=registry SELECTOR='app=registry' REGISTRY_ROOT=/var/lib/registry/docker/registry/v2/repositories OLDER_THAN_MIN=60 DRY_RUN=true $0"
  exit 1
}

# Resolve the target pod
pod="$(sudo k8s kubectl -n "${NAMESPACE}" get pods -l "${SELECTOR}" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.status.containerStatuses[0].ready}{"\n"}{end}' \
  | awk '$2=="Running" && $3=="true"{print $1}' | head -n1 || true)"

if [[ -z "${pod}" ]]; then
  echo "[ERROR] No Running/Ready pod matched selector '${SELECTOR}' in ns '${NAMESPACE}'."
  echo "        Adjust NAMESPACE/SELECTOR or ensure the registry pod is running."
  exit 1
fi

# Resolve the container if not provided
if [[ -z "${CONTAINER}" ]]; then
  CONTAINER="$(sudo k8s kubectl -n "${NAMESPACE}" get pod "${pod}" -o jsonpath='{.spec.containers[0].name}')"
fi

echo "[INFO] Target pod: ${pod} (container=${CONTAINER}, ns=${NAMESPACE})"
echo "[INFO] Registry root: ${REGISTRY_ROOT}"
echo "[INFO] Threshold: older than ${OLDER_THAN_MIN} minutes"
echo "[INFO] Dry-run: ${DRY_RUN}"
echo "[INFO] Clean empty dirs after: ${CLEAN_EMPTY_DIRS}"

# Validate the registry path exists inside the container
if ! sudo k8s kubectl -n "${NAMESPACE}" exec -c "${CONTAINER}" "${pod}" -- sh -lc "test -d '${REGISTRY_ROOT}'"; then
  echo "[ERROR] Path '${REGISTRY_ROOT}' not found inside container."
  echo "        If your registry path is different, set REGISTRY_ROOT to the correct repositories root."
  exit 1
fi

# Build the remote find command
# We look for directories under */_uploads/* that haven't been modified for OLDER_THAN_MIN minutes.
base_find_cmd="find '${REGISTRY_ROOT}' -type d -path '*/_uploads/*' -mmin +${OLDER_THAN_MIN}"

echo "[INFO] Scanning for abandoned upload directories..."
sudo k8s kubectl -n "${NAMESPACE}" exec -c "${CONTAINER}" "${pod}" -- sh -lc "
  set -e
  COUNT=\$(${base_find_cmd} -print | wc -l | tr -d ' ')
  echo \"[INFO] Found \$COUNT directories older than ${OLDER_THAN_MIN} minutes under _uploads/\"
  if [ \"\$COUNT\" -gt 0 ]; then
    echo \"[LIST]\"; ${base_find_cmd} -print
  fi
"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Skipping deletion. Set DRY_RUN=false to remove the above directories."
  exit 0
fi

echo "[ACTION] Deleting abandoned upload directories..."
sudo k8s kubectl -n "${NAMESPACE}" exec -c "${CONTAINER}" "${pod}" -- sh -lc "
  set -e
  ${base_find_cmd} -print -exec rm -rf {} +
  if [ '${CLEAN_EMPTY_DIRS}' = 'true' ]; then
    # Remove now-empty _uploads directories and any empty directories created by the cleanup
    find '${REGISTRY_ROOT}' -type d -empty -print -delete || true
  fi
  echo \"[DONE] Cleanup completed.\"
"

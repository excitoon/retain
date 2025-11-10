#!/usr/bin/env bash
set -euo pipefail

REGISTRY="${REGISTRY:-registry.internal.yourdomain}"
REPO="${1:?usage: $0 repo [keep] [days]}"
KEEP="${2:-30}"
MAX_AGE_DAYS="${3:-0}"         # 0 disables age filter
DRY_RUN="${DRY_RUN:-true}"

cutoff_ts=0
if [ "$MAX_AGE_DAYS" -gt 0 ]; then
  cutoff_ts=$(date -u -d "-${MAX_AGE_DAYS} days" +%s)
fi

tags=$(regctl tag ls "${REGISTRY}/${REPO}" | sort -r)
count=0
while read -r tag; do
  [ -z "$tag" ] && continue
  count=$((count+1))

  # Age check (if enabled)
  if [ "$cutoff_ts" -ne 0 ]; then
    created=$(regctl image config "${REGISTRY}/${REPO}:${tag}" 2>/dev/null | jq -r '.created // empty')
    if [ -n "$created" ]; then
      cts=$(date -u -d "$created" +%s || echo 0)
      if [ "$cts" -lt "$cutoff_ts" ] && [ "$count" -gt "$KEEP" ]; then
        action="DELETE"
      else
        action="KEEP"
      fi
    else
      action=$([ "$count" -le "$KEEP" ] && echo KEEP || echo DELETE)
    fi
  else
    action=$([ "$count" -le "$KEEP" ] && echo KEEP || echo DELETE)
  fi

  if [ "$action" = DELETE ]; then
    if [ "$DRY_RUN" = true ]; then
      echo "DRY DELETE ${REPO}:${tag}"
    else
      echo "Deleting ${REPO}:${tag}"
      regctl tag rm "${REGISTRY}/${REPO}:${tag}"
    fi
  else
    echo "KEEP ${REPO}:${tag}"
  fi
done <<< "$tags"

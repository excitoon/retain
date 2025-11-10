#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Image Retention Script
# -----------------------------------------------------------------------------
# This script enforces tag retention policies across all repositories in a
# Docker Distribution / OCI registry.
#
# Policy dimensions:
#   * Keep newest N tags (KEEP)
#   * Optionally delete tags older than MAX_AGE_DAYS
#   * Never delete protected tags (PROTECT_TAGS)
#   * Never delete tags currently used by running Kubernetes workloads
#   * Skip repositories in EXCLUDE_REPOS
#
# Deletion mechanism:
#   * Attempts manifest deletion first (regctl manifest rm) for stronger GC
#     effect. Falls back to tag deletion if manifest delete unsupported.
#   * Classifies delete errors: 405 (unsupported – enable delete), 500 (internal),
#     ENOSPC errno 28 (disk full during _uploads mkdir), generic failures.
#
# To enable manifest deletion in a Docker Distribution registry, set:
#   storage:
#     delete:
#       enabled: true
# Then restart the registry deployment/pod.
# Until enabled, deletions through manifest rm return 405 UNSUPPORTED.
#
# Space reclamation sequence (recommended):
#   1. Clean abandoned uploads (./clean-uploads.sh) to avoid ENOSPC during deletes.
#   2. Ensure delete enabled (REGISTRY_STORAGE_DELETE_ENABLED=true env or config).
#   3. Run this script (DRY_RUN=false) to prune tags.
#   4. Run registry garbage-collect (dry-run first) to purge unreferenced blobs.
#
# Counters and summary printed at end when DELETE operations attempted.
# -----------------------------------------------------------------------------

# CONFIG (override via env)
REGISTRY="${REGISTRY:-registry.internal.yourdomain}"
KEEP="${KEEP:-5}"               # Keep newest N tags per repository
MAX_AGE_DAYS="${MAX_AGE_DAYS:-1}" # 0 disables age filter
DRY_RUN="${DRY_RUN:-true}"       # true|false
EXCLUDE_REPOS="${EXCLUDE_REPOS:-}"   # space-separated repo names
PROTECT_TAGS="${PROTECT_TAGS:-latest stable production}" # never delete these
PARALLEL="${PARALLEL:-1}"        # concurrent repo processing
KUBE_CONTEXT_SCAN="${KUBE_CONTEXT_SCAN:-true}" # if true, collect running images
KUBECTL="${KUBECTL:-sudo k8s kubectl}"
VERBOSE="${VERBOSE:-false}"          # if true, print discovered repo list
REPO_LIST_OUT="${REPO_LIST_OUT:-}"   # optional file to write repo list
PRINT_TAGS="${PRINT_TAGS:-false}"     # if true, print tag names for each repo (diagnostics)
TAG_PREVIEW_COUNT="${TAG_PREVIEW_COUNT:-50}" # how many tag names to show when PRINT_TAGS=true
GC_ENABLE="${GC_ENABLE:-true}"       # set true to run garbage-collect after pruning
GC_NAMESPACE="${GC_NAMESPACE:-registry}"    # kubernetes namespace of registry
GC_LABEL_SELECTOR="${GC_LABEL_SELECTOR:-name=registry,app=registry,app.kubernetes.io/name=registry,app.kubernetes.io/component=registry,component=registry}" # label selector(s) to find registry pod (comma-separated)
GC_DRY_RUN="${GC_DRY_RUN:-true}"      # run registry garbage-collect in dry-run mode first
GC_CONFIG_PATH="${GC_CONFIG_PATH:-/etc/docker/registry/config.yml}" # path inside pod
GC_EXTRA_ARGS="${GC_EXTRA_ARGS:---delete-untagged}" # extra args (e.g. --delete-untagged)
GC_POD_NAME="${GC_POD_NAME:-}"    # optional explicit pod name override

# Internal record delimiter (avoid tab parsing issues in some shells)
RECORD_DELIM='|'

# Delete error classification helper
# Categorizes common registry deletion failures so we can distinguish
# unsupported (405) from internal (500) or disk full (ENOSPC/Err 28) issues.
classify_delete_error() {
  local ref="$1"; shift
  local msg="$*"
  local http_code="" errno="" category="unknown"
  if [[ "$msg" =~ http\ ([0-9]{3}) ]]; then
    http_code="${BASH_REMATCH[1]}"
  elif [[ "$msg" =~ \[http\ ([0-9]{3})\] ]]; then
    http_code="${BASH_REMATCH[1]}"
  fi
  if [[ "$msg" =~ \"Err\":([0-9]+) ]]; then
    errno="${BASH_REMATCH[1]}"
  fi

  case "$http_code" in
    405) category="unsupported" ;;
    500) category="internal" ;;
  esac
  if [ "$errno" = "28" ]; then
    category="disk-full" # ENOSPC during mkdir in _uploads
  fi

  case "$category" in
    unsupported)
      echo "    SKIP-UNSUPPORTED: delete not enabled for $ref (http 405)" ;;
    disk-full)
      echo "    RETRY-LATER: disk full during delete for $ref (ENOSPC errno 28)" ;;
    internal)
      echo "    WARN: internal server error deleting $ref (http 500)" ;;
    *)
      echo "    WARN: failed delete $ref (unclassified)" ;;
  esac
}

export -f classify_delete_error

# Deletion counters (global)
DELETE_COUNT=0
KEEP_COUNT=0
SKIP_UNSUPPORTED_COUNT=0
FAIL_DELETE_COUNT=0
DISK_FULL_COUNT=0
INTERNAL_ERR_COUNT=0
PROTECTED_COUNT=0
IN_USE_COUNT=0
RANK_DELETE_COUNT=0
AGE_DELETE_COUNT=0
DIGEST_DELETE_COUNT=0          # number of digests fully deleted (all tags pruned)
DIGEST_PROMOTED_COUNT=0        # tags originally DELETE but promoted to KEEP due to shared digest with kept tag
DIGEST_SKIP_EXTRA_COUNT=0      # tags skipped from redundant deletion attempts after manifest removed

# Wrapper to delete a tag: try manifest delete first then tag delete
delete_tag() {
  local repo="$1" tag="$2" ref="${REGISTRY}/${repo}:${tag}"
  local manifest_digest=""
  # Obtain manifest digest (may fail for schema1 or missing)
  if manifest_digest=$(regctl manifest digest "$ref" 2>/dev/null); then
    # Try manifest deletion
    if out=$(regctl manifest rm "${REGISTRY}/${repo}@${manifest_digest}" 2>&1); then
      DELETE_COUNT=$((DELETE_COUNT+1))
      return 0
    else
      # classify error; if unsupported, fall back to tag rm
      if [[ "$out" =~ 405 ]]; then
        SKIP_UNSUPPORTED_COUNT=$((SKIP_UNSUPPORTED_COUNT+1))
        classify_delete_error "$ref" "$out"
        # Fallback to tag rm
        if out2=$(regctl tag rm "$ref" 2>&1); then
          DELETE_COUNT=$((DELETE_COUNT+1))
          return 0
        else
          classify_delete_error "$ref" "$out2"
          case "$out2" in
            *"Err":28*) DISK_FULL_COUNT=$((DISK_FULL_COUNT+1)) ;;
            *405*) SKIP_UNSUPPORTED_COUNT=$((SKIP_UNSUPPORTED_COUNT+1)) ;;
            *500*) INTERNAL_ERR_COUNT=$((INTERNAL_ERR_COUNT+1)) ;;
            *) FAIL_DELETE_COUNT=$((FAIL_DELETE_COUNT+1)) ;;
          esac
          return 1
        fi
      else
        classify_delete_error "$ref" "$out"
        case "$out" in
          *"Err":28*) DISK_FULL_COUNT=$((DISK_FULL_COUNT+1)) ;;
          *405*) SKIP_UNSUPPORTED_COUNT=$((SKIP_UNSUPPORTED_COUNT+1)) ;;
          *500*) INTERNAL_ERR_COUNT=$((INTERNAL_ERR_COUNT+1)) ;;
          *) FAIL_DELETE_COUNT=$((FAIL_DELETE_COUNT+1)) ;;
        esac
        return 1
      fi
    fi
  else
    # Could not resolve digest; attempt tag rm directly
    if out=$(regctl tag rm "$ref" 2>&1); then
      DELETE_COUNT=$((DELETE_COUNT+1))
      return 0
    else
      classify_delete_error "$ref" "$out"
      case "$out" in
        *"Err":28*) DISK_FULL_COUNT=$((DISK_FULL_COUNT+1)) ;;
        *405*) SKIP_UNSUPPORTED_COUNT=$((SKIP_UNSUPPORTED_COUNT+1)) ;;
        *500*) INTERNAL_ERR_COUNT=$((INTERNAL_ERR_COUNT+1)) ;;
        *) FAIL_DELETE_COUNT=$((FAIL_DELETE_COUNT+1)) ;;
      esac
      return 1
    fi
  fi
}

export -f delete_tag

# Build protected tag map
declare -A protect_map
for t in $PROTECT_TAGS; do protect_map["$t"]=1; done

# Build exclude repo map
declare -A exclude_map
for r in $EXCLUDE_REPOS; do exclude_map["$r"]=1; done

# Collect in-use tags from Kubernetes (optional)
declare -A in_use
IN_USE_FILE=""
if [ "$KUBE_CONTEXT_SCAN" = "true" ]; then
  echo "[INFO] Scanning Kubernetes for in-use images..."
  # Collect all images (pods + cronjobs templates)
  imgs="$($KUBECTL get pods -A -o jsonpath='{..image}' 2>/dev/null || true)"
  for img in $imgs; do
    # Normalize image: registry/namespace/repo:tag
    # Extract repo path and tag
    tag="${img##*:}"
    repo_part="${img%:*}"
    repo_part="${repo_part#"$REGISTRY"/}"    # strip registry prefix if present
    # repo_part now namespace/repo or similar
    in_use["$repo_part:$tag"]=1
  done
  # Persist in-use keys for use by parallel workers (arrays aren't exported)
  IN_USE_FILE="$(mktemp)"
  for k in "${!in_use[@]}"; do echo "$k"; done | sort -u > "$IN_USE_FILE"
  echo "[INFO] Found $(wc -l < "$IN_USE_FILE") images in use."
fi

cutoff_ts=0
if [ "$MAX_AGE_DAYS" -gt 0 ]; then
  cutoff_ts=$(date -u -d "-${MAX_AGE_DAYS} days" +%s)
  echo "[INFO] Age cutoff: $MAX_AGE_DAYS days -> epoch $cutoff_ts"
fi

# Function to process a single repository
process_repo() {
  local repo="$1"
  # Load in-use map from file if provided (to avoid repeated greps)
  declare -A in_use_map
  if [ -n "${IN_USE_FILE:-}" ] && [ -f "$IN_USE_FILE" ]; then
    # shellcheck disable=SC2162
    while IFS= read line; do
      [ -n "$line" ] && in_use_map["$line"]=1
    done < "$IN_USE_FILE"
  fi
  if [ -n "${exclude_map[$repo]:-}" ]; then
    echo "[SKIP-REPO] $repo is excluded"
    return 0
  fi

  echo "[REPO] $repo"
  # List tags; if none, skip
  mapfile -t tags < <(regctl tag ls "${REGISTRY}/${repo}" 2>/dev/null || true)
  if [ "${#tags[@]}" -eq 0 ]; then
    echo "  (no tags)"
    return 0
  fi
  echo "  (tags=${#tags[@]})"
  if [ "$PRINT_TAGS" = "true" ]; then
    local show_n="$TAG_PREVIEW_COUNT"
    if [ "$show_n" -le 0 ] || [ "$show_n" -gt "${#tags[@]}" ]; then
      show_n="${#tags[@]}"
    fi
    echo "  tags (first ${show_n}):"
    for t in "${tags[@]:0:show_n}"; do
      echo "    - $t"
    done
    if [ "${#tags[@]}" -gt "$show_n" ]; then
      echo "    ... ($(( ${#tags[@]} - show_n )) more)"
    fi
  fi

  # Collect tag metadata (created date) to sort by time if available
  # Fallback to lexical if missing
  tmpfile="$(mktemp)"
  for tag in "${tags[@]}"; do
    # Try to fetch image config; tolerate failures
    cfg="$(regctl image config "${REGISTRY}/${repo}:${tag}" 2>/dev/null || true)"
    created=""
    if command -v jq >/dev/null 2>&1; then
      created="$(printf '%s' "$cfg" | jq -r '.created // empty' 2>/dev/null || true)"
    fi
    created_ts=""
    if [ -n "$created" ]; then
      created_ts="$(date -u -d "$created" +%s 2>/dev/null || echo "")"
    fi
    printf '%s\t%s\t%s\n' "$tag" "${created_ts:-0}" "${created:-unknown}" >> "$tmpfile"
  done

  # Sort by timestamp desc if timestamps exist; fallback: lexical desc
  # If any timestamp > 0 exists, use numeric sorting
  if awk -F'\t' '{if($2>0){print; exit}}' "$tmpfile" >/dev/null; then
    sorted_tags=$(awk -F'\t' '{print $0}' "$tmpfile" | sort -k2,2nr)
  else
    sorted_tags=$(awk -F'\t' '{print $0}' "$tmpfile" | sort -k1,1r)
  fi

  # Fallback if sorting produced no lines: use lexical order of tag names
  if [ -z "$sorted_tags" ]; then
    sorted_tags=$(printf '%s\n' "${tags[@]}" | awk '{printf "%s\t0\tunknown\n", $0}' | sort -k1,1r)
  fi

  rm -f "$tmpfile"

  # First pass: build records including digest and initial decision WITHOUT
  # incrementing counters (we'll adjust after digest grouping safety).
  # Ensure arrays are initialized (avoid unbound variable with set -u)
  declare -a recs=()
  declare -A digest_to_indices=()
  count=0
  # Read sorted tag metadata lines robustly (process substitution preserves newlines)
  while IFS=$'\t' read -r tag ts created_raw; do
    count=$((count+1))
    action="KEEP"
    reason="newest"
    protected_flag="${protect_map[$tag]:-}"
    in_use_flag="${in_use_map[$repo:$tag]:-}"

    if [ -n "$protected_flag" ]; then
      action="KEEP"; reason="protected"
    elif [ -n "$in_use_flag" ]; then
      action="KEEP"; reason="in-use"
    fi

    if [ "$action" = "KEEP" ] && [ "$MAX_AGE_DAYS" -gt 0 ]; then
      if [ -n "$ts" ] && [ "$ts" -gt 0 ] && [ "$ts" -lt "$cutoff_ts" ]; then
        if [ -z "$protected_flag" ] && [ -z "$in_use_flag" ]; then
          action="DELETE"; reason="old>${MAX_AGE_DAYS}d"
        fi
      fi
    fi

    if [ "$action" = "KEEP" ] && [ "$count" -gt "$KEEP" ]; then
      if [ -z "$protected_flag" ] && [ -z "$in_use_flag" ]; then
        action="DELETE"; reason="rank>${KEEP}"
      fi
    fi

    # Obtain manifest digest for grouping (tolerate failures)
    md="$(regctl manifest digest "${REGISTRY}/${repo}:${tag}" 2>/dev/null || echo "")"
    digest="$md"; [ -z "$digest" ] && digest="nodigest"
    idx=${#recs[@]}
  # Build record using custom delimiter to ensure reliable splitting regardless of embedded spaces
  recs+=("$tag${RECORD_DELIM}$ts${RECORD_DELIM}$created_raw${RECORD_DELIM}$digest${RECORD_DELIM}$action${RECORD_DELIM}$reason")
    digest_to_indices["$digest"]+="$idx "
    # Immediate diagnostic preview (will be reconciled later)
    printf '  PREVIEW %-7s %-35s %s (ts=%s,digest=%s)\n' "$action" "$repo" "$tag" "$ts" "$digest"
  done < <(printf '%s\n' "$sorted_tags")

  echo "  [debug] collected_records=${#recs[@]} digests=${#digest_to_indices[@]}"
  if [ "${#recs[@]}" -eq 0 ]; then
    echo "  [warn] No records collected after metadata parsing; falling back to simple per-tag listing.";
    for tag in "${tags[@]}"; do
      echo "  KEEP    $tag (fallback,no-metadata)"
      KEEP_COUNT=$((KEEP_COUNT+1))
    done
    return 0
  fi
  echo "  [debug] digest_groups=${#digest_to_indices[@]} initial"

  # Determine digests that must be kept (any tag KEEP)
  declare -A digest_keep=()
  if [ "${#digest_to_indices[@]}" -gt 0 ]; then
    for d in "${!digest_to_indices[@]}"; do
      keep_any=0
      for idx in ${digest_to_indices[$d]:-}; do
  val="${recs[$idx]:-}"
  IFS="$RECORD_DELIM" read -r _tag _ts _created _digest _action _reason <<< "$val"
        if [ "$_action" = "KEEP" ]; then
          keep_any=1; break
        fi
      done
      if [ "$keep_any" -eq 1 ]; then
        digest_keep["$d"]=1
      fi
    done
  fi

  # Promote DELETE tags that share a kept digest
  if [ "${#recs[@]}" -gt 0 ]; then
    for idx in "${!recs[@]}"; do
  val="${recs[$idx]:-}"
  IFS="$RECORD_DELIM" read -r tag ts created_raw digest action reason <<< "$val"
      if [ "$action" = "DELETE" ] && [ -n "${digest_keep[$digest]:-}" ]; then
        action="KEEP"; reason="digest-shared"; DIGEST_PROMOTED_COUNT=$((DIGEST_PROMOTED_COUNT+1))
  recs[$idx]="$tag${RECORD_DELIM}$ts${RECORD_DELIM}$created_raw${RECORD_DELIM}$digest${RECORD_DELIM}$action${RECORD_DELIM}$reason"
      fi
    done
  fi
  # Final pass: digest grouping safety & printing
  declare -A digest_all_delete=()
  for d in "${!digest_to_indices[@]}"; do
    all_del=1
    for idx in ${digest_to_indices[$d]}; do
  IFS="$RECORD_DELIM" read -r _tag _ts _cr _dg _act _rs <<< "${recs[$idx]}"
      if [ "$_act" != "DELETE" ]; then all_del=0; break; fi
    done
    digest_all_delete["$d"]="$all_del"
  done
  declare -A digest_deleted=()
  for idx in "${!recs[@]}"; do
  IFS="$RECORD_DELIM" read -r tag ts created_raw digest action reason <<< "${recs[$idx]}"
    # Update counters based on final intention (may still be promoted below)
    case "$action:$reason" in
      KEEP:protected) PROTECTED_COUNT=$((PROTECTED_COUNT+1)) ;;
      KEEP:in-use) IN_USE_COUNT=$((IN_USE_COUNT+1)) ;;
      DELETE:old*) AGE_DELETE_COUNT=$((AGE_DELETE_COUNT+1)) ;;
      DELETE:rank*) RANK_DELETE_COUNT=$((RANK_DELETE_COUNT+1)) ;;
    esac
    if [ "$action" = "DELETE" ]; then
      if [ "${digest_all_delete[$digest]:-0}" = "1" ]; then
        # safe to delete manifest once
        if [ -z "${digest_deleted[$digest]:-}" ]; then
          printf '  %-7s %-35s %s (%s,digest %s)\n' "$action" "$repo" "$tag" "$reason" "$digest"
          if [ "$DRY_RUN" != "true" ]; then delete_tag "$repo" "$tag" || true; fi
          digest_deleted["$digest"]=1; DIGEST_DELETE_COUNT=$((DIGEST_DELETE_COUNT+1))
        else
          printf '  %-7s %-35s %s (%s,digest %s already-deleted)\n' "SKIP" "$repo" "$tag" "$reason" "$digest"
          DIGEST_SKIP_EXTRA_COUNT=$((DIGEST_SKIP_EXTRA_COUNT+1))
        fi
      else
        # Promote to KEEP for safety
        action="KEEP"; reason="digest-partial"; DIGEST_PROMOTED_COUNT=$((DIGEST_PROMOTED_COUNT+1))
        printf '  %-7s %-35s %s (%s,digest %s)\n' "$action" "$repo" "$tag" "$reason" "$digest"
        KEEP_COUNT=$((KEEP_COUNT+1))
        continue
      fi
    fi
    if [ "$action" = "KEEP" ]; then
      printf '  %-7s %-35s %s (%s,digest %s)\n' "$action" "$repo" "$tag" "$reason" "$digest"
      KEEP_COUNT=$((KEEP_COUNT+1))
    fi
  done
  # Fallback: if no KEEP/DELETE lines (other than PREVIEW) were printed, emit summary decisions
  # Count printed action lines by searching shell variable PROMPT_COMMAND capture not feasible; rely on counters
  if [ $KEEP_COUNT -eq 0 ] && [ $DELETE_COUNT -eq 0 ] && [ $DIGEST_DELETE_COUNT -eq 0 ]; then
    echo "  [warn] No final action lines printed; emitting fallback decisions."
    for idx in "${!recs[@]}"; do
  IFS="$RECORD_DELIM" read -r tag ts created_raw digest action reason <<< "${recs[$idx]}"
      printf '  FBACK  %-35s %s (%s,digest %s)\n' "$repo" "$tag" "$reason" "$digest"
    done
  fi
}

export -f process_repo
export REGISTRY KEEP MAX_AGE_DAYS DRY_RUN PROTECT_TAGS PARALLEL cutoff_ts
export KUBE_CONTEXT_SCAN IN_USE_FILE

REPO_LIST=""
REPO_SOURCE=""
# Priority 1: explicit REPOS env (space separated)
if [ -n "${REPOS:-}" ]; then
  REPO_LIST="$(printf "%s" "$REPOS" | tr ' ' '\n' | sed '/^$/d')"
  REPO_SOURCE="env:REPOS"
fi

# Priority 2: REPOS_FILE (one repo per line)
if [ -z "$REPO_LIST" ] && [ -n "${REPOS_FILE:-}" ] && [ -f "$REPOS_FILE" ]; then
  REPO_LIST="$(grep -v '^[[:space:]]*$' "$REPOS_FILE" || true)"
  REPO_SOURCE="file:$REPOS_FILE"
fi

# Priority 3: registry catalog listing
if [ -z "$REPO_LIST" ]; then
  REPO_LIST="$(regctl repo ls "$REGISTRY" 2>/dev/null || true)"
  REPO_SOURCE="catalog:$REGISTRY"
fi

# Priority 4: derive from in-use images (strip tags)
if [ -z "$REPO_LIST" ] && [ -n "${IN_USE_FILE:-}" ] && [ -f "$IN_USE_FILE" ]; then
  REPO_LIST="$(cut -d':' -f1 "$IN_USE_FILE" | sort -u)"
  REPO_SOURCE="in-use-derived"
fi

if [ -z "$REPO_LIST" ]; then
  echo "[ERROR] No repositories determined (tried REPOS, REPOS_FILE, catalog, in-use)." >&2
  exit 1
fi

REPO_COUNT="$(printf "%s\n" "$REPO_LIST" | grep -c . || true)"
echo "[INFO] Processing ${REPO_COUNT} repositories (source=$REPO_SOURCE, parallel=$PARALLEL, keep=$KEEP, age=$MAX_AGE_DAYS, dry_run=$DRY_RUN)"
if [ "$VERBOSE" = "true" ]; then
  echo "[INFO] Repository list:";
  printf '%s\n' "$REPO_LIST" | sed 's/^/  - /'
fi
if [ -n "$REPO_LIST_OUT" ]; then
  printf '%s\n' "$REPO_LIST" > "$REPO_LIST_OUT" || true
fi

# Run in parallel using background jobs (avoid bash -c startup sourcing side-effects)
run_all_repos() {
  local parallel="$PARALLEL"
  local active=0
  local pids=()
  if [ "$parallel" -le 1 ]; then
    # Avoid using a pipeline here (it would run the loop in a subshell and counters won't persist)
    while IFS= read -r repo; do
      [ -z "$repo" ] && continue
      process_repo "$repo"
    done <<< "$REPO_LIST"
    return
  fi
  # Bash 5 has wait -n; if not available, use manual polling
  have_wait_n=0
  if help wait 2>&1 | grep -q -- '-n'; then
    have_wait_n=1
  fi
  while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    process_repo "$repo" &
    pid=$!
    pids+=("$pid")
    active=$((active+1))
    if [ "$active" -ge "$parallel" ]; then
      if [ "$have_wait_n" -eq 1 ]; then
        wait -n
        active=$((active-1))
      else
        # fallback: wait for first PID then remove it
        wait "${pids[0]}" || true
        unset 'pids[0]'
        # compact array (bash 4 portability)
        pids=("${pids[@]}")
        active=$((active-1))
      fi
    fi
  done <<EOF
$(printf '%s\n' "$REPO_LIST")
EOF
  # Wait remaining
  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done
}

run_all_repos

if [ "$DRY_RUN" = "true" ]; then
  echo "[SUMMARY] Dry run complete. Re-run with DRY_RUN=false to apply deletions."
else
  echo "[SUMMARY] Deletions attempted. Consider running registry garbage-collect next."
fi

echo "[COUNTERS] kept=$KEEP_COUNT deleted=$DELETE_COUNT digest_deleted=$DIGEST_DELETE_COUNT digest_promoted=$DIGEST_PROMOTED_COUNT digest_skip_extra=$DIGEST_SKIP_EXTRA_COUNT age_deletes=$AGE_DELETE_COUNT rank_deletes=$RANK_DELETE_COUNT protected=$PROTECTED_COUNT in_use=$IN_USE_COUNT"
echo "[COUNTERS] skip_unsupported=$SKIP_UNSUPPORTED_COUNT internal_errors=$INTERNAL_ERR_COUNT disk_full=$DISK_FULL_COUNT failed=$FAIL_DELETE_COUNT"

# Optional: run registry garbage-collect at end
run_gc() {
  echo "[GC] enable=$GC_ENABLE dry_run=$GC_DRY_RUN namespace=$GC_NAMESPACE selector=$GC_LABEL_SELECTOR"
  if [ "$GC_ENABLE" != "true" ]; then
    echo "[GC] Skipped (GC_ENABLE not true)"; return 0
  fi
  local pod=""
  if [ -n "$GC_POD_NAME" ]; then
    pod="$GC_POD_NAME"
    echo "[GC] Using explicit GC_POD_NAME override: $pod"
  else
    # Allow multiple selectors separated by commas; try each until one yields a pod
    IFS=',' read -r -a selectors <<< "$GC_LABEL_SELECTOR"
    for sel in "${selectors[@]}"; do
      [ -z "$sel" ] && continue
      pod="$($KUBECTL -n "$GC_NAMESPACE" get pods -l "$sel" -o name 2>/dev/null | head -n1 | sed -E 's|.*/||' | tr -d ' \t\r\n' || true)"
      if [ -n "$pod" ]; then
        echo "[GC] Found pod '$pod' with selector '$sel'"
        break
      fi
    done
    if [ -z "$pod" ]; then
      echo "[GC] Selector(s) failed; attempting name-based fallback search for 'registry' substring"
      pod="$($KUBECTL -n "$GC_NAMESPACE" get pods -o name 2>/dev/null | grep -m1 -E '(^|/)registry(-|$)' | head -n1 | sed -E 's|.*/||' | tr -d ' \t\r\n' || true)"
    fi
  fi
  if [ -z "$pod" ]; then
    if [ "$VERBOSE" = "true" ]; then
      echo "[GC] VERBOSE: Dumping pods to aid troubleshooting:"
      $KUBECTL -n "$GC_NAMESPACE" get pods --show-labels 2>&1 | sed 's/^/[GC]   /'
    fi
    echo "[GC] No registry pod found (namespace '$GC_NAMESPACE'). Provide GC_POD_NAME or adjust GC_LABEL_SELECTOR."; return 1
  fi
  local gc_cmd="registry garbage-collect $GC_CONFIG_PATH $GC_EXTRA_ARGS"
  if [ "$GC_DRY_RUN" = "true" ]; then
    gc_cmd="registry garbage-collect --dry-run $GC_CONFIG_PATH $GC_EXTRA_ARGS"
  fi
  echo "[GC] Executing on pod $pod: $gc_cmd"
  if $KUBECTL -n "$GC_NAMESPACE" exec "$pod" -- $gc_cmd 2>&1 | sed 's/^/[GC] /'; then
    echo "[GC] Completed"
  else
    echo "[GC] WARN: garbage-collect encountered errors"
  fi
}

run_gc

# Cleanup temp file
if [ -n "${IN_USE_FILE:-}" ] && [ -f "$IN_USE_FILE" ]; then
  rm -f "$IN_USE_FILE"
fi

# Bug 1.
#   KEEP    06532fef (newest)
# [REPO] someproject/someservice1
#   DELETE  06532fef (old>1d)
#   DELETE  14b85d2d (old>1d)
#   DELETE  17afe855 (old>1d)
#   DELETE  232bf086 (old>1d)
#   DELETE  39171022 (old>1d)
#   DELETE  59fedb08 (old>1d)
#   DELETE  6c98f52f (old>1d)
#   DELETE  890c7b73 (old>1d)
#   DELETE  9979d1ea (old>1d)
#   DELETE  9c5e46a3 (old>1d)
#   DELETE  dc191a7c (old>1d)
#   DELETE  ed287d5a (old>1d)
#   DELETE  ee5d5d67 (old>1d)

# Bug 2.
# [REPO] someproject/someservice2
#   KEEP    14b85d2d (newest)
#   KEEP    6c98f52f (newest)
#   KEEP    9979d1ea (newest)
#   KEEP    232bf086 (newest)
#   KEEP    890c7b73 (newest)
#   KEEP    17afe855 (newest)
#   KEEP    06532fef (newest)
#   KEEP    ee5d5d67 (newest)
#   KEEP    39171022 (newest)
#   DELETE  ed287d5a (old>1d)
#   DELETE  9c5e46a3 (old>1d)
#   KEEP    14b85d2d (newest)
#   KEEP    6c98f52f (newest)
#   KEEP    9979d1ea (newest)
#   KEEP    232bf086 (newest)
#   KEEP    890c7b73 (newest)
#   KEEP    17afe855 (newest)
#   KEEP    06532fef (newest)
#   KEEP    ee5d5d67 (newest)
#   KEEP    39171022 (newest)
#   DELETE  ed287d5a (old>1d)
#   DELETE  9c5e46a3 (old>1d)
#   KEEP    14b85d2d (newest)
#   KEEP    6c98f52f (newest)
#   KEEP    9979d1ea (newest)
#   KEEP    232bf086 (newest)
#   KEEP    890c7b73 (newest)
#   KEEP    17afe855 (newest)
#   KEEP    06532fef (newest)
#   KEEP    ee5d5d67 (newest)
#   KEEP    39171022 (newest)
#   DELETE  ed287d5a (old>1d)
#   DELETE  9c5e46a3 (old>1d)
#   KEEP    14b85d2d (newest)
#   KEEP    6c98f52f (newest)
#   KEEP    9979d1ea (newest)
#   KEEP    232bf086 (newest)
#   KEEP    890c7b73 (newest)
#   KEEP    17afe855 (newest)
#   KEEP    06532fef (newest)
#   KEEP    ee5d5d67 (newest)
#   KEEP    39171022 (newest)
#   DELETE  ed287d5a (old>1d)
#   DELETE  9c5e46a3 (old>1d)
# [SUMMARY] Dry run complete. Re-run with DRY_RUN=false to apply deletions.

# Bug 3.
#     WARN: failed delete dc191a7c
#   DELETE  ed287d5a (old>1d)
# failed to send blob post, ref registry.internal.yourdomain/someproject/postgres:ed287d5a: request failed: unexpected http status code: Internal Server Error [http 500]: {"errors":[{"code":"UNKNOWN","message":"unknown error","detail":{"DriverName":"filesystem","Enclosed":{"Op":"mkdir","Path":"/var/lib/registry/docker/registry/v2/repositories/someproject/postgres/_uploads/45e246c6-e682-4338-b305-05bf6761255b","Err":28}}}]}
#
# Solution:
# Use ./clean-uploads.sh to remove abandoned uploads first.

# Bug 4.
#   DELETE  39171022 (rank>10)
# failed deleting dummy manifest for registry.internal.yourdomain/someproject/someservice3:39171022@sha256:d82b7448b4e345dcf01e9e9055ef1cba45b4753789e4ead2157f6646cf32f8cc: failed to delete manifest registry.internal.yourdomain/someproject/someservice3:39171022@sha256:d82b7448b4e345dcf01e9e9055ef1cba45b4753789e4ead2157f6646cf32f8cc: request failed: unexpected http status code: Method Not Allowed [http 405]: {"errors":[{"code":"UNSUPPORTED","message":"The operation is unsupported."}]}
#
# Solution:
# kubectl -n registry set env deploy/registry REGISTRY_STORAGE_DELETE_ENABLED=true
# kubectl -n registry rollout restart deploy/registry

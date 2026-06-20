#!/usr/bin/env bash
set -euo pipefail

receipt_json="${1:-}"
if [ -z "$receipt_json" ]; then
  echo "Usage: $0 <bundle-audit.json>" >&2
  echo "Example: $0 target/uselesskey-webhook-audit/bundle-audit.json" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to evaluate bundle-audit.json" >&2
  exit 3
fi

if [ ! -f "$receipt_json" ]; then
  echo "bundle-audit.json not found: $receipt_json" >&2
  exit 4
fi

status="$(jq -r '.status // "unknown"' "$receipt_json")"
profile="$(jq -r '.profile // "unknown"' "$receipt_json")"
check_count="$(jq -r '.checks | length' "$receipt_json")"

if [ "$status" = "unknown" ] || [ -z "$status" ]; then
  echo "required field missing: status" >&2
  exit 6
fi

if [ "$status" != "pass" ] && [ "$status" != "fail" ]; then
  echo "unsupported status in bundle-audit.json: ${status}" >&2
  exit 6
fi

if [ -z "$profile" ]; then
  echo "required field missing: profile" >&2
  exit 6
fi

if ! jq -e '.checks | type == "array"' "$receipt_json" >/dev/null 2>&1; then
  echo "required field missing or invalid: checks" >&2
  exit 6
fi

disallowed_failure_classes=(
  missing_manifest
  invalid_manifest
  path_escape
  missing_artifact
  unexpected_artifact
  missing_receipt
  invalid_receipt
  scanner_safe_mismatch
  runtime_material_mismatch
  profile_validation_failed
  unsupported_profile
)

if [ -n "${BUNDLE_AUDIT_DISALLOWED_CLASSES+x}" ]; then
  if [ -z "${BUNDLE_AUDIT_DISALLOWED_CLASSES//[[:space:]]/}" ] || [ "${BUNDLE_AUDIT_DISALLOWED_CLASSES}" = "none" ]; then
    disallowed_failure_classes=()
  else
    IFS=',' read -r -a disallowed_override <<< "${BUNDLE_AUDIT_DISALLOWED_CLASSES}"
    disallowed_failure_classes=("${disallowed_override[@]}")
  fi
fi

KNOWN_FAILURE_CLASSES=(
  missing_manifest
  invalid_manifest
  path_escape
  missing_artifact
  unexpected_artifact
  missing_receipt
  invalid_receipt
  scanner_safe_mismatch
  runtime_material_mismatch
  profile_validation_failed
  unsupported_profile
)

echo "bundle profile: ${profile}"
echo "audit status: ${status}"
echo "total checks: ${check_count}"
echo "checks by failure_class:"
jq -r '
  .checks
  | group_by(.failure_class)
  | sort_by(.[0].failure_class)
  | .[]
  | "  " + .[0].failure_class + ": total=" + (length | tostring) + ", fail=" + (([.[] | select(.status == "fail")] | length) | tostring) + ", pass=" + (([.[] | select(.status == "pass")] | length) | tostring)
' "$receipt_json"

mapfile -t failing_classes < <(
  jq -r '.checks[] | select(.status == "fail") | .failure_class' "$receipt_json"
)

if [ "${#failing_classes[@]}" -eq 0 ]; then
  echo "no fail checks"
  exit 0
fi

is_disallowed=false
for failure_class in "${failing_classes[@]}"; do
  if ! printf '%s\n' "${KNOWN_FAILURE_CLASSES[@]}" | grep -Fqx "$failure_class"; then
    echo "disallowed failure class (unknown to consumer): ${failure_class}" >&2
    is_disallowed=true
    continue
  fi

  if printf '%s\n' "${disallowed_failure_classes[@]}" | grep -Fqx "$failure_class"; then
    echo "disallowed failure class: ${failure_class}" >&2
    is_disallowed=true
  fi
done

if [ "$is_disallowed" = true ]; then
  exit 5
fi

exit 0

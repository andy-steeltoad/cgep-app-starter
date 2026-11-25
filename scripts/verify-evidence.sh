#!/usr/bin/env bash
# scripts/verify-evidence.sh
#
# Verifies the chain of custody for evidence in the Object Lock vault.
#
# Usage:
#   verify-evidence.sh <run_id>                             # PR run (grc-gate.yml)
#   verify-evidence.sh --deployment <sha>/<run>-<attempt>   # deploy (deploy.yml)
#
# Options:
#   --vault <bucket>   Vault bucket (or set EVIDENCE_VAULT).
#   --repo <owner/name>  GitHub repo whose workflows must have signed the
#                        evidence (default: andy-steeltoad/cgep-app-starter,
#                        or EVIDENCE_REPO).
#   --profile <p>      AWS CLI profile.
#
# PR runs (runs/<run_id>/, written by capture-evidence.sh):
#   0. Read the ORIGINAL version of receipt.json (oldest version in the vault)
#   1. Integrity:    bundle.tar.gz at the receipt's version ID matches its sha256,
#                    and every file inside matches manifest.json
#   2. Authenticity: Cosign signature from grc-gate.yml in this repo
#   3. Preservation: every object version is still under Object Lock retention
#
# Deploys (deployments/<sha>/<run>-<attempt>/, written by deploy.yml):
#   0. Read the original version of every object under the prefix
#   1. Integrity:    every file matches SHA256SUMS, and nothing is unlisted
#   2. Authenticity: Cosign signature on SHA256SUMS from deploy.yml on main
#   3. Preservation: as above
#
# Any object with more than one version is reported: evidence keys are
# written once, so extra versions mean something was re-uploaded.
#
# Requires: aws, cosign, jq, sha256sum or shasum. The caller needs
# s3:ListBucketVersions, s3:GetObjectVersion, s3:GetObjectRetention and
# kms:Decrypt on the vault key.

set -euo pipefail

usage() {
  echo "usage: verify-evidence.sh <run_id> | --deployment <sha>/<run>-<attempt>  [--vault <bucket>] [--repo <owner/name>] [--profile <p>]" >&2
  exit 2
}

MODE=""
TARGET=""
VAULT="${EVIDENCE_VAULT:-}"
REPO="${EVIDENCE_REPO:-andy-steeltoad/cgep-app-starter}"
PROFILE_ARGS=()
OIDC_ISSUER="https://token.actions.githubusercontent.com"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deployment) MODE=deploy; TARGET="${2:?}"; shift 2 ;;
    --vault)      VAULT="${2:?}"; shift 2 ;;
    --repo)       REPO="${2:?}"; shift 2 ;;
    --profile)    PROFILE_ARGS=(--profile "${2:?}"); shift 2 ;;
    -h|--help)    usage ;;
    -*)           echo "Unknown arg: $1" >&2; usage ;;
    *)            [[ -z "$TARGET" ]] || usage; MODE=run; TARGET="$1"; shift ;;
  esac
done
[[ -n "$MODE" && -n "$TARGET" ]] || usage
[[ -n "$VAULT" ]] || { echo "Set --vault or EVIDENCE_VAULT" >&2; exit 2; }
for bin in aws cosign jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Need $bin on PATH" >&2; exit 2; }
done

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

# shellcheck disable=SC2016  # $ is a literal regex character here
REPO_RE=$(printf '%s' "$REPO" | sed 's/[.[\*^$()+?{|]/\\&/g')
if [[ "$MODE" == run ]]; then
  PREFIX="runs/$TARGET"
  # grc-gate runs on pull_request (refs/pull/N/merge) or workflow_dispatch (a branch).
  IDENTITY_RE="^https://github\.com/${REPO_RE}/\.github/workflows/grc-gate\.yml@refs/(pull/[0-9]+/merge|heads/.+)$"
else
  PREFIX="deployments/$TARGET"
  IDENTITY_RE="^https://github\.com/${REPO_RE}/\.github/workflows/deploy\.yml@refs/heads/main$"
fi

FAILURES=0
WARNINGS=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILURES=$((FAILURES + 1)); }
warn() { echo "  WARN  $*"; WARNINGS=$((WARNINGS + 1)); }
s3api() { aws ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} s3api "$@"; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

echo "Verifying s3://$VAULT/$PREFIX/"

# ---- 0. Inventory: every version of every object under the prefix ----
s3api list-object-versions --bucket "$VAULT" --prefix "$PREFIX/" --output json > "$WORK/versions.json"
if [[ $(jq '(.Versions // []) | length' "$WORK/versions.json") -eq 0 ]]; then
  echo "FAIL: no objects under s3://$VAULT/$PREFIX/"; exit 1
fi

echo "[0] Inventory"
while IFS=$'\t' read -r key count; do
  if [[ "$count" -gt 1 ]]; then warn "$key has $count versions; verifying the original"; fi
done < <(jq -r '.Versions | group_by(.Key)[] | [.[0].Key, length] | @tsv' "$WORK/versions.json")
if [[ $(jq '(.DeleteMarkers // []) | length' "$WORK/versions.json") -gt 0 ]]; then
  warn "delete markers present: $(jq -r '[.DeleteMarkers[].Key] | unique | join(", ")' "$WORK/versions.json")"
fi

original_version() { # <key> -> oldest VersionId for that key
  jq -r --arg k "$1" '[.Versions[] | select(.Key == $k)] | sort_by(.LastModified) | .[0].VersionId // empty' "$WORK/versions.json"
}

VERIFIED_OBJECTS=""   # "key<TAB>version" lines, for the retention check
fetch() { # <key> <version> <outfile>
  s3api get-object --bucket "$VAULT" --key "$1" --version-id "$2" "$3" > /dev/null
  VERIFIED_OBJECTS+="$1"$'\t'"$2"$'\n'
}

sha_of() { $SHASUM "$1" | awk '{print $1}'; }

verify_signature() { # <file> <sigstore bundle>
  if cosign verify-blob "$1" --bundle "$2" \
       --certificate-identity-regexp "$IDENTITY_RE" \
       --certificate-oidc-issuer "$OIDC_ISSUER" > "$WORK/cosign.log" 2>&1; then
    pass "Cosign signature on $(basename "$1") from $IDENTITY_RE"
  else
    fail "Cosign signature on $(basename "$1"): $(tail -1 "$WORK/cosign.log")"
  fi
}

if [[ "$MODE" == run ]]; then
  # ---------------------------- PR run ----------------------------
  RECEIPT_KEY="$PREFIX/receipt.json"
  RECEIPT_VER=$(original_version "$RECEIPT_KEY")
  [[ -n "$RECEIPT_VER" ]] || { echo "FAIL: $RECEIPT_KEY not found"; exit 1; }
  fetch "$RECEIPT_KEY" "$RECEIPT_VER" "$WORK/receipt.json"
  pass "receipt.json (original version $RECEIPT_VER)"

  r() { jq -r --arg f "$1" '.[$f] // empty' "$WORK/receipt.json"; }
  BUNDLE_KEY=$(r key);           BUNDLE_VER=$(r version_id)
  SIG_KEY=$(r signature_key);    SIG_VER=$(r signature_version_id)
  EXPECTED_SHA=$(r sha256)
  [[ "$BUNDLE_KEY" == "$PREFIX/bundle.tar.gz" ]] || fail "receipt points at unexpected key '$BUNDLE_KEY'"

  echo "[1] Integrity"
  fetch "$BUNDLE_KEY" "$BUNDLE_VER" "$WORK/bundle.tar.gz"
  ACTUAL_SHA=$(sha_of "$WORK/bundle.tar.gz")
  if [[ -n "$EXPECTED_SHA" && "$ACTUAL_SHA" == "$EXPECTED_SHA" ]]; then
    pass "bundle.tar.gz sha256 matches receipt ($ACTUAL_SHA)"
  else
    fail "bundle.tar.gz sha256 $ACTUAL_SHA != receipt ${EXPECTED_SHA:-<missing>}"
  fi

  mkdir -p "$WORK/x"
  BUNDLE_ROOT=""
  if tar xzf "$WORK/bundle.tar.gz" -C "$WORK/x" 2>"$WORK/tar.err"; then
    BUNDLE_ROOT=$(find "$WORK/x" -mindepth 1 -maxdepth 1 -type d | head -1)
  fi
  MANIFEST="$BUNDLE_ROOT/manifest.json"
  if [[ ! -s "$WORK/bundle.tar.gz" ]] || [[ -s "$WORK/tar.err" && -z "$BUNDLE_ROOT" ]]; then
    fail "bundle.tar.gz is not a readable archive: $(tail -1 "$WORK/tar.err")"
  elif [[ -z "$BUNDLE_ROOT" || ! -f "$MANIFEST" ]]; then
    fail "manifest.json missing from bundle"
  else
    BAD=0
    while IFS=$'\t' read -r name sha; do
      if [[ ! -f "$BUNDLE_ROOT/$name" ]]; then fail "manifest lists missing file $name"; BAD=1
      elif [[ $(sha_of "$BUNDLE_ROOT/$name") != "$sha" ]]; then fail "$name does not match manifest"; BAD=1
      fi
    done < <(jq -r '.[] | [.filename, .sha256] | @tsv' "$MANIFEST")
    while IFS= read -r f; do
      rel="${f#"$BUNDLE_ROOT"/}"
      [[ "$rel" == manifest.json ]] && continue
      jq -e --arg n "$rel" 'any(.[]; .filename == $n)' "$MANIFEST" > /dev/null \
        || { fail "$rel is in the bundle but not in manifest.json"; BAD=1; }
    done < <(find "$BUNDLE_ROOT" -type f)
    if [[ $BAD -eq 0 ]]; then pass "all $(jq length "$MANIFEST") files match manifest.json"; fi
  fi

  echo "[2] Authenticity"
  if [[ -z "$SIG_KEY" ]]; then
    fail "receipt has no signature (bundle was captured without --sign)"
  else
    fetch "$SIG_KEY" "$SIG_VER" "$WORK/bundle.tar.gz.sigstore.json"
    verify_signature "$WORK/bundle.tar.gz" "$WORK/bundle.tar.gz.sigstore.json"
  fi

else
  # ---------------------------- Deploy ----------------------------
  echo "[1] Integrity"
  mkdir -p "$WORK/d"
  while IFS= read -r key; do
    fetch "$key" "$(original_version "$key")" "$WORK/d/${key#"$PREFIX"/}"
  done < <(jq -r '[.Versions[].Key] | unique[]' "$WORK/versions.json")

  if [[ ! -f "$WORK/d/SHA256SUMS" ]]; then
    fail "SHA256SUMS not found"
  else
    if (cd "$WORK/d" && $SHASUM -c SHA256SUMS > "$WORK/sums.log" 2>&1); then
      pass "all $(wc -l < "$WORK/d/SHA256SUMS" | tr -d ' ') files match SHA256SUMS"
    else
      fail "SHA256SUMS check: $(grep -v ': OK$' "$WORK/sums.log" | tr '\n' ' ')"
    fi
    for f in "$WORK"/d/*; do
      base=$(basename "$f")
      case "$base" in SHA256SUMS|SHA256SUMS.sigstore.json) continue ;; esac
      awk '{print $2}' "$WORK/d/SHA256SUMS" | grep -qxF "$base" \
        || fail "$base is in the vault but not in SHA256SUMS"
    done
  fi

  echo "[2] Authenticity"
  if [[ -f "$WORK/d/SHA256SUMS.sigstore.json" ]]; then
    verify_signature "$WORK/d/SHA256SUMS" "$WORK/d/SHA256SUMS.sigstore.json"
  else
    fail "SHA256SUMS.sigstore.json not found"
  fi
fi

# ---- 3. Preservation: Object Lock retention on every verified version ----
echo "[3] Preservation"
NOW=$(date -u +%Y-%m-%dT%H:%M:%S)
while IFS=$'\t' read -r key ver; do
  [[ -n "$key" ]] || continue
  if ! RET=$(s3api get-object-retention --bucket "$VAULT" --key "$key" --version-id "$ver" \
               --query 'Retention.[Mode,RetainUntilDate]' --output text 2>"$WORK/ret.err"); then
    fail "${key#"$PREFIX"/}: no retention ($(tail -1 "$WORK/ret.err"))"; continue
  fi
  MODE_=$(echo "$RET" | awk '{print $1}'); UNTIL=$(echo "$RET" | awk '{print $2}')
  if [[ "${UNTIL:0:19}" > "$NOW" ]]; then
    pass "${key#"$PREFIX"/}: $MODE_ until $UNTIL"
  else
    fail "${key#"$PREFIX"/}: retention expired at $UNTIL (vault default retention is set in evidence_vault.tf)"
  fi
done <<< "$VERIFIED_OBJECTS"

echo
if [[ $FAILURES -eq 0 ]]; then
  echo "CHAIN INTACT for $PREFIX ($WARNINGS warning(s))"
else
  echo "CHAIN BROKEN for $PREFIX: $FAILURES failure(s), $WARNINGS warning(s)"
  exit 1
fi

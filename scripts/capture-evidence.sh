#!/usr/bin/env bash
# scripts/capture-evidence.sh
# Usage:
#   capture-evidence.sh --workspace <path> --run-id <id> --vault <bucket>
#                       [--evidence-dir <dir>] [--sign [--verify-identity <id>]]
#                       [--profile <p>]
#
#   --evidence-dir     Copy every file in <dir> (e.g. conftest-results.json,
#                      tfsec.sarif) into the bundle under evidence/.
#   --sign             Sign bundle.tar.gz with Cosign (keyless) and upload the
#                      Sigstore bundle next to it as bundle.tar.gz.sigstore.json.
#                      In GitHub Actions this needs `id-token: write`.
#   --verify-identity  After signing, verify the signature against this
#                      certificate identity (GitHub OIDC issuer), so a bad
#                      signature fails the run before anything is uploaded.
#
# Writes to the vault, under runs/<run-id>/:
#   bundle.tar.gz                 plan, state, commit, version, evidence/, manifest.json
#   bundle.tar.gz.sigstore.json   Cosign bundle (only with --sign)
#   receipt.json                  sha256 + version IDs; read by verify-evidence.sh

set -euo pipefail

PROFILE_ARGS=()
WORKSPACE=""
RUN_ID=""
VAULT=""
EVIDENCE_SRC=""
SIGN=0
VERIFY_IDENTITY=""
OIDC_ISSUER="https://token.actions.githubusercontent.com"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)       WORKSPACE="$2";       shift 2 ;;
    --run-id)          RUN_ID="$2";          shift 2 ;;
    --vault)           VAULT="$2";           shift 2 ;;
    --evidence-dir)    EVIDENCE_SRC="$2";    shift 2 ;;
    --sign)            SIGN=1;               shift ;;
    --verify-identity) VERIFY_IDENTITY="$2"; shift 2 ;;
    --profile)         PROFILE_ARGS=(--profile "$2"); shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$VAULT" ]] && {
  echo "Usage: $0 --workspace <path> --run-id <id> --vault <bucket> [--evidence-dir <dir>] [--sign [--verify-identity <id>]] [--profile <p>]" >&2
  exit 2
}
if [[ -n "$EVIDENCE_SRC" && ! -d "$EVIDENCE_SRC" ]]; then
  echo "--evidence-dir $EVIDENCE_SRC is not a directory" >&2; exit 2
fi
if [[ $SIGN -eq 1 ]] && ! command -v cosign >/dev/null 2>&1; then
  echo "--sign requires cosign on PATH" >&2; exit 2
fi
if [[ -n "$VERIFY_IDENTITY" && $SIGN -eq 0 ]]; then
  echo "--verify-identity requires --sign" >&2; exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_DIR="$WORK/bundle-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

( cd "$WORKSPACE" && [[ -f tfplan ]] && \
    terraform show -json tfplan > "$BUNDLE_DIR/plan.json" 2>/dev/null || true )
( cd "$WORKSPACE" && terraform state pull > "$BUNDLE_DIR/state.json" 2>/dev/null || true )
( cd "$WORKSPACE" && git log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null \
    || echo "no git commit available" > "$BUNDLE_DIR/commit.txt" )
terraform version > "$BUNDLE_DIR/version.txt"

if [[ -n "$EVIDENCE_SRC" ]]; then
  mkdir -p "$BUNDLE_DIR/evidence"
  cp -R "$EVIDENCE_SRC"/. "$BUNDLE_DIR/evidence/"
fi

# manifest.json: path (relative to the bundle), sha256, size, captured_at_utc per file
{
  echo "["
  FIRST=1
  while IFS= read -r f; do
    rel="${f#"$BUNDLE_DIR"/}"
    [[ "$rel" == "manifest.json" ]] && continue
    HASH=$($SHASUM "$f" | awk '{print $1}')
    SIZE=$(wc -c < "$f" | tr -d ' ')
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$rel" "$HASH" "$SIZE" "$CAPTURED_AT"
  done < <(find "$BUNDLE_DIR" -type f | LC_ALL=C sort)
  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

BUNDLE_TGZ="$WORK/bundle.tar.gz"
( cd "$WORK" && tar czf "$BUNDLE_TGZ" "bundle-$RUN_ID" )
BUNDLE_SHA=$($SHASUM "$BUNDLE_TGZ" | awk '{print $1}')

KEY="runs/$RUN_ID/bundle.tar.gz"
SIG_KEY=""
SIG_FILE="$WORK/bundle.tar.gz.sigstore.json"

# Sign (and optionally verify) before uploading anything, so the vault never
# holds a bundle whose signing step failed.
if [[ $SIGN -eq 1 ]]; then
  cosign sign-blob --yes --bundle "$SIG_FILE" "$BUNDLE_TGZ" >&2
  if [[ -n "$VERIFY_IDENTITY" ]]; then
    cosign verify-blob "$BUNDLE_TGZ" \
      --bundle "$SIG_FILE" \
      --certificate-identity "$VERIFY_IDENTITY" \
      --certificate-oidc-issuer "$OIDC_ISSUER" >&2
  fi
  SIG_KEY="$KEY.sigstore.json"
fi

put_object() { # <key> <file> [content-type] -> prints the new VersionId
  aws ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} s3api put-object \
    --bucket "$VAULT" --key "$1" --body "$2" \
    ${3:+--content-type "$3"} \
    --query VersionId --output text
}

VERSION_ID=$(put_object "$KEY" "$BUNDLE_TGZ")

SIG_VERSION_ID=""
if [[ -n "$SIG_KEY" ]]; then
  SIG_VERSION_ID=$(put_object "$SIG_KEY" "$SIG_FILE" application/json)
fi

# receipt.json is stored next to the bundle and read by verify-evidence.sh:
# it pins the exact object versions and the expected bundle hash.
RECEIPT_KEY="runs/$RUN_ID/receipt.json"
RECEIPT_FILE="$WORK/receipt.json"
printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","sha256":"%s","signature_key":"%s","signature_version_id":"%s","signer_identity":"%s","captured_at_utc":"%s"}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$BUNDLE_SHA" "$SIG_KEY" "$SIG_VERSION_ID" "$VERIFY_IDENTITY" "$CAPTURED_AT" \
  > "$RECEIPT_FILE"
put_object "$RECEIPT_KEY" "$RECEIPT_FILE" application/json > /dev/null

cat "$RECEIPT_FILE"

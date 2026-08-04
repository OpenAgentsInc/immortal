#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <gcp-project> <secret-name> <immortal-binary> <unsigned-events.json>" >&2
  exit 2
fi

gcp_project="$1"
secret_name="$2"
immortal_binary="$3"
unsigned_events="$4"

if [[ ! -x "$immortal_binary" ]]; then
  echo "immortal binary is not executable: $immortal_binary" >&2
  exit 1
fi
if [[ ! -f "$unsigned_events" ]]; then
  echo "unsigned event input does not exist: $unsigned_events" >&2
  exit 1
fi

relay_secret=""
cleanup() {
  unset relay_secret
}
trap cleanup EXIT

relay_secret="$(
  gcloud secrets versions access latest \
    --project "$gcp_project" \
    --secret "$secret_name"
)"
if [[ ! "$relay_secret" =~ ^[0-9a-f]{64}$ ]]; then
  echo "protected relay secret has an invalid shape" >&2
  exit 1
fi

IMMORTAL_RELAY_SECRET_KEY="$relay_secret" \
  "$immortal_binary" sign-openagents-project-events < "$unsigned_events"

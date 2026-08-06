#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${CERTWEAVER_COMPOSE_FILE:-$ROOT_DIR/docker/compose.pki.yml}"

for prefix in STEP_CA OPENBAO EJBCA CADDY TRAEFIK; do
  repository_var="${prefix}_IMAGE_REPOSITORY"
  digest_var="${prefix}_IMAGE_DIGEST"
  repository="${!repository_var:-}"
  digest="${!digest_var:-}"

  if [[ -z "$repository" || -z "$digest" ]]; then
    continue
  fi
  last_component="${repository##*/}"
  if [[ "$repository" == *@* || "$last_component" == *:* ]]; then
    printf 'error: %s must be a repository without a tag or digest\n' "$repository_var" >&2
    exit 2
  fi
  if [[ ! "$digest" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
    printf 'error: %s must be sha256:<64 hex characters>\n' "$digest_var" >&2
    exit 2
  fi
done

exec docker compose -f "$COMPOSE_FILE" "$@"

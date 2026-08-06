#!/usr/bin/env bash
set -euo pipefail

validate_args=()
if [[ "${CERTWEAVER_STRICT:-0}" == "1" ]]; then
  validate_args+=(--strict)
fi

for config in config/certweaver.example.yml examples/configs/*.yml; do
  printf 'Validating %s\n' "$config"
  certweaver validate "${validate_args[@]}" -c "$config"
done

#!/usr/bin/env bash
set -euo pipefail

for config in config/certweaver.example.yml examples/configs/*.yml; do
  printf 'Validating %s\n' "$config"
  certweaver validate -c "$config"
done

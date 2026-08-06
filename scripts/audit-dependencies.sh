#!/usr/bin/env bash
set -euo pipefail

requirements_file="$(mktemp)"
trap 'rm -f "$requirements_file"' EXIT

# pip-audit cannot resolve the local project because it is not published on PyPI.
# Audit every installed third-party dependency from an exact pip-freeze snapshot.
python -m pip freeze \
  | awk 'tolower($0) !~ /^-e / && tolower($0) !~ /^certweaver([[:space:]]|[=<>!~@]|$)/' \
  > "$requirements_file"

test -s "$requirements_file"
pip-audit --strict --requirement "$requirements_file"

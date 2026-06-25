#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ansible-galaxy collection install -r collections/requirements.yml
printf 'Development environment ready. Activate with: source .venv/bin/activate
'

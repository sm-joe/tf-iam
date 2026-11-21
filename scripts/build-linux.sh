#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONHASHSEED=0
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
python -m PyInstaller --noconfirm --clean --onefile --name tfiam --collect-data tfiam --collect-all hcl2 --collect-data jsonschema_specifications --collect-all boto3 --collect-all botocore scripts/entrypoint.py
(cd dist && sha256sum tfiam > SHA256SUMS)

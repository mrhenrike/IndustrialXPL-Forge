#!/usr/bin/env bash
# IXF local publish — reads PYPI_API_TOKEN from .env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env"
DIST_DIR="${1:-dist}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: .env not found. Copy .env.example to .env and set PYPI_API_TOKEN." >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if [[ -z "${PYPI_API_TOKEN:-}" || "$PYPI_API_TOKEN" == *REPLACE* ]]; then
    echo "ERROR: PYPI_API_TOKEN not set or still placeholder in .env." >&2
    exit 1
fi

if [[ ! -d "$DIST_DIR" ]] || [[ -z "$(ls "$DIST_DIR" 2>/dev/null)" ]]; then
    echo "Building distribution..."
    python -m build
fi

echo "Uploading to PyPI..."
TWINE_USERNAME=__token__ TWINE_PASSWORD="$PYPI_API_TOKEN" \
    twine upload "$DIST_DIR"/* --skip-existing

echo "Done."

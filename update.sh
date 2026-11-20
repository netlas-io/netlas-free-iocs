#!/bin/bash
set -e

SSLBL_URL=$(yq -r '.sslbl_url' config.yaml)
if [[ -z "$SSLBL_URL" || "$SSLBL_URL" == null ]]; then
    echo "Error: sslbl_url not found in config.yaml" >&2
    exit 2
fi

DATABASE_BASE_URL=$(yq -r '.database_base_url' config.yaml)
DATABASE_FILE=$(yq -r '.database_file' config.yaml)
if [[ -z "$DATABASE_FILE" || "$DATABASE_FILE" == null || -z "$DATABASE_BASE_URL" || "$DATABASE_BASE_URL" == null ]]; then
    echo "Error: database_file or database_base_url not found in config.yaml" >&2
    exit 5
fi

WORK_DIR=$(mktemp -d "${DATABASE_FILE}.download.XXXXXX")
trap 'rm -r -- "$WORK_DIR"' EXIT
DATABASE_DOWNLOAD="$WORK_DIR/database.csv"
SSLBL_FILE="$WORK_DIR/sslbl.csv"
NETLAS_OUTPUT_FILE="$WORK_DIR/latest_search.csv"
SSLBL_EXTENDED_FILE="sslbl_extended.json"

echo "Downloading the current feed and SSL blacklist..."
wget --no-cache --quiet -O "$DATABASE_DOWNLOAD" "$DATABASE_BASE_URL$DATABASE_FILE" || {
    echo "Error: Failed to download the current database ($DATABASE_FILE)" >&2
    exit 5
}

CHECKSUM_FILE="${DATABASE_CHECKSUM_FILE:-$WORK_DIR/database.md5}"
if [[ -z "${DATABASE_CHECKSUM_FILE:-}" ]]; then
    wget --no-cache --quiet -O "$CHECKSUM_FILE" "$DATABASE_BASE_URL$DATABASE_FILE.md5" || {
        echo "Error: Failed to download the current database checksum" >&2
        exit 5
    }
fi

python3 - "$DATABASE_DOWNLOAD" "$CHECKSUM_FILE" <<'PYTHON'
from hashlib import file_digest
from pathlib import Path
import sys

database, checksum = map(Path, sys.argv[1:])
parts = checksum.read_text(encoding="ascii").split()
with database.open("rb") as source:
    actual = file_digest(source, "md5").hexdigest()
if not parts or actual != parts[0].lower():
    sys.exit("Error: Downloaded database does not match its published checksum.")
PYTHON
mv -- "$DATABASE_DOWNLOAD" "$DATABASE_FILE"

wget --quiet -O "$SSLBL_FILE" "$SSLBL_URL" || {
    echo "Error: Failed to download the SSL blacklist from $SSLBL_URL" >&2
    exit 6
}

echo "Running the update scripts..."
if [[ -z "$NETLAS_API_KEY" ]]; then
    python3 sslbl_netlas_search.py -i "$SSLBL_FILE" -o "$NETLAS_OUTPUT_FILE"
else
    python3 sslbl_netlas_search.py -i "$SSLBL_FILE" -o "$NETLAS_OUTPUT_FILE" -a "$NETLAS_API_KEY"
fi

python3 sslbl_netlas_list_update.py "$NETLAS_OUTPUT_FILE"

echo "Updating STATS.md"
NUMBER_OF_THREATS=$(yq -r '.number_of_threats' config.yaml 2>/dev/null || echo 10)
MIN_PORT_COUNT=$(yq -r '.min_port_count' config.yaml 2>/dev/null || echo 50)

python3 sslbl_extended.py -i "$SSLBL_FILE" -o "$SSLBL_EXTENDED_FILE" -p 0
python3 stats.py "$SSLBL_EXTENDED_FILE" "$DATABASE_FILE" -n "$NUMBER_OF_THREATS" --min-port-count "$MIN_PORT_COUNT"

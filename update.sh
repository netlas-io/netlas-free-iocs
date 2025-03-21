#!/bin/bash

SSLBL_URL=$(yq -r '.sslbl_url' config.yaml)
if [ -z "$SSLBL_URL" ]; then
    echo "Error: sslbl_url not found in config.yaml"
    exit 2
fi

DATABASE_BASE_URL=$(yq -r '.database_base_url' config.yaml)
DATABASE_FILE=$(yq -r '.database_file' config.yaml)

echo "SSLBL_URL: $SSLBL_URL"
echo "DATABASE_BASE_URL: $DATABASE_BASE_URL"
echo "DATABASE_FILE: $DATABASE_FILE"

echo "Downloading the latest files from Netlas and Abuse.ch..."

if [ -n "$DATABASE_FILE" ]; then
    wget --quiet -O "$DATABASE_FILE" "$DATABASE_BASE_URL""$DATABASE_FILE" || true
else
    echo "Error: database_file not found in config.yaml"
    exit 5
fi

# Exit immediately if a command fails
set -e

# Define variables for script and output file names
SCRIPT1="sslbl_netlas_search.py"
SCRIPT2="sslbl_netlas_list_update.py"
SCRIPT3="sslbl_extended.py"
NETLAS_OUTPUT_FILE="latest_search.csv"
SSLBL_FILE="sslbl.csv"
SSLBL_EXTENDED_FILE="sslbl_extended.json"

wget --quiet -O "$SSLBL_FILE" "$SSLBL_URL"
if [ $? -ne 0 ]; then
    echo "Error: Failed to download $SSLBL_FILE from $SSLBL_URL"
    exit 6
fi

echo "Running the update scripts..."

# Run the search script to check the latest Abuse.ch data and search in the latest Netlas Internet Scan Data
if [[ -z "$NETLAS_API_KEY" ]]; then
    python3 "$SCRIPT1" -i "$SSLBL_FILE" -o "$NETLAS_OUTPUT_FILE"
else
    python3 "$SCRIPT1" -i "$SSLBL_FILE" -o "$NETLAS_OUTPUT_FILE" -a "$NETLAS_API_KEY"
fi

# Check if the first script exited successfully
if [[ $? -ne 0 ]]; then
    echo "Error: $SCRIPT1 failed. Exiting."
    exit 7
fi

# Check if the output file exists after the first script completes successfully
if [[ -f "$NETLAS_OUTPUT_FILE" ]]; then
    
    # Run the second script to update the database
    python3 "$SCRIPT2" "$NETLAS_OUTPUT_FILE"

    # Check if the second script exited successfully
    if [[ $? -ne 0 ]]; then
        echo "Error: $SCRIPT2 failed. Exiting."
        exit 8
    fi    
else
    echo "Output file $NETLAS_OUTPUT_FILE not found. Second script will not run."
    exit 9
fi

# Run the third script to generate extended sslbl data
echo "Updating STATS.md"

NUMBER_OF_THREATS=$(yq -r '.number_of_threats' config.yaml 2>/dev/null || echo 10)
MIN_PORT_COUNT=$(yq -r '.min_port_count' config.yaml 2>/dev/null || echo 50)

python3 "$SCRIPT3" -i "$SSLBL_FILE" -o "$SSLBL_EXTENDED_FILE" -p 0
python3 stats.py "$SSLBL_EXTENDED_FILE" "$DATABASE_FILE" -n "$NUMBER_OF_THREATS" --min-port-count "$MIN_PORT_COUNT"

echo "Removing temporary files..."
rm "$NETLAS_OUTPUT_FILE"
rm "$SSLBL_FILE"
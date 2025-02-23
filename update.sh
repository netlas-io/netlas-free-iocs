#!/bin/bash

# Exit immediately if a command fails
set -e

# Define variables for script and output file names
SCRIPT1="sslbl_netlas_search.py"
SCRIPT2="update_malicious_hosts_list.py"
OUTPUT_FILE="latest_search.csv"

# Run the search script to check the latest Abuse.ch data and search in the latest Netlas Internet Scan Data
if [[ -z "$NETLAS_API_KEY" ]]; then
    python3 "$SCRIPT1" -o "$OUTPUT_FILE"
else
    python3 "$SCRIPT1" -o "$OUTPUT_FILE" -a "$NETLAS_API_KEY" -s
fi

# Check if the first script exited successfully
if [[ $? -ne 0 ]]; then
    echo "Error: $SCRIPT1 failed. Exiting."
    exit 1
fi

# Check if the output file exists after the first script completes successfully
if [[ -f "$OUTPUT_FILE" ]]; then
    
    # Run the second script to update the database
    python3 "$SCRIPT2" "$OUTPUT_FILE"

    # Check if the second script exited successfully
    if [[ $? -ne 0 ]]; then
        echo "Error: $SCRIPT2 failed. Exiting."
        exit 2
    fi

    # Delete the output file after the second script completes successfully
    rm "$OUTPUT_FILE"
else
    echo "Output file $OUTPUT_FILE not found. Second script will not run."
    exit 2
fi

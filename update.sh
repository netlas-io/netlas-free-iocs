#!/bin/bash

# Define variables for script and output file names
SCRIPT1="sslbl_netlas_search.py"
SCRIPT2="update_malicious_hosts_list.py"
OUTPUT_FILE="latest_search.csv"

# Run the search script to check the latest Abuse.ch data and search in the latest Netlas Internet Scan Data
# if [[ -z "$NETLAS_API_KEY" ]]; then
#     python3 "$SCRIPT1" -o "$OUTPUT_FILE"
# else
#     python3 "$SCRIPT1" -o "$OUTPUT_FILE" -a "$NETLAS_API_KEY" -q
# fi

# # Check if the output file exists after the first script completes
# if [[ -f "$OUTPUT_FILE" ]]; then
#     # Updating database script
#     python3 "$SCRIPT2" "$OUTPUT_FILE"
#     # Delete the output file after the second script completes
#     rm "$OUTPUT_FILE"
# else
#     echo "Output file $OUTPUT_FILE not found. Second script will not run."
# fi

echo "Temp file" > temp.txt
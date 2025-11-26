"""
This script downloads the SSL Certificate Blacklist CSV file from Abuse.ch, processes it,
and queries the Netlas API to search for the most relevant internet scan data, identifying
hosts that are using blacklisted SSL certificates.

Key functionalities:
1. Downloads the SSLBL CSV file from Abuse.ch or uses a local file if provided.
2. Processes the CSV to extract SHA-1 fingerprints of blacklisted SSL certificates.
3. Queries the Netlas API to find URIs (not just IPs) associated with these blacklisted certificates.
4. Outputs the results, including URIs and associated ports, to a CSV file.
5. Supports command-line options:
    - -i/--input-file: provide a local SSL Blacklist CSV file.
    - -o/--output-file: specify the output CSV file name.
    - -a/--apikey: provide a Netlas API key.
    - -s/--silent: suppress the output.

Important:
- The script makes thousands of requests to the Netlas API. A **paid Netlas account** is required
  to ensure sufficient API usage limits.
"""

import json
import requests
import time
import csv
import yaml
import argparse
import re
import netlas
from itertools import islice
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn, TimeRemainingColumn


CONFIG_FILE = "config.yaml"
dbf = "netlas_sslbl_malicious_hosts.csv"                            # Database file name
sslbl_url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"     # URL to the SSL Certificate Blacklist CSV
max_retries = 3                                                     # Number of retries in case of errors
initial_delay = 1                                                   # Initial delay in seconds between retries
max_delay = 30                                                      # Maximum delay in seconds
csv_chunk_size = 50                                                 # Number of SHA fingerprints per Netlas request MAX=90
sslbl_cert_url = "https://sslbl.abuse.ch/ssl-certificates/sha1/"    # Base URL to the SSL Blacklist certificate page
netlas_host_url = "https://app.netlas.io/host/"                     # Base URL to the Netlas host page
log = False                                                         # Log changes to the log file
log_file_name = None                                                # Log file name
output_file_path = f"sslbl_netlas_output_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"

# Parse command-line arguments
parser = argparse.ArgumentParser(description='''
                    Search for hosts with blacklisted certificates in the latest Netlas Internet Scan Data collection.
                    Indicators of Compromise (IoCs) provided by the Abuse.ch SSL Certificate Blacklist.
                    ''')
parser.add_argument("-i", "--input-file", type=str, default=None, help=f"provide file name of the local SSL Blacklist CSV (do not fetch from the internet)")
parser.add_argument("-o", "--output-file", type=str, default=output_file_path, 
                    help=f"specify the output file name (default: {output_file_path})")
parser.add_argument("-a", "--apikey", type=str, help="netlas API Key for accessing the service (optional)")
parser.add_argument("-s", "--silent", action="store_true", help="run the script without any output")
args = parser.parse_args()

console = Console()
console.quiet = args.silent

def print_l(msg: str):
    console.print(msg)
    if log:
        log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\t{msg}\n")


# Loading configuration
try:
    with open(CONFIG_FILE, "r") as file:
        config = yaml.safe_load(file)
        dbf = config.get("database_file", dbf)
        sslbl_url = config.get("sslbl_url", sslbl_url)
        max_retries = config.get("max_retries", max_retries)  
        initial_delay = config.get("initial_delay", initial_delay)
        max_delay = config.get("max_delay", max_delay)    
        csv_chunk_size = config.get("csv_chunk_size", csv_chunk_size)
        sslbl_cert_url = config.get("sslbl_cert_url", sslbl_cert_url)
        netlas_host_url = config.get("netlas_host_url", netlas_host_url)
        log = config.get("log_changes", log)
        log_file_name = config.get("log_file", log_file_name)
except yaml.YAMLError as e:
    console.print(f"Error parsing YAML file: {e}. Using default values.")
except Exception as e:
    console.print(f"Error reading config file: {e}. Using default values.")

# Setting up output file
if args.output_file:
    output_file_path = args.output_file
try:
    output_file = open(output_file_path, mode='w', newline='', encoding='utf-8')
except Exception as e:
    console.print(f"Error opening output file: {e}")
    exit(1)

try:
    log_file = open(config.get("log_file"), mode='a', encoding='utf-8')
except Exception as e:
    log = False
    console.print(f"Error opening log file: {e}. Logging disabled.")

# Ensure the API key is defined and Initialize Netlas connection
api_key = args.apikey
if not api_key:
    api_key = netlas.helpers.get_api_key()
    if not api_key:
        console.print("Error: Netlas API Key undefined!")
        exit(2)
netlas_connection = netlas.Netlas(api_key)

# Read the SSL Certificate Blacklist CSV file
if args.input_file:
    with open(args.input_file, "r") as file:
        blacklist_csv = file.read()
else:
    response = requests.get(sslbl_url)
    response.raise_for_status()  # Raise an error for HTTP issues
    blacklist_csv = response.text
sslbl_reader = csv.reader(blacklist_csv.splitlines())


processed_rows = 0
queries_to_download = {}
total_targets = 0
processed_targets = 0
used_hashes = [] # List to store used hashes and avoid redundant queries

# Iterate through each row and count how many results are there for each query
with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TaskProgressColumn(),
    TimeRemainingColumn(),
    console=console,
) as progress:
    task = progress.add_task("Searching for blacklisted certificates", total=len(blacklist_csv.splitlines()))
    while True:

        # Using chunk of N lines to make less queries
        chunk_raws = list(islice(sslbl_reader, csv_chunk_size))  # Read N lines at a time
        if not chunk_raws:  # Break if no more lines
            break
        
        # Process each row in the current chunk
        chunk = []
        for row in chunk_raws:
            if row[0][0] != '#' and len(row)>=3 and row[1] not in used_hashes:
                chunk.append(row)
            else:
                # Regular expression to match the date and time pattern
                match = re.search(r"Last updated: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", row[0])
                if match:
                    print_l(f"Using Abuse.ch SSL Certificate Blacklist CSV dated {match.group(1)}")
        
        if len(chunk)==0:
            continue

        query = "certificate.fingerprint_sha1:("
        for row in chunk:
            query = query + row[1] + " OR "
            used_hashes.append(row[1])
        query = query[:-4] + ")"

        # Query the Netlas API with retries to get count for current chunk
        for attempt in range(1, max_retries + 1):
            try:
                cnt_of_res = netlas_connection.count(query=query, datatype="response")
                break
            except Exception:
                if attempt == max_retries:
                    progress.stop()
                    print_l(f"\nAll {max_retries} retries failed. Exiting.")
                    exit(3)
                time.sleep(min(initial_delay * (2 ** (attempt - 1)), max_delay))
        
        if cnt_of_res["count"] > 0:
            queries_to_download[query] = chunk # Using queries, that have results as keys, and chunks of data as values
            total_targets += cnt_of_res["count"]
        
        progress.update(task, advance=len(chunk_raws))


# Check if there are any targets to download
if total_targets > 0:
    print_l(f"Found {format(total_targets, ',')} targets to download.")
else:
    print_l(f"Processed {len(blacklist_csv.splitlines())} lines. No targets to download found.")
    exit(4)



fieldnames = ['timestamp', 'host', 'port', 'protocol', 'path', 'ip', 'threat', 'netlas:link', 'x509:sha1', 'x509:timestamp', 'x509:link']
targets = []

# Iterate through each row and count how many results are there for each query
with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TaskProgressColumn(),
    TimeRemainingColumn(),
    console=console,
) as progress:
    task = progress.add_task("Downloading malicious targets from Netlas", total=total_targets)
    for key, value in queries_to_download.items():                  # Iterate through queries
        for attempt in range(1, max_retries + 1):                   # And  make some retries for each query
            try:
                for resp in netlas_connection.download_all(key):    # Iterate through responses returned for current query
                    response = json.loads(resp.decode("utf-8"))     # Decode response from binary
                    target = []                                     # Each returned response is a target                    

                    if len(response["data"]) == 0:
                        raise Exception("Netlas download for query " + key + " returned empty data.")
                    
                    # Building a target from URI, threat name, sha1 and timestamp
                    target.append(response.get("data", {}).get("@timestamp"))
                    host = response.get("data", {}).get("host") 
                    target.append(host)
                    target.append(response.get("data", {}).get("port"))
                    target.append(response.get("data", {}).get("protocol"))
                    target.append(response.get("data", {}).get("path"))
                    target.append(response.get("data", {}).get("ip"))
                    sha1 = response.get("data", {}).get("certificate", {}).get("fingerprint_sha1")
                    for row in value:
                        if row[1] == sha1: # Search for threat name by SHA1 in SSL Certificate Blacklist CSV part associated with this query
                            target.append(row[2]) # Adding a threat neame
                            target.append(f"{netlas_host_url}{host}/")
                            target.append(sha1) # Adding SHA1
                            target.append(row[0]) # Adding a cert timestamp from SSLBL
                            target.append(f"{sslbl_cert_url}{sha1}/") # Adding a cert timestamp from SSLBL
                    targets.append(target)
                    processed_targets += 1
                    progress.update(task, advance=1)
                break
            except Exception as ex:
                if attempt == max_retries:
                    progress.stop()
                    print_l(f"\nAll {max_retries} retries failed.")
                    print_l(str(ex))
                    exit(5)
                time.sleep(min(initial_delay * (2 ** (attempt - 1)), max_delay))

writer = csv.writer(output_file)
console.print(f"Writing output to '{output_file_path}'.")
writer.writerow(fieldnames)
for target in targets:
    writer.writerow(target)
output_file.flush() 
output_file.close()

# Open the file and read all lines
with open(output_file_path, 'r') as output_file:
    lines = output_file.readlines()
    print_l(f"A total of {format(len(lines)-1, ',')} targets have been downloaded")
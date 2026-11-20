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
from pathlib import Path
from tempfile import NamedTemporaryFile
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
blacklist_lines = blacklist_csv.splitlines()
sslbl_reader = csv.reader(blacklist_lines)


queries_to_download = []
total_targets = 0
processed_targets = 0
used_hashes = set()

# Iterate through each row and count how many results are there for each query
with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TaskProgressColumn(),
    TimeRemainingColumn(),
    console=console,
) as progress:
    task = progress.add_task("Searching for blacklisted certificates", total=len(blacklist_lines))
    while True:

        # Using chunk of N lines to make less queries
        chunk_raws = list(islice(sslbl_reader, csv_chunk_size))  # Read N lines at a time
        if not chunk_raws:  # Break if no more lines
            break
        
        # Process each row in the current chunk
        certificates = {}
        for row in chunk_raws:
            if not row or not row[0]:
                continue
            if row[0].startswith('#'):
                match = re.search(r"Last updated: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", row[0])
                if match:
                    print_l(f"Using Abuse.ch SSL Certificate Blacklist CSV dated {match.group(1)}")
            elif len(row) >= 3 and row[1] not in used_hashes:
                timestamp, sha1, threat = row[:3]
                certificates[sha1] = (timestamp, threat)
                used_hashes.add(sha1)

        progress.update(task, advance=len(chunk_raws))
        if not certificates:
            continue

        query = f"certificate.fingerprint_sha1:({' OR '.join(certificates)})"

        # Query the Netlas API with retries to get count for current chunk
        for attempt in range(1, max_retries + 1):
            try:
                count = netlas_connection.count(query=query, datatype="response")["count"]
                break
            except Exception:
                if attempt == max_retries:
                    progress.stop()
                    print_l(f"\nAll {max_retries} retries failed. Exiting.")
                    exit(3)
                time.sleep(min(initial_delay * (2 ** (attempt - 1)), max_delay))
        
        if count > 0:
            queries_to_download.append((query, count, certificates))
            total_targets += count


# Check if there are any targets to download
if total_targets > 0:
    print_l(f"Found {format(total_targets, ',')} targets to download.")
else:
    print_l(f"Processed {len(blacklist_lines)} lines. No targets to download found.")
    exit(4)



fieldnames = ['timestamp', 'host', 'port', 'protocol', 'path', 'ip', 'threat', 'netlas:link', 'x509:sha1', 'x509:timestamp', 'x509:link']
download_fields = "@timestamp,host,port,protocol,path,ip,certificate.fingerprint_sha1"


def download_batch(query, count, certificates):
    """Return CSV rows only after the complete batch downloads successfully."""
    targets = []
    for raw_response in netlas_connection.download(query, fields=download_fields, size=count):
        data = json.loads(raw_response)["data"]
        if not data:
            raise ValueError(f"Netlas download for query {query} returned empty data.")

        sha1 = data.get("certificate", {}).get("fingerprint_sha1")
        if sha1 not in certificates:
            raise ValueError(f"Netlas returned an unexpected certificate fingerprint: {sha1!r}")

        host = data.get("host")
        timestamp, threat = certificates[sha1]
        targets.append([
            data.get("@timestamp"), host, data.get("port"), data.get("protocol"),
            data.get("path"), data.get("ip"), threat, f"{netlas_host_url}{host}/",
            sha1, timestamp, f"{sslbl_cert_url}{sha1}/",
        ])
    return targets


output_path = Path(output_file_path)
temporary_path = None
try:
    with NamedTemporaryFile(
        mode="w", newline="", encoding="utf-8", dir=output_path.parent, delete=False
    ) as output_file:
        temporary_path = Path(output_file.name)
        writer = csv.writer(output_file)
        writer.writerow(fieldnames)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Downloading malicious targets from Netlas", total=total_targets)
            for query, count, certificates in queries_to_download:
                for attempt in range(1, max_retries + 1):
                    try:
                        targets = download_batch(query, count, certificates)
                        break
                    except Exception as error:
                        if attempt == max_retries:
                            progress.stop()
                            print_l(f"\nAll {max_retries} retries failed: {error}")
                            exit(5)
                        time.sleep(min(initial_delay * (2 ** (attempt - 1)), max_delay))

                writer.writerows(targets)
                processed_targets += len(targets)
                progress.update(task, advance=len(targets))

    temporary_path.replace(output_path)
    console.print(f"Wrote output to '{output_file_path}'.")
except OSError as error:
    console.print(f"Error writing output file: {error}")
    exit(1)
finally:
    if temporary_path is not None:
        temporary_path.unlink(missing_ok=True)

print_l(f"A total of {processed_targets:,} targets have been downloaded")

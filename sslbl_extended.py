"""
This script parses the SSL Blacklist from abuse.ch and extends it with additional information
from the SSL certificate pages. The script can either fetch the blacklist from the internet or
use a local file. The extended information is saved in a JSON file.

Usage:
    python parse_sslbl.py [-i INPUT_FILE] [-o OUTPUT] [-p PAUSE] [-s]

Arguments:
    -i, --input-file: Provide file name of the local SSL Blacklist CSV (do not fetch from the internet).
    -o, --output: Specify the output file name (default: sslbl_extended.json).
    -p, --pause: Specify the pause between requests (default: 1).
    -s, --silent: Run the script without progress bars.
"""
import requests
import csv
import json
import time
import argparse
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn, TimeRemainingColumn
from bs4 import BeautifulSoup


# Makes an HTTP GET request to the specified URL with retries and exponential backoff.
def make_request(url, console, max_retries, init_delay, max_delay) -> requests.Response:
    delay = init_delay
    for attempt in range(max_retries):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                console.print(f"Request failed ({e}), retrying in {delay} seconds...")
                time.sleep(delay)
                delay = min(delay * 2, max_delay)
            else:
                console.print(f"Request failed after {max_retries} attempts: {e}")
                raise


# Parses the SSL certificate page to extract certificate details and malware samples.
def parse_ssl_certificate_page(text: str) -> dict:
    soup = BeautifulSoup(text, 'html.parser')

    # Extract all tables within the main tag
    main_content = soup.find('main', class_='container')
    tables = main_content.find_all('table') if main_content else []

    # Extracting the database entry table (first table)
    data = {}
    if len(tables) > 0:
        db_entry = tables[0]
        rows = db_entry.find_all('tr')
        for row in rows:
            th = row.find('th')
            td = row.find('td')
            if th and td:
                key = th.get_text(strip=True).replace(':', '')
                value = td.get_text(strip=True)
                data[key] = value

    # Extracting the malware samples table (second table, optional)
    host_ports = []
    if len(tables) > 1:
        samples_table = tables[1]
        samples_rows = samples_table.find('tbody').find_all('tr')
        for sample_row in samples_rows:
            sample_cols = sample_row.find_all('td')
            if len(sample_cols) >= 5:
                host_port = sample_cols[4].get_text(strip=True)
                host_port_splitted = str(host_port).split(':')
                sample = {
                    'timestamp': sample_cols[0].get_text(strip=True),
                    'malware_md5': sample_cols[1].get_text(strip=True),
                    'host': host_port_splitted[0],
                    'port': host_port_splitted[1]
                }
                host_ports.append(sample)

    # Constructing the final result
    result = {
        'CN': data.get('Certificate Common Name (CN)', ''),
        'DN': data.get('Issuer Distinguished Name (DN)', ''),
        'fseen': data.get('First seen', ''),
        'lseen': data.get('Last seen', ''),
        'status': data.get('Status', ''),
        'samples': host_ports
    }

    return result

def main():

    CONFIG_FILE = "config.yaml"
    base_url = "https://sslbl.abuse.ch/ssl-certificates/sha1/"
    sslbl_url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    max_retries = 3
    init_delay = 1
    max_delay = 30

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-i", "--input-file", type=str, default=None, help=f"provide file name of the local SSL Blacklist CSV (do not fetch from the internet)")
    parser.add_argument("-o", "--output", type=str, default="sslbl_extended.json", help=f"specify the output file name (default: sslbl_extended.json)")
    parser.add_argument("-p", "--pause", type=int, default=1, help=f"specify the pause between requests (default: 1)")
    parser.add_argument("-s", "--silent", action="store_true", help="run the script without progress bars")
    args = parser.parse_args()

    console = Console()
    console.quiet = args.silent
    sleep_between_requests = args.pause

    try:
        with open(CONFIG_FILE, "r") as file:
            config = yaml.safe_load(file)
            base_url = config.get("sslbl_cert_url", base_url)
            sslbl_url = config.get("sslbl_url", sslbl_url)
            max_retries = config.get("max_retries", max_retries)
            init_delay = config.get("init_delay", init_delay)
            max_delay = config.get("max_delay", max_delay)
    except yaml.YAMLError as e:
        console.print(f"Error parsing YAML file: {e}. Using default values.")
    except Exception as e:
        console.print(f"Error reading config file: {e}. Using default values.")


    # Read the SSL Blacklist from the internet or a local file
    if args.input_file:
        with open(args.input_file, "r") as file:
            blacklist_csv = file.read()
    else:
        response = make_request(sslbl_url, console, max_retries, init_delay, max_delay)
        blacklist_csv = response.text
    sslbl_reader = csv.reader(blacklist_csv.splitlines() )

    # console.print(f"Loaded SSL Blacklist with {len(blacklist_csv.splitlines())} entries.")

    # Load existing data from the output file if it exists
    sslbl_current = []
    try:
        with open(args.output, "r") as json_file:
            sslbl_current = json.load(json_file)
    except FileNotFoundError:
        console.print(f"Output file {args.output} not found. A new file will be created.")
    except json.JSONDecodeError as e:
        console.print(f"Error decoding JSON from {args.output}: {e}. Starting with an empty list.")
    except Exception as e:
        console.print(f"Error reading {args.output}: {e}. Starting with an empty list.")
    
    # console.print(f"Loaded {len(sslbl_current)} entries from the output file.")

    new_lines = []
    for line_number, line in enumerate(sslbl_reader, start=1):
        if line[0][0] != '#' and len(line)>=3:
            if any(entry['sha1'] == line[1] for entry in sslbl_current):
                    continue
            new_lines.append(line)

    if len(new_lines) == 0:
        console.print("No new entries found to process.")
        exit(0)
    console.print(f"Found {len(new_lines)} new entries to process.")

    # Enum threats from the SSL Blacklist
    sslbl_new = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing SSL Blacklist", total=len(new_lines))
        for line in new_lines:
            progress.update(task, advance=1)
            if line[0][0] != '#' and len(line)>=3:
                element = {}
                element['sha1'] = line[1]
                element['threat'] = line[2]
                element['listing_date'] = line[0]
                response = make_request(f"{base_url}{element['sha1']}/", console, max_retries, init_delay, max_delay)
                parse = parse_ssl_certificate_page(response.text)
                element['cn'] = parse['CN']
                element['dn'] = parse['DN']
                element['fseen'] = parse['fseen']
                element['lseen'] = parse['lseen']
                element['status'] = parse['status']
                element['samples'] = parse['samples']
                sslbl_new.append(element)
                time.sleep(sleep_between_requests)

    # Save the extended SSL Blacklist to a JSON file
    sslbl_new.extend(sslbl_current)
    try:
        with open(args.output, "w") as json_file:
            json.dump(sslbl_new, json_file, indent=4)
    except Exception as e:
        console.print_exception()

if __name__ == "__main__":
    main()


    








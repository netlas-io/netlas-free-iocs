import csv
import os
import argparse
import yaml
from datetime import datetime

CONFIG_FILE = "config.yaml"
fieldnames = ['timestamp', 'host', 'port', 'protocol', 'path', 'ip', 'threat', 'netlas:fseen', 'netlas:link', 'x509:sha1', 'x509:timestamp', 'x509:link']

def load_database(file_path):
    """Load the existing database into a dictionary."""
    database = {}
    if os.path.exists(file_path):
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            lines = file.readlines()
            if lines:
                reader = csv.DictReader(lines)
                for row in reader:
                    key = (row['host'], row['port'], row['protocol'], row['path'], row['ip'], row['threat'])
                    database[key] = {
                        'timestamp': row['timestamp'],
                        'netlas:fseen': row['netlas:fseen'],
                        'netlas:link': row['netlas:link'],
                        'x509:sha1': row['x509:sha1'],
                        'x509:timestamp': row['x509:timestamp'],
                        'x509:link': row['x509:link']
                    }
    return database

def save_database(database, file_path):
    """Save the database dictionary back to the CSV file."""
    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for (host, port, protocol, path, ip, threat), data in database.items():
            writer.writerow({
                'timestamp': data['timestamp'], 
                'host': host,
                'port': port, 
                'protocol': protocol, 
                'path': path, 
                'ip': ip, 
                'threat': threat, 
                'netlas:fseen': data['netlas:fseen'], 
                'netlas:link': data['netlas:link'], 
                'x509:sha1': data['x509:sha1'], 
                'x509:timestamp': data['x509:timestamp'], 
                'x509:link': data['x509:link']
            })

def process_input_file(input_file, database):
    """Process the input file and update the database."""
    added_count = 0
    updated_count = 0
    with open(input_file, mode='r', newline='', encoding='utf-8') as file:
        lines = file.readlines()
        if lines:
            reader = csv.DictReader(lines)
            for row in reader:
                timestamp = row['timestamp']
                key = (row['host'], row['port'], row['protocol'], row['path'], row['ip'], row['threat'])
                if key in database:
                    # Update the last seen date only if the new timestamp is later
                    existing_timestamp = database[key]['timestamp']
                    if datetime.fromisoformat(timestamp) > datetime.fromisoformat(existing_timestamp):
                        database[key]['timestamp'] = timestamp
                        updated_count += 1
                else:
                    # Add a new entry with first seen and last seen dates
                    database[key] = {
                        'timestamp': timestamp,
                        'netlas:fseen': timestamp,
                        'netlas:link': row['netlas:link'],
                        'x509:sha1': row['x509:sha1'],
                        'x509:timestamp': row['x509:timestamp'],
                        'x509:link': row['x509:link']
                    }
                    added_count += 1
    return added_count, updated_count


def log_message(message, log_file):
    """Log a message with a timestamp to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, mode='a', encoding='utf-8') as lf:
        lf.write(f"[{timestamp}]\t{message}\n")


def main():
    parser = argparse.ArgumentParser(description="Update a database of malicious hosts.")
    parser.add_argument("input_file", help="Path to the input CSV file")
    parser.add_argument("-s", "--silent", action="store_true", help="Run in silent mode (no output)")
    args = parser.parse_args()

    input_file = args.input_file

    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        exit(1)
    
    try:
        with open(CONFIG_FILE, "r") as file:
            config = yaml.safe_load(file)
            dbf = config.get("database_file")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}. Using default values.")
    except Exception as e:
        print(f"Error reading config file: {e}. Using default values.")
    
    # Load the existing database
    database = load_database(dbf)

    # Process the input file
    added_count, updated_count = process_input_file(input_file, database)

    if added_count > 0 or updated_count > 0:
        save_database(database, dbf)  # Save the updated database
        message = f"Comparison: Database updated successfully. {added_count} entries added, {updated_count} entries updated."
    else:
        message = f"Comparison: Nothing to update"
    
    if config.get("log_changes"):
      log_message(message, config.get("log_file"))

    if not args.silent:
        print(message)

if __name__ == "__main__":
    main()

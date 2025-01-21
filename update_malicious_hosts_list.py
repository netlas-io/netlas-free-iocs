import csv
import os
import argparse
import yaml
from datetime import datetime

CONFIG_FILE = "config.yaml"

def load_database(file_path):
    """Load the existing database into a dictionary."""
    database = {}
    if os.path.exists(file_path):
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            lines = file.readlines()
            if lines:
                reader = csv.DictReader(lines)
                for row in reader:
                    key = (row['URL'], row['Threat'])
                    database[key] = {
                        'FSeen': row['FSeen'],
                        'LSeen': row['LSeen']
                    }
    return database

def save_database(database, file_path):
    """Save the database dictionary back to the CSV file."""
    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        fieldnames = ['URL', 'Threat', 'FSeen', 'LSeen']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for (url, threat), data in database.items():
            writer.writerow({
                'URL': url,
                'Threat': threat,
                'FSeen': data['FSeen'],
                'LSeen': data['LSeen']
            })

def process_input_file(input_file, database):
    """Process the input file and update the database."""
    added_count = 0
    updated_count = 0
    with open(input_file, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            url, threat, _, timestamp = row
            key = (url, threat)
            if key in database:
                # Update the last seen date only if the new timestamp is later
                existing_lseen = database[key]['LSeen']
                if datetime.fromisoformat(timestamp) > datetime.fromisoformat(existing_lseen):
                    database[key]['LSeen'] = timestamp
                    updated_count += 1
            else:
                # Add a new entry with first seen and last seen dates
                database[key] = {
                    'FSeen': timestamp,
                    'LSeen': timestamp
                }
                added_count += 1
    return added_count, updated_count


def log_message(message, log_file):
    """Log a message with a timestamp to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, mode='a', encoding='utf-8') as log_file:
        log_file.write(f"[{timestamp}]\t{message}\n")


def main():
    parser = argparse.ArgumentParser(description="Update a database of malicious hosts.")
    parser.add_argument("input_file", help="Path to the input CSV file")
    parser.add_argument("-s", "--silent", action="store_true", help="Run in silent mode (no output)")
    args = parser.parse_args()

    input_file = args.input_file

    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        exit(code=-1)

    # Load configuration
    with open(CONFIG_FILE, "r") as file:
        config = yaml.safe_load(file)

    # Load the existing database
    dbf = config.get("database_file")
    database = load_database(dbf)

    # Process the input file
    added_count, updated_count = process_input_file(input_file, database)

    # Save the updated database
    save_database(database, dbf)

    message = f"Database updated successfully. {added_count} entries added, {updated_count} entries updated."
    
    if config.get("log_changes_summary"):
      log_message(message, config.get("log_file"))

    if not args.silent:
        print(message)

if __name__ == "__main__":
    main()

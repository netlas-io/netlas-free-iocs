import csv
import os
import argparse
import yaml
from datetime import datetime

CONFIG_FILE = "config.yaml"

HEADER = "URL,Threat,fseen,lseen\n"

def load_database(file_path):
    """Load the existing database into a dictionary."""
    database = {}
    if os.path.exists(file_path):
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            lines = file.readlines()
            # Skip the header line
            data_lines = lines[1:] if lines else []
            if data_lines:
                reader = csv.DictReader(data_lines)
                for row in reader:
                    key = (row['URL'], row['Threat'])
                    database[key] = {
                        'fseen': row['fseen'],
                        'lseen': row['lseen']
                    }
    return database

def save_database(database, file_path):
    """Save the database dictionary back to the CSV file."""
    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        file.write(HEADER)
        fieldnames = ['URL', 'Threat', 'fseen', 'lseen']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for (url, threat), data in database.items():
            writer.writerow({
                'URL': url,
                'Threat': threat,
                'fseen': data['fseen'],
                'lseen': data['lseen']
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
                existing_lseen = database[key]['lseen']
                if datetime.fromisoformat(timestamp) > datetime.fromisoformat(existing_lseen):
                    database[key]['lseen'] = timestamp
                    updated_count += 1
            else:
                # Add a new entry with first seen and last seen dates
                database[key] = {
                    'fseen': timestamp,
                    'lseen': timestamp
                }
                added_count += 1
    return added_count, updated_count

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

    if not args.silent:
        print(f"Database updated successfully. {added_count} entries added, {updated_count} entries updated.")

if __name__ == "__main__":
    main()

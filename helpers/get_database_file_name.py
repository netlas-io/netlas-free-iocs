import yaml
import sys

def get_database_file_name():
    try:
        with open("config.yaml", "r") as config_file:
            config = yaml.safe_load(config_file)
            database_file = config.get("database_file")
            if not database_file:
                raise ValueError("database_file not found in config.yaml")
            return database_file
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    print(get_database_file_name())

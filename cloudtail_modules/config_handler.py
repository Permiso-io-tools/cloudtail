import json
import os
import sys

def read_config(file_path):
    if not os.path.exists(file_path):
        print(f"\033[91m[!] Config file not found: {file_path}\033[0m")
        sys.exit(1)
    
    try:
        with open(file_path, 'r') as file:
            config = json.load(file)
        return config
    except json.JSONDecodeError:
        print(f"\033[91m[!] Failed to parse config file: {file_path}. Ensure it's a valid JSON file.\033[0m")
        sys.exit(1)


def validate_basic_config(config):
    if 'dataSources' not in config or not isinstance(config['dataSources'], list):
        print("\033[91m[!] Invalid config: 'dataSources' field missing or incorrectly formatted.\033[0m")
        sys.exit(1)
    
    for idx, source in enumerate(config['dataSources']):
        if 'source' not in source or not isinstance(source['source'], str):
            print(f"\033[91m[!] Invalid config: 'source' field missing or not a string in dataSource at index {idx}.\033[0m")
            sys.exit(1)
        
        if 'lookup_Attributes' not in source or not isinstance(source['lookup_Attributes'], list):
            print(f"\033[91m[!] Invalid config: 'lookup_Attributes' missing or not a list in dataSource at index {idx} ('{source.get('source', 'Unknown')}').\033[0m")
            sys.exit(1)

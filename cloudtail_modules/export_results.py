import os
import json
from datetime import datetime
from cloudtail_modules.database_utils import connect_to_db

def fetch_events(cursor, event_table, execStartTime=None, execEndTime=None):
    query = f"SELECT * FROM {event_table}"
    params = []
    
    if execStartTime and execEndTime:
        query += " WHERE execStartTime >= ? AND execEndTime <= ?"
        params.append(execStartTime)
        params.append(execEndTime)

    cursor.execute(query, params)
    return cursor.fetchall()

def append_or_write_json(file_path, events):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            existing_data = json.load(f)
    else:
        existing_data = []

    new_events = [event for event in events if event not in existing_data]
    
    if new_events:
        existing_data.extend(new_events)
        with open(file_path, 'w') as f:
            json.dump(existing_data, f, default=str, indent=4)
        print(f"\033[92m[+]\033[96m Successfully wrote \033[92m{len(new_events)} \033[96m new events to \033[93m{file_path}")
    else:
        print(f"\033[92m[+]\033[96m No new events to write in \033[93m{file_path}")

def export_events_to_json(db_path, event_table, source_name, output_dir, execStartTime=None, execEndTime=None):
    con, cursor = connect_to_db(db_path)
    
    events = fetch_events(cursor, event_table, execStartTime, execEndTime)

    if not events:
        print(f"\033[92m[+]\033[96m No events found for \033[93m{source_name} in the given time range.")
        return

    date_str = datetime.now().strftime('%Y-%m-%d')
    file_name = f"{source_name}_{date_str}.json"
    file_path = os.path.join(output_dir, file_name)

    append_or_write_json(file_path, events)

def export_all_events(db_paths, output_dir):
    export_events_to_json(db_paths['aws'], 'cloudtrail_events', 'AWS_CloudTrail', output_dir)
    export_events_to_json(db_paths['azure'], 'azure_events', 'Azure_Activity_Log', output_dir)

def export_events_by_time_range(db_paths, output_dir, execStartTime, execEndTime):
    export_events_to_json(db_paths['aws'], 'cloudtrail_events', 'AWS_CloudTrail', output_dir, execStartTime, execEndTime)
    export_events_to_json(db_paths['azure'], 'azure_events', 'Azure_Activity_Log', output_dir, execStartTime, execEndTime)


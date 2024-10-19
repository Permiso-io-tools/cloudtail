import sqlite3
from datetime import datetime, timedelta
from azure.mgmt.monitor.v2015_04_01.models import LocalizableString
import json
import uuid



def adapt_datetime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def convert_datetime(s):
    return datetime.strptime(s.decode('ascii'), "%Y-%m-%d %H:%M:%S.%f")


sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)

def connect_to_db(db_name):
    con = sqlite3.connect(db_name, detect_types=sqlite3.PARSE_DECLTYPES)
    return con, con.cursor()




def set_up_aws_tables(cursor, con, event_table_name):
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS execution_history(
            ExecutionID INTEGER PRIMARY KEY AUTOINCREMENT,
            RuleName TEXT,
            AttributeKey TEXT,
            AttributeValue TEXT,
            startTime TIMESTAMP,
            endTime TIMESTAMP,
            execStartTime TIMESTAMP,
            execEndTime TIMESTAMP,
            resultCount INTEGER,
            isSuccessful BOOLEAN,
            UNIQUE(RuleName, AttributeKey, AttributeValue, startTime)
        );
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {event_table_name}(
            EventID TEXT PRIMARY KEY,
            AccountID TEXT,
            ProfileName TEXT,
            EventName TEXT,
            EventTime TIMESTAMP,
            EventData TEXT,
            ExecutionID INTEGER,
            FOREIGN KEY(ExecutionID) REFERENCES execution_history(ExecutionID)
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lookup_attributes(
            AttributeID INTEGER PRIMARY KEY AUTOINCREMENT,
            AttributeKey TEXT,
            AttributeValue TEXT,
            UNIQUE(AttributeKey, AttributeValue)
        );
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS event_lookup_attributes(
            EventID TEXT,
            AttributeID INTEGER,
            FOREIGN KEY(EventID) REFERENCES {event_table_name}(EventID),
            FOREIGN KEY(AttributeID) REFERENCES lookup_attributes(AttributeID)
        );
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS rule_matches(
            RuleMatchID INTEGER PRIMARY KEY AUTOINCREMENT,
            RuleName TEXT,
            EventID TEXT,
            ExecutionID INTEGER,
            UNIQUE(RuleName, EventID),
            FOREIGN KEY(EventID) REFERENCES {event_table_name}(EventID),
            FOREIGN KEY(ExecutionID) REFERENCES execution_history(ExecutionID)
        );
    """)
    con.commit()

def set_up_azure_tables(cursor, con, event_table_name):
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS execution_history(
            ExecutionID INTEGER PRIMARY KEY AUTOINCREMENT,
            RuleName TEXT,
            AttributeKey TEXT,
            AttributeValue TEXT,
            startTime TIMESTAMP,
            endTime TIMESTAMP,
            execStartTime TIMESTAMP,
            execEndTime TIMESTAMP,
            resultCount INTEGER,
            isSuccessful BOOLEAN,
            UNIQUE(RuleName, AttributeKey, AttributeValue, startTime)
        );
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {event_table_name}(
            eventDataId TEXT PRIMARY KEY,
            SubscriptionID TEXT,
            OperationName TEXT,
            EventTimestamp TIMESTAMP,
            EventData TEXT,
            ExecutionID INTEGER,
            FOREIGN KEY(ExecutionID) REFERENCES execution_history(ExecutionID)
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lookup_attributes(
            AttributeID INTEGER PRIMARY KEY AUTOINCREMENT,
            AttributeKey TEXT,
            AttributeValue TEXT,
            UNIQUE(AttributeKey, AttributeValue)
        );
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS event_lookup_attributes(
            eventDataId TEXT,
            AttributeID INTEGER,
            FOREIGN KEY(eventDataId) REFERENCES {event_table_name}(eventDataId),
            FOREIGN KEY(AttributeID) REFERENCES lookup_attributes(AttributeID)
        );
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS rule_matches(
            RuleMatchID INTEGER PRIMARY KEY AUTOINCREMENT,
            RuleName TEXT,
            eventDataId TEXT,
            ExecutionID INTEGER,
            UNIQUE(RuleName, eventDataId),
            FOREIGN KEY(eventDataId) REFERENCES {event_table_name}(eventDataId),
            FOREIGN KEY(ExecutionID) REFERENCES execution_history(ExecutionID)
        );
    """)
    con.commit()
    

def setup_database_connection_and_tables(db_name, event_table_name, event_type):
    """Helper function to handle connection and table setup based on event type (AWS or Azure)"""
    con, cursor = connect_to_db(db_name)
    if event_type == 'aws':
        set_up_aws_tables(cursor, con, event_table_name)
    elif event_type == 'azure':
        set_up_azure_tables(cursor, con, event_table_name)
    return con, cursor



def add_execution_history(cursor, con, attribute_key: str, attribute_value: str, startTime: datetime, endTime: datetime,
                          execStartTime: datetime, execEndTime: datetime,
                          resultCount: int, isSuccessful: bool, rule_name: str) -> int:
    query = f"""INSERT INTO execution_history (RuleName, AttributeKey, AttributeValue, startTime, endTime, execStartTime, execEndTime, resultCount, isSuccessful)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    cursor.execute(query, (rule_name, attribute_key, attribute_value, startTime, endTime, execStartTime, execEndTime, resultCount, isSuccessful))
    con.commit()
    return cursor.lastrowid




def get_last_successful_execution_history(cursor, attribute_key: str, attribute_value: str) -> datetime:
    query = f"SELECT endTime FROM execution_history WHERE AttributeKey = ? AND AttributeValue = ? AND isSuccessful = 1 ORDER BY endTime DESC LIMIT 1"
    cursor.execute(query, (attribute_key, attribute_value))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        return datetime.now() - timedelta(days=90) + timedelta(days=1)




def add_lookup_attribute(cursor, con, attribute_key: str, attribute_value: str) -> int:
    cursor.execute("""
        INSERT OR IGNORE INTO lookup_attributes (AttributeKey, AttributeValue)
        VALUES (?, ?)
    """, (attribute_key, attribute_value))
    
    cursor.execute("""
        SELECT AttributeID FROM lookup_attributes 
        WHERE AttributeKey = ? AND AttributeValue = ?
    """, (attribute_key, attribute_value))
    
    result = cursor.fetchone()
    return result[0] if result else None




def add_event_lookup_mapping(cursor, con, event_id: str, attribute_id: int, event_table_name: str):
    if event_table_name == 'cloudtrail_events':
        id_column = 'EventID'
    elif event_table_name == 'azure_events':
        id_column = 'eventDataId'
    else:
        raise ValueError("Unknown event table name")
    
    cursor.execute(f"""
        INSERT OR IGNORE INTO event_lookup_attributes ({id_column}, AttributeID)
        VALUES (?, ?)
    """, (event_id, attribute_id))
    con.commit()




def add_rule_match(cursor, con, rule_name: str, event_id: str, execution_id: int, event_table_name: str):
    table_id_column_map = {
        'cloudtrail_events': 'EventID',
        'azure_events': 'eventDataId'
    }

    try:
        id_column = table_id_column_map[event_table_name]
    except KeyError:
        raise ValueError(f"Unknown event table name: {event_table_name}. Expected 'cloudtrail_events' or 'azure_events'.")

    cursor.execute(f"""
        INSERT OR IGNORE INTO rule_matches (RuleName, {id_column}, ExecutionID)
        VALUES (?, ?, ?)
    """, (rule_name, event_id, execution_id))
    
    con.commit()




def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    elif isinstance(x, timedelta):
        return str(x)
    elif isinstance(x, LocalizableString):
        return x.value  
    elif isinstance(x, dict):
        return {k: datetime_handler(v) for k, v in x.items()}  
    elif isinstance(x, list):
        return [datetime_handler(i) for i in x]  
    elif x is None:
        return None  
    elif hasattr(x, '__dict__'):
        return {k: datetime_handler(v) for k, v in x.__dict__.items()}  
    else:
        return str(x)      
    
    
    

def write_events(cursor, con, events: list[dict], execution_id: int, event_table_name: str, id_column: str, account_info: dict = None) -> int:
    eventCount = 0
    failed_events = []  

    for event in events:
        try:
            if event_table_name == 'azure_events' and hasattr(event, '__dict__'):
                event = event.__dict__

            if not isinstance(event, dict):
                print(f"\033[91m[!] Warning: Expected dict, but got {type(event).__name__}. Skipping this event.")
                continue  

            if event_table_name == 'azure_events':
                id_value = event.get('event_data_id')

                if not id_value:
                    id_value = event.get('id', str(uuid.uuid4()))  

                name_value = event.get('operation_name') or event.get('operationName')
                if isinstance(name_value, LocalizableString):
                    name_value = name_value.value
                elif isinstance(name_value, dict):
                    name_value = name_value.get('value')

                time_value = event.get('event_timestamp')

                if name_value is None:
                    print(f"Warning: operation_name is missing in event {id_value}")

                if time_value is None:
                    print(f"Warning: event_timestamp is missing in event {id_value}")

                name_column = 'operationName'
                time_column = 'eventTimestamp'
                subscription_id = account_info.get('subscription_id')

                cursor.execute(f"""
                    INSERT OR IGNORE INTO {event_table_name} (
                        {id_column}, SubscriptionID, {name_column}, {time_column}, EventData, ExecutionID)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    id_value, 
                    subscription_id,
                    name_value,
                    time_value,
                    json.dumps(event, default=datetime_handler),
                    execution_id
                ))

            elif event_table_name == 'cloudtrail_events':
                id_value = event.get('EventId')
                name_value = event.get('EventName')
                time_value = event.get('EventTime')
                account_id = account_info.get('account_id')
                profile_name = account_info.get('profile_name')

                if not id_value:
                    raise ValueError(f"Event ID not found for cloudtrail_events")

                cursor.execute(f"""
                    INSERT OR IGNORE INTO {event_table_name} (
                        {id_column}, AccountID, ProfileName, EventName, EventTime, EventData, ExecutionID)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    id_value,
                    account_id,
                    profile_name,
                    name_value,
                    time_value,
                    json.dumps(event, default=datetime_handler),
                    execution_id
                ))

            else:
                raise ValueError("Unknown event table name")

            if cursor.rowcount > 0:
                eventCount += 1

        except Exception as e:
            print(f"\033[91m[!] Error writing event {event.get(id_column, 'unknown_id')}: {e}")
            failed_events.append(event)  

    con.commit()

    if failed_events:
        print(f"\033[91m[!] {len(failed_events)} events failed to write. See logs for more details.")

    return eventCount

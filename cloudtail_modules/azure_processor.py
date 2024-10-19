import fnmatch
import re
from datetime import datetime, timedelta
from azure.mgmt.monitor.v2015_04_01.models import LocalizableString
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError, HttpResponseError
from cloudtail_modules.database_utils import set_up_azure_tables, add_execution_history, write_events, get_last_successful_execution_history, add_lookup_attribute, add_event_lookup_mapping, add_rule_match


def custom_json_handler(obj):
    if isinstance(obj, LocalizableString):
        return obj.value  
    elif isinstance(obj, datetime):
        return obj.isoformat()  
    else:
        return str(obj)  
    

    
def to_snake_case(camel_case_str):
    """Convert a camelCase string to snake_case."""
    return ''.join(['_' + i.lower() if i.isupper() else i for i in camel_case_str]).lstrip('_')



def get_azure_events(monitor_client, start_time: datetime, end_time: datetime):
    filter_str = f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}'"    
    try:
        logs = monitor_client.activity_logs.list(filter=filter_str)
        for log in logs:
            yield log
    except HttpResponseError as hre:
        print(f"\033[91m[!] Error retrieving Azure events: {hre.message}. Skipping.\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Unexpected error retrieving Azure events: {e}. Skipping.\033[0m")


def fuzzy_match(value, pattern):
    if '*' not in pattern and not re.search(r'[.^$+?{}[\]|()]', pattern):
        return value == pattern
    
    if '*' in pattern:
        return fnmatch.fnmatch(value, pattern)
    
    try:
        return re.match(pattern, value) is not None
    except re.error:
        print(f"\033[91m[!] Invalid regex pattern: {pattern}\033[0m")
        return False



def process_azure_events(config, cursor, con):
    table_name = "azure_events"
    set_up_azure_tables(cursor, con, table_name)

    for source in config['dataSources']:
        if source['source'] == 'Azure Activity Log':
            subscription_ids = source.get('subscription_ids', [])

            if not subscription_ids:
                print(f"\033[93m[!] No subscription_ids defined. Skipping Azure Activity Log processing.\033[0m")
                continue
            
            credential = DefaultAzureCredential()

            for subscription_id in subscription_ids:
                try:
                    monitor_client = MonitorManagementClient(credential, subscription_id)
                except ClientAuthenticationError:
                    print(f"\033[91m[!] Authentication failed for subscription_id '{subscription_id}'. Skipping.\033[0m")
                    continue
                except ResourceNotFoundError:
                    print(f"\033[91m[!] The subscription '{subscription_id}' could not be found. Skipping.\033[0m")
                    continue
                except HttpResponseError as hre:
                    if "InvalidSubscriptionId" in str(hre):
                        print(f"\033[91m[!] The subscription identifier '{subscription_id}' is malformed or invalid. Skipping.\033[0m")
                    else:
                        print(f"\033[91m[!] An unexpected HTTP error occurred: {hre.message}. Skipping.\033[0m")
                    continue
                except Exception as e:
                    print(f"\033[91m[!] An unexpected error occurred: {e}. Skipping.\033[0m")
                    continue

                for attr in source['lookup_Attributes']:
                    print(f"\n\033[96m[*] Querying Azure lookup attribute \033[94m{attr}\033[0m for subscription \033[94m{subscription_id}\033[0m")

                    attribute_key = attr.get('AttributeKey')
                    attribute_value = attr.get('AttributeValue')
                    rule_name = attr.get('RuleName', 'Unknown Rule')

                    if not attribute_key or not attribute_value:
                        print(f"\033[91m[!] AttributeKey & AttributeValue are not defined in config file, so skipping this query.\033[0m")
                        continue

                    apply_fuzzy_matching = '*' in attribute_value or re.search(r'[.^$+?{}[\]|()]', attribute_value)

                    startTime = get_last_successful_execution_history(cursor, attribute_key, attribute_value)
                    endTime = datetime.now() - timedelta(minutes=30)

                    if endTime <= startTime:
                        endTime = startTime + timedelta(minutes=1)

                    endTime = min(startTime + timedelta(days=30), endTime)

                    print(f"\033[96m[*] Start Time :: \033[93m{startTime.isoformat()}\033[0m")
                    print(f"\033[96m[*] End Time   :: \033[93m{endTime.isoformat()}\033[0m")

                    execStartTime = datetime.now()
                    try:
                        events = list(get_azure_events(monitor_client, startTime, endTime))
                    except Exception as e:
                        print(f"\033[91m[!] Error retrieving events: {e}. Skipping this lookup.\033[0m")
                        continue

                    snake_case_attribute_key = to_snake_case(attribute_key)

                    filtered_events = []
                    for event in events:
                        event_data = event.__dict__

                        if snake_case_attribute_key in event_data:
                            event_attribute_value = event_data[snake_case_attribute_key]
                            if isinstance(event_attribute_value, LocalizableString):
                                event_attribute_value = event_attribute_value.value
                            elif isinstance(event_attribute_value, dict) and 'value' in event_attribute_value:
                                event_attribute_value = event_attribute_value['value']
                        else:
                            continue

                        if apply_fuzzy_matching:
                            if fuzzy_match(event_attribute_value, attribute_value):
                                filtered_events.append(event)
                        else:
                            if event_attribute_value == attribute_value:
                                filtered_events.append(event)

                    execution_id = add_execution_history(cursor, con, attribute_key, attribute_value, startTime, endTime, execStartTime, datetime.now(), len(filtered_events), True, rule_name)

                    account_info = {'subscription_id': subscription_id}
                    eventCount = write_events(cursor, con, filtered_events, execution_id, table_name, 'eventDataId', account_info)

                    attribute_id = add_lookup_attribute(cursor, con, attribute_key, attribute_value)
                    for event in filtered_events:
                        add_event_lookup_mapping(cursor, con, event.event_data_id, attribute_id, table_name)
                        add_rule_match(cursor, con, rule_name, event.event_data_id, execution_id, table_name)

                    if eventCount > 0:
                        print(f"\033[92m[+]\033[96m Successfully wrote \033[92m{eventCount}\033[96m {'event' if eventCount == 1 else 'events'} into \033[92m{table_name}\033[96m table for above attribute.\033[0m")

                    else:
                        print(f"\033[96m[*] \033[92m0\033[96m events found for above attribute & time range.\033[0m")


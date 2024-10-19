from datetime import datetime, timedelta
import boto3
import json
import jmespath
import fnmatch
import re
from jmespath.exceptions import LexerError, JMESPathError
from botocore.exceptions import ProfileNotFound
from cloudtail_modules.database_utils import set_up_aws_tables, add_execution_history, write_events, get_last_successful_execution_history, add_lookup_attribute, add_event_lookup_mapping, add_rule_match

def get_cloudtrail_events(client, lookup_attributes, startTime, endTime):
    paginator = client.get_paginator('lookup_events')
    page_iterator = paginator.paginate(
        LookupAttributes=lookup_attributes,
        StartTime=startTime,
        EndTime=endTime,
        MaxResults=50,
    )
    for page in page_iterator:
        for event in page['Events']:
            yield event


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

def get_nested_event_value(event, attribute_key):

    keys = attribute_key.split(".")
    value = event
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key, "")
        else:
            return "" 
    return value
    

def process_aws_events(config, cursor, con):
    for source in config['dataSources']:
        if source['source'] == 'AWS CloudTrail':
            account_profile_pairs = source.get('account_profile_pairs', [])
            
            if not account_profile_pairs:
                print(f"\033[93m[!] No account_profile_pairs defined. Using default AWS profile.\033[0m")
                account_profile_pairs = [{"account_id": None, "profile_name": None}]

            for pair in account_profile_pairs:
                profile_name = pair['profile_name']
                expected_account_id = pair['account_id']
                
                try:
                    session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
                    client = session.client('sts')
                    response = client.get_caller_identity()
                    account_id = response['Account']

                    if expected_account_id and expected_account_id != account_id:
                        raise ValueError(f"Configured accountId {expected_account_id} does not match the current credentials' accountId {account_id} for profile {profile_name}")

                except ProfileNotFound:
                    print(f"\033[91m[!] Profile '{profile_name}' not found. Skipping this profile.\033[0m")
                    continue
                except ValueError as ve:
                    print(f"\033[91m[!] {ve}. Skipping this profile.\033[0m")
                    continue
                except Exception as e:
                    print(f"\033[91m[!] An unexpected error occurred: {e}. Skipping this profile.\033[0m")
                    continue

                table_name = "cloudtrail_events"
                set_up_aws_tables(cursor, con, table_name)

                client = session.client('cloudtrail')

                lookup_attributes_list = source.get('lookup_Attributes', [])

                if not lookup_attributes_list:
                    print(f"\033[93m[!] No lookup attributes defined for profile {profile_name} with accountId {expected_account_id}. Skipping...\033[0m")
                    continue

                for attr in lookup_attributes_list:
                    print(f"\n\033[96m[*] Querying AWS lookup attribute: \033[94m{attr}\033[0m with profile: \033[94m{profile_name or 'default'}\033[0m")

                    attribute_key = attr.get('AttributeKey')
                    attribute_value = attr.get('AttributeValue')
                    rule_name = attr.get('RuleName', 'Unknown Rule')
                    jmes_path_expression = attr.get('jmes_filter', None)

                    if jmes_path_expression:
                        try:
                            compiled_expression = jmespath.compile(jmes_path_expression)
                        except (LexerError, JMESPathError) as e:
                            print(f"\033[91m[!] Invalid JMESPath expression: {jmes_path_expression}. Skipping this query.")
                            continue  
                    else:
                        compiled_expression = None

                    if not ((attribute_key and attribute_value) or jmes_path_expression):
                        print(f"\033[91m[!] Either 'attributeKey'/'attributeValue' or 'jmes_filter' must be defined. Skipping this query.\033[0m")
                        continue

                    apply_fuzzy_matching = '*' in attribute_value or re.search(r'[.^$+?{}[\]|()]', attribute_value) if attribute_value else False

                    lookup_attributes = []
                    if not apply_fuzzy_matching and attribute_key and attribute_value:
                        lookup_attributes = [{'AttributeKey': attribute_key, 'AttributeValue': attribute_value}]

                    startTime = get_last_successful_execution_history(cursor, attribute_key, attribute_value)
                    endTime = datetime.now() - timedelta(minutes=30)

                    if endTime <= startTime:
                        endTime = startTime + timedelta(minutes=1)

                    endTime = min(startTime + timedelta(days=30), endTime)

                    print(f"\033[96m[*] Start Time :: \033[93m{startTime.isoformat()}\033[0m")
                    print(f"\033[96m[*] End Time   :: \033[93m{endTime.isoformat()}\033[0m")

                    execStartTime = datetime.now()

                    try:
                        if lookup_attributes:
                            events = list(get_cloudtrail_events(client, lookup_attributes, startTime, endTime))
                        else:
                            events = list(get_cloudtrail_events(client, [], startTime, endTime))
                    except client.exceptions.ClientError as e:
                        if "cloudtrail:LookupEvents" in str(e):
                            print(f"\033[91m[!] Missing permission: cloudtrail:LookupEvents\033[0m")
                            continue  
                        else:
                            raise e

                    parsed_events = []
                    for event in events:
                        if 'CloudTrailEvent' in event:
                            try:
                                event_data = json.loads(event['CloudTrailEvent'])
                                
                                event_data.update({
                                    'EventId': event['EventId'],
                                    'EventTime': event['EventTime'],
                                    'EventName': event['EventName'],
                                    'EventSource': event['EventSource'],
                                })
                                
                                parsed_events.append(event_data)
                            except json.JSONDecodeError:
                                print(f"\033[91m[!] Failed to decode CloudTrailEvent JSON for event {event['EventId']}\033[0m")
                                continue
                        else:
                            parsed_events.append(event)  

                    if compiled_expression:
                        filtered_events = compiled_expression.search(parsed_events)
                        if not filtered_events:
                            print(f"\033[93m[*] No events matched the JMESPath filter: {jmes_path_expression}\033[0m")
                            continue  
                    else:
                        filtered_events = parsed_events

                    matched_events = []
                    if apply_fuzzy_matching:
                        for event in filtered_events:
                            event_value = get_nested_event_value(event, attribute_key)
                            if fuzzy_match(event_value, attribute_value):
                                matched_events.append(event)
                    else:
                        matched_events = filtered_events

                    execution_id = add_execution_history(cursor, con, attribute_key, attribute_value, startTime, endTime, execStartTime, datetime.now(), len(matched_events), True, rule_name)
                    account_info = {'account_id': account_id, 'profile_name': profile_name}
                    eventCount = write_events(cursor, con, matched_events, execution_id, table_name, 'EventID', account_info)

                    attribute_id = add_lookup_attribute(cursor, con, attribute_key, attribute_value)
                    for event in matched_events:
                        add_event_lookup_mapping(cursor, con, event['EventId'], attribute_id, table_name)
                        add_rule_match(cursor, con, rule_name, event['EventId'], execution_id, table_name)

                    if eventCount > 0:
                        print(f"\033[92m[+]\033[96m Successfully wrote \033[92m{eventCount}\033[96m {'event' if eventCount == 1 else 'events'} into \033[92m{table_name}\033[96m table for above attribute.\033[0m")
                    else:
                        print(f"\033[96m[*] \033[92m0\033[96m events found for above attribute & time range.\033[0m")



from cloudtail_modules.database_utils import set_up_aws_tables, set_up_azure_tables
from cloudtail_modules.aws_processor import process_aws_events
from cloudtail_modules.azure_processor import process_azure_events

def process_all_events(config, aws_cursor, aws_con, azure_cursor, azure_con):
    set_up_aws_tables(aws_cursor, aws_con, 'cloudtrail_events')
    set_up_azure_tables(azure_cursor, azure_con, 'azure_events')

    process_aws_events(config, aws_cursor, aws_con)
    process_azure_events(config, azure_cursor, azure_con)

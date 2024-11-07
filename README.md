
<img width="892" alt="CloudTail" src="https://github.com/user-attachments/assets/4effc8fc-4a03-4ad1-a5d7-27bd79079502">

# CloudTail

**Permiso:** [https://permiso.io](https://permiso.io)  
**Read our release blog:** [https://permiso.io/blog/introducing-cloudtail-an-open-source-tool-for-long-term-cloud-log-retention-and-searchability](https://permiso.io/blog/introducing-cloudtail-an-open-source-tool-for-long-term-cloud-log-retention-and-searchability)



**Release Date: October 19th, 2024**

**Event: BSides NYC** 

CloudTail is an open-source tool designed to simplify the long-term retention and searchability of cloud logs from cloud platforms like AWS and Azure. It provides a practical solution that focuses on retaining high-value events for extended periods via the native APIs provided by each cloud provider, ensuring compatibility and efficiency.

## Required Packages

>```bash
># Optional: Set up a virtual environment
>python3 -m venv ./venv
>source venv/bin/activate
>
># Install required dependencies
>python3 -m pip install -r requirements.txt
>```

## Authentication

**AWS**

CloudTail uses **AWS credentials** configured in the local environment or specified in the configuration file to access AWS CloudTrail logs. You need to provide credentials with permissions to call the necessary CloudTrail APIs.

- **Setup**: Ensure that AWS credentials are configured in `~/.aws/credentials` or set as environment variables (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`).
- **Permissions**: The IAM user or role should have `cloudtrail:LookupEvents` permissions to retrieve CloudTrail logs.

**Azure**

The simplest way to authenticate with Azure is to first run:

`az login`

This will open a browser window and prompt you to login to Azure.

## **Input**

### **Configuration file**

To run CloudTail, you must specify a configuration file or use the default one `event_config.json` that defines how CloudTail will interact with the cloud providers and filter events.

The default configuration file we have provided contains a curated list of **high-value events** that we believe are the most important for security operations. This includes key events related to user management, role assignments, resource changes, security alerts, and more. However, you can easily modify the configuration file to suit your specific needs and add more detailed or customized event filters.

Below is a simplified example of the configuration file to demonstrate the account/subscription and filtering options:

```jsx
{
  "dataSources": [
    {
      "source": "AWS CloudTrail",
      "account_profile_pairs": [
        {"account_id": "9823653221093", "profile_name": "default"},
        {"account_id": "1234567890212", "profile_name": "development"}
      ],
      "lookup_Attributes": [
        {
          "RuleName": "User Management",
          "AttributeKey": "EventName",
          "AttributeValue": "CreateUser"
        }
      ]
    },
    {
      "source": "Azure Activity Log",
      "subscription_ids": [
        "34eb1234-8743-30ab-cdef-1238397430ab"
      ],
      "lookup_Attributes": [
        {
          "RuleName": "Resource Group Changes",
          "AttributeKey": "category",
          "AttributeValue": "Administrative"
        }
      ]
    }
  ]
}
```

Configuration file structure:

- **Data Sources**: Define the cloud providers and the necessary credentials. CloudTail supports multiple AWS accounts and profiles, as well as Azure subscriptions. If an AWS profile is not defined, it will default to using the `default` profile. Azure subscriptions must be explicitly defined.
- **Lookup Attributes**: Defines the event attributes to be filtered and retained, including support for **wildcard matching** and **JMESPath filtering**.

### **Running CloudTail**

To run CloudTail, use the following command:

```python3 cloudtail.py event_config.json```

![ASCII](https://github.com/user-attachments/assets/d3e756b7-0245-467f-9456-f32478aa22ff)


### **Example Use Cases**


**Example 1**

**Detecting S3 Activity**: Use `AttributeKey` as `EventSource` with `AttributeValue` set to `s3.amazonaws.com` to focus on S3-related events

```jsx
{
    "RuleName": "S3 Bucket Access",
    "AttributeKey": "EventSource",
    "AttributeValue": "s3.amazonaws.com"
}
```

**Example 2**

**Tracking Deletion Events**: Use wildcard matching (`Delete*`) to capture all events that involve deletions. This is particularly useful for monitoring critical changes.

```jsx
{
    "RuleName": "Deletion Events",
    "AttributeKey": "EventName",
    "AttributeValue": "Delete*"
}
```

**Example 3**

**Filtering User Creation Events**: Use `AttributeKey` as `EventName` with `AttributeValue` set to `CreateUser` where a specific user was created, using JMESPath filtering such as `userIdentity.username == 'admin-user'`

```jsx
{
     "RuleName": "User Management",
     "AttributeKey": "EventName",
     "AttributeValue": "CreateUser",
     "jmes_filter": "[?userIdentity.userName == 'admin-user']"
}
```

### **Notes**

-JMESPath filtering is only available for AWS logs. You can combine wildcard matching, JMESPath filtering, and other attribute filters to create comprehensive rules that cover multiple use cases.

-Scheduled Execution: CloudTail is designed to run on a scheduled basis, ensuring continuous processing of AWS and Azure logs. After each run, it automatically picks up where it left off, fetching new events based on the last successful execution. It can process up to 30 days of logs in one run but is optimized for regular scheduling, such as daily or hourly.

-Duplicate Event Handling: The tool tracks previously captured events, allowing it to run multiple times without capturing duplicates, ensuring efficiency when filling in gaps in event collection.

## Output

The extracted event data and associated metadata are stored in two SQLite databases (`aws_events.db` for AWS and `azure_events.db` for Azure). 

**Tables**

- `cloudtrail_events` and `azure_events` : Contains event metadata like `EventID`, `AccountID`, `ProfileName`, `EventName`, `EventTime`, and full `EventData`.
- `execution_history`: Tracks the execution history of event extraction for different rules.
- `rule_matches`: Stores information about events that match specific rules.
- `lookup_attributes` and `event_lookup_attributes` store lookup data and attribute mappings.

Additionally, CloudTail offers the option to export processed events as JSON files for easier viewing and external processing.

- **Export All Events**: Export all events that have already been processed and stored in the database.
    
    ```python3 cloudtail.py --export --output-dir /path/to/output```
    
- **Export Events within a Specific Time Range**: Export events processed between a specified time range. Provide start and end dates in the format `YYYY-MM-DD`.
    
    ```python3 cloudtail.py --export-time-range 2024-01-01 2024-12-31 --output-dir /path/to/output```
    

**Output Files**

- AWS events are stored in JSON files with the format: `AWS_CloudTrail_<date>.json`
- Azure events are stored in JSON files with the format: `Azure_Activity_Log_<date>.json`

If the tool is run multiple times in a single day, new events will be appended to the existing JSON file. The tool ensures that no duplicate events are added to the file.

import sys
import os
import argparse
from cloudtail_modules.config_handler import read_config, validate_basic_config
from cloudtail_modules.event_pipeline import process_all_events
from cloudtail_modules.database_utils import setup_database_connection_and_tables
from cloudtail_modules.export_results import export_all_events, export_events_by_time_range
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

ascii_art = f"""
{Fore.BLUE}                                                    kkkkkkkkkkkkkk                                  
                                                 (kk~kkkkkkkkkkkkkkk)                              
                                       kkkkkkk  kkmmkkkk      kkkkkkkkk                              
                                     kk      lkkkkkkk    kkkl    #kkkkkkk                            
                                   #k  kkkkkkkkkkkk   kkkkkkkkk      kkkkkkk                           
                               C#kkkk kkkkkkkkkkkkk  kkkkkkkkkkkC      kkkkkkk                          
                            mkkl    ~kkkkkkkkkkkkk  kkkk      kkkkk       kkkk kkkk#                       
                           kk  kkkkkkkkkkkkkk       kkkkkk      kkkk       kkkk#kkkkkk                      
                          km kkkkkkkkkkkkkkkkkkkk      kkkk      kkk         kkkk [kkkkkk)                  
                         kk kkkkkkkkkkkkkkkkkkkkkk        k      kkk          kkkkkkkkkkkkkc                    
                         kk kkk                               ##lll             kkkkkkk #kkkkkkk{Fore.GREEN}                    
                         kk[kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkmmmmmk           kkkkkkkkkkkkkkkkkk                   
                         #kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk    kkkkkkkkkkkkkkkkkkkkkkkkjkkkK                   
                          kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk             ~      
                           kkkkkkkkkkkkkkkkkkkkkkkk________                ________      _ __           ~~~
                            kkkkkkkk             / ____/ /___  __  ______/ /_  __/___ _(_) /           ~~~~
                                    kkkkkkkkkk  / /   / / __ \\/ / / / __  / / / / __ `/ / /            / /
                                               / /___/ / /_/ / /_/ / /_/ / / / / /_/ / / /____________/ /  
                                               \\____/_/\\____/\\__,_/\\__,_/ /_/  \\__,_/_/_/______________/   
                                                                                                   
"""

from_permiso = Fore.RED + r"""
                                 __  ___ __     . __   __     __  __             __  __
                                |__)|__ |__)|\/||/__` /  \   |__)/ /\   |    /\ |__)/__`
                          FROM: |   |___|  \|  ||.__/ \__/   |   \/_/   |___/~~\|__).__/
                             """

print(
    ascii_art +
    "" +
    from_permiso +
    "\n\n\n"
)

def main():
    parser = argparse.ArgumentParser(description="CloudTail Tool for processing and exporting events.")
    parser.add_argument('config_file', nargs='?', default=None, help="Path to the configuration file (required for processing events)")
    parser.add_argument('--export', action='store_true', help="Export all processed events to JSON")
    parser.add_argument('--export-time-range', nargs=2, help="Export events from a specific time range. Provide start and end date in 'YYYY-MM-DD' format")
    parser.add_argument('--output-dir', default="./", help="Directory to save the JSON files")

    args = parser.parse_args()
    output_dir = args.output_dir

    if not os.path.exists(output_dir):
        print(f"\033[91m[!] Output directory {output_dir} does not exist. Creating it...\033[0m")
        os.makedirs(output_dir)

    if args.export or args.export_time_range:
        try:
            aws_db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../aws_events.db")
            azure_db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../azure_events.db")
            
            db_paths = {
                'aws': aws_db_path,
                'azure': azure_db_path
            }

            if args.export:
                export_all_events(db_paths, output_dir)
            elif args.export_time_range:
                execStartTime = datetime.strptime(args.export_time_range[0], '%Y-%m-%d')
                execEndTime = datetime.strptime(args.export_time_range[1], '%Y-%m-%d')
                export_events_by_time_range(db_paths, output_dir, execStartTime, execEndTime)
        except Exception as e:
            print(f"\033[91m[!] An error occurred during export: {e}\033[0m")
            sys.exit(1)

    elif args.config_file:
        config_file_path = args.config_file

        from cloudtail_modules.config_handler import read_config, validate_basic_config

        config = read_config(config_file_path)
        validate_basic_config(config)

        try:
            aws_db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "./aws_events.db")
            azure_db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "./azure_events.db")

            aws_con, aws_cur = setup_database_connection_and_tables(aws_db_path, 'cloudtrail_events', 'aws')
            azure_con, azure_cur = setup_database_connection_and_tables(azure_db_path, 'azure_events', 'azure')

            process_all_events(config, aws_cur, aws_con, azure_cur, azure_con)

        except Exception as e:
            print(f"\033[91m[!] An error occurred during processing: {e}\033[0m")
            sys.exit(1)
    else:
        print("\033[91m[!] Either provide a config file for event processing or use --export options for exporting.\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()

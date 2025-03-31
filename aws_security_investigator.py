#!/usr/bin/env python3

import boto3
import yaml
import json
from datetime import datetime
import time
import argparse
from collections import defaultdict

def load_config(config_file='config.yaml'):
    """Load configuration from yaml file."""
    try:
        with open(config_file, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"Error loading config: {str(e)}")
        return None

def list_and_select_log_group(logs_client):
    """List available log groups and let user select one."""
    try:
        response = logs_client.describe_log_groups()
        log_groups = [group['logGroupName'] for group in response['logGroups']]
        
        if not log_groups:
            print("No log groups found in the account.")
            return None
            
        print("\nAvailable log groups:")
        for i, group in enumerate(log_groups, 1):
            print(f"{i}. {group}")
            
        while True:
            try:
                choice = int(input("\nSelect a log group number (or 0 to exit): "))
                if choice == 0:
                    return None
                if 1 <= choice <= len(log_groups):
                    return log_groups[choice - 1]
                print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
    except Exception as e:
        print(f"Error listing log groups: {str(e)}")
        return None

def query_cloudwatch_logs(logs_client, log_group, start_time, filter_pattern):
    """Query CloudWatch logs using the specified filter pattern and return structured data."""
    results = {
        'users': set(),
        'roles': set(),
        'groups': set(),
        'ip_addresses': set(),
        'regions': defaultdict(lambda: {
            'ip_addresses': set(),
            'users': set(),
            'roles': set(),
            'groups': set()
        })
    }
    try:
        response = logs_client.filter_log_events(
            logGroupName=log_group,
            startTime=start_time,
            filterPattern=filter_pattern
        )
        
        for event in response.get('events', []):
            try:
                message = json.loads(event['message'])
                user_identity = message.get('userIdentity', {})
                source_ip = message.get('sourceIPAddress', '')
                aws_region = message.get('awsRegion', 'unknown')
                
                # Extract user information
                if 'userName' in user_identity:
                    results['users'].add(user_identity['userName'])
                    results['regions'][aws_region]['users'].add(user_identity['userName'])
                if 'roleArn' in user_identity.get('sessionContext', {}):
                    role = user_identity['sessionContext']['roleArn']
                    results['roles'].add(role)
                    results['regions'][aws_region]['roles'].add(role)
                if 'groupName' in user_identity:
                    results['groups'].add(user_identity['groupName'])
                    results['regions'][aws_region]['groups'].add(user_identity['groupName'])
                
                # Add IP address
                if source_ip:
                    results['ip_addresses'].add(source_ip)
                    results['regions'][aws_region]['ip_addresses'].add(source_ip)
            except json.JSONDecodeError as e:
                print(f"Error parsing log message: {str(e)}")
                continue
            
    except Exception as e:
        print(f"Error querying CloudWatch logs: {str(e)}")
    
    return results

def write_report(all_results, report_file='security_report.txt'):
    """Write the collected results to a report file."""
    with open(report_file, 'w') as f:
        f.write("AWS Security Investigation Report\n")
        f.write("=" * 30 + "\n\n")
        f.write(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Overall summary
        f.write("Overall Summary\n")
        f.write("-" * 15 + "\n")
        f.write(f"Total unique users: {len(all_results['users'])}\n")
        f.write(f"Total unique roles: {len(all_results['roles'])}\n")
        f.write(f"Total unique groups: {len(all_results['groups'])}\n")
        f.write(f"Total unique IP addresses: {len(all_results['ip_addresses'])}\n\n")

        # Details per region
        f.write("Details by Region\n")
        f.write("-" * 15 + "\n")
        for region, data in all_results['regions'].items():
            f.write(f"\nRegion: {region}\n")
            f.write("  IP Addresses:\n")
            for ip in sorted(data['ip_addresses']):
                f.write(f"    - {ip}\n")
            f.write("  Users:\n")
            for user in sorted(data['users']):
                f.write(f"    - {user}\n")
            f.write("  Roles:\n")
            for role in sorted(data['roles']):
                f.write(f"    - {role}\n")
            f.write("  Groups:\n")
            for group in sorted(data['groups']):
                f.write(f"    - {group}\n")

def list_log_groups(logs_client):
    """List available log groups."""
    try:
        response = logs_client.describe_log_groups()
        log_groups = [group['logGroupName'] for group in response['logGroups']]
        
        if not log_groups:
            print("No log groups found in the account.")
            return
            
        print("\nAvailable log groups:")
        for i, group in enumerate(log_groups, 1):
            print(f"{i}. {group}")
            
    except Exception as e:
        print(f"Error listing log groups: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='AWS Security Investigation Tool')
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    parser.add_argument('--type', choices=['iam-denied', 'access-key', 'ip-address', 'list-buckets', 'list-logs', 'all'],
                      help='Type of investigation to perform')
    parser.add_argument('--value', help='Search value for access-key or ip-address')
    parser.add_argument('--days', type=int, default=7, help='Number of days to look back (default: 7)')
    parser.add_argument('--report', default='security_report.txt', help='Path to output report file')
    args = parser.parse_args()

    # Calculate start time based on days
    current_time = int(time.time())
    start_time = current_time - (args.days * 24 * 60 * 60)

    # Initialize results dictionary
    all_results = {
        'users': set(),
        'roles': set(),
        'groups': set(),
        'ip_addresses': set(),
        'regions': defaultdict(lambda: {
            'ip_addresses': set(),
            'users': set(),
            'roles': set(),
            'groups': set()
        })
    }

    # Load configuration
    config = load_config(args.config)
    if not config:
        return

    # Initialize boto3 client
    try:
        logs_client = boto3.client('logs', region_name=config['cloudwatch']['region'])
        
        # Verify log group exists or let user select one
        configured_log_group = config['cloudwatch']['log_group_name']
        try:
            logs_client.describe_log_groups(logGroupNamePrefix=configured_log_group)
            log_group = configured_log_group
        except logs_client.exceptions.ResourceNotFoundException:
            print(f"Log group '{configured_log_group}' not found.")
            log_group = list_and_select_log_group(logs_client)
            if not log_group:
                print("No log group selected. Exiting.")
                return
            
        
        if args.type == 'iam-denied':
            print("\n=== Checking for IAM Access Denied Attempts ===")
            for pattern in config['cloudwatch']['queries']['access_denied']['patterns']:
                print(f"\nSearching for pattern: {pattern}")
                results = query_cloudwatch_logs(
                    logs_client,
                    log_group,
                    start_time,
                    pattern
                )
                # Merge results
                all_results['users'].update(results['users'])
                all_results['roles'].update(results['roles'])
                all_results['groups'].update(results['groups'])
                all_results['ip_addresses'].update(results['ip_addresses'])
                for region, data in results['regions'].items():
                    all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                    all_results['regions'][region]['users'].update(data['users'])
                    all_results['regions'][region]['roles'].update(data['roles'])
                    all_results['regions'][region]['groups'].update(data['groups'])
                
        elif args.type == 'list-logs':
            print("\n=== Listing CloudWatch Log Groups ===")
            list_log_groups(logs_client)
            return
            
        elif args.type == 'access-key':
            key = args.value or config['cloudwatch']['queries']['iam_key_search']['pattern']
            print(f"\n=== Checking for IAM Access Key: {key} ===")
            results = query_cloudwatch_logs(
                logs_client,
                log_group,
                start_time,
                key
            )
            # Merge results
            all_results['users'].update(results['users'])
            all_results['roles'].update(results['roles'])
            all_results['groups'].update(results['groups'])
            all_results['ip_addresses'].update(results['ip_addresses'])
            for region, data in results['regions'].items():
                all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                all_results['regions'][region]['users'].update(data['users'])
                all_results['regions'][region]['roles'].update(data['roles'])
                all_results['regions'][region]['groups'].update(data['groups'])
            
        elif args.type == 'ip-address':
            ip = args.value or config['cloudwatch']['queries']['ip_address_search']['pattern']
            print(f"\n=== Checking for IP Address: {ip} ===")
            results = query_cloudwatch_logs(
                logs_client,
                log_group,
                start_time,
                ip
            )
            # Merge results
            all_results['users'].update(results['users'])
            all_results['roles'].update(results['roles'])
            all_results['groups'].update(results['groups'])
            all_results['ip_addresses'].update(results['ip_addresses'])
            for region, data in results['regions'].items():
                all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                all_results['regions'][region]['users'].update(data['users'])
                all_results['regions'][region]['roles'].update(data['roles'])
                all_results['regions'][region]['groups'].update(data['groups'])
            
        elif args.type == 'list-buckets':
            print("\n=== Checking for ListBuckets Operations ===")
            results = query_cloudwatch_logs(
                logs_client,
                log_group,
                start_time,
                config['cloudwatch']['queries']['list_buckets']['pattern']
            )
            # Merge results
            all_results['users'].update(results['users'])
            all_results['roles'].update(results['roles'])
            all_results['groups'].update(results['groups'])
            all_results['ip_addresses'].update(results['ip_addresses'])
            for region, data in results['regions'].items():
                all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                all_results['regions'][region]['users'].update(data['users'])
                all_results['regions'][region]['roles'].update(data['roles'])
                all_results['regions'][region]['groups'].update(data['groups'])
            
        elif args.type == 'all':
            print("\n=== Running All Available Queries ===")
            
            # Run IAM Denied queries
            print("\n=== Checking for IAM Access Denied Attempts ===")
            for pattern in config['cloudwatch']['queries']['access_denied']['patterns']:
                print(f"\nSearching for pattern: {pattern}")
                results = query_cloudwatch_logs(logs_client, log_group, start_time, pattern)
                # Merge results
                all_results['users'].update(results['users'])
                all_results['roles'].update(results['roles'])
                all_results['groups'].update(results['groups'])
                all_results['ip_addresses'].update(results['ip_addresses'])
                for region, data in results['regions'].items():
                    all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                    all_results['regions'][region]['users'].update(data['users'])
                    all_results['regions'][region]['roles'].update(data['roles'])
                    all_results['regions'][region]['groups'].update(data['groups'])

            # Run Access Key Search
            key = config['cloudwatch']['queries']['iam_key_search']['pattern']
            print(f"\n=== Checking for IAM Access Key: {key} ===")
            results = query_cloudwatch_logs(logs_client, log_group, start_time, key)
            # Merge results
            all_results['users'].update(results['users'])
            all_results['roles'].update(results['roles'])
            all_results['groups'].update(results['groups'])
            all_results['ip_addresses'].update(results['ip_addresses'])
            for region, data in results['regions'].items():
                all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                all_results['regions'][region]['users'].update(data['users'])
                all_results['regions'][region]['roles'].update(data['roles'])
                all_results['regions'][region]['groups'].update(data['groups'])

            # Run IP Address Search
            ip = config['cloudwatch']['queries']['ip_address_search']['pattern']
            print(f"\n=== Checking for IP Address: {ip} ===")
            results = query_cloudwatch_logs(logs_client, log_group, start_time, ip)
            # Merge results
            all_results['users'].update(results['users'])
            all_results['roles'].update(results['roles'])
            all_results['groups'].update(results['groups'])
            all_results['ip_addresses'].update(results['ip_addresses'])
            for region, data in results['regions'].items():
                all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                all_results['regions'][region]['users'].update(data['users'])
                all_results['regions'][region]['roles'].update(data['roles'])
                all_results['regions'][region]['groups'].update(data['groups'])

            # Run List Buckets Search
            print("\n=== Checking for ListBuckets Operations ===")
            results = query_cloudwatch_logs(logs_client, log_group, start_time, config['cloudwatch']['queries']['list_buckets']['pattern'])
            # Merge results
            all_results['users'].update(results['users'])
            all_results['roles'].update(results['roles'])
            all_results['groups'].update(results['groups'])
            all_results['ip_addresses'].update(results['ip_addresses'])
            for region, data in results['regions'].items():
                all_results['regions'][region]['ip_addresses'].update(data['ip_addresses'])
                all_results['regions'][region]['users'].update(data['users'])
                all_results['regions'][region]['roles'].update(data['roles'])
                all_results['regions'][region]['groups'].update(data['groups'])

        else:
            print("Please specify a valid investigation type using --type")
            parser.print_help()
            return

        # Write the report
        write_report(all_results, args.report)
        print(f"\nReport has been written to {args.report}")
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
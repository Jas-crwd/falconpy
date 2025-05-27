from falconpy import FirewallManagement, FirewallPolicies, HostGroup
from argparse import ArgumentParser, RawTextHelpFormatter
import os
import pandas as pd

class URLFirewallManager:
    def __init__(self, client_id, client_secret):
        self.csv_file = 'output.csv'
        self.df = None
        self.mgmt = FirewallManagement(client_id=client_id, client_secret=client_secret)
        self.policies = FirewallPolicies(client_id=client_id, client_secret=client_secret)
        self.host_groups = HostGroup(client_id=client_id, client_secret=client_secret)

    def load_csv(self):
        try:
            self.df = pd.read_csv(self.csv_file)
            print(f"CSV columns: {self.df.columns.tolist()}")
            return True
        except Exception as e:
            print(f"Error loading CSV: {str(e)}")
            return False

    def display_categories(self):
        print("\nAvailable Categories:")
        for i, category in enumerate(self.df['category'], 1):
            print(f"{i}. {category}")

    def get_user_selection(self):
        while True:
            try:
                user_input = input("\nEnter category numbers (separated by commas): ")
                selected_indices = [int(x.strip()) - 1 for x in user_input.split(',')]
                selected_categories = self.df['category'].iloc[selected_indices].tolist()
                return selected_categories
            except (ValueError, IndexError):
                print("Invalid input. Please enter valid category numbers.")

    def get_blocked_urls(self, selected_categories):
        try:
            url_column = 'url'
            if url_column not in self.df.columns:
                possible_names = ['url', 'urls', 'URL', 'URLs']
                for name in possible_names:
                    if name in self.df.columns:
                        url_column = name
                        break
                else:
                    raise KeyError(f"Could not find URL column. Available columns: {self.df.columns.tolist()}")

            urls = self.df[self.df['category'].isin(selected_categories)][url_column].tolist()
            urls_string = ";".join([
                url.strip() 
                for url_list in urls 
                for url in (url_list.split(',') if isinstance(url_list, str) else []) 
                if url.strip()
            ])
            
            if urls_string.endswith(';'):
                urls_string = urls_string[:-1]
                
            return urls_string
        except Exception as e:
            print(f"Error processing URLs: {str(e)}")
            return ""

    def get_host_groups(self):
        """List all available host groups and let user select one."""
        print("\nFetching host groups...")
        try:
            response = self.host_groups.query_host_groups()
            if response["status_code"] == 200:
                groups = response["body"]["resources"]
                groups_details = self.host_groups.get_host_groups(ids=groups)
                
                print("\nAvailable Host Groups:")
                print("-" * 50)
                host_groups = {}
                for i, group in enumerate(groups_details["body"]["resources"], 1):
                    host_groups[i] = {"id": group["id"], "name": group["name"]}
                    print(f"{i}. {group['name']}")
                print("-" * 50)

                while True:
                    try:
                        choice = int(input("\nSelect host group number: "))
                        if choice in host_groups:
                            return host_groups[choice]
                    except ValueError:
                        pass
                    print("Invalid selection. Please try again.")
            else:
                print("Failed to retrieve host groups!")
                return None
        except Exception as e:
            print(f"Error getting host groups: {str(e)}")
            return None


    def create_rule_group(self, group_name, blocked_urls):
        """Create a new rule group with domain blocking rules."""
        print("\n\t\tCREATING NEW RULE GROUP...")

        RULES = {
                    "action": "DENY",
                    "address_family": "NONE",
                    "description": "Domain blocking rule",
                    "direction": "OUT",
                    "enabled": True,
                    "fields": [
                        {
                            "name": "image_name",
                            "value": "",
                            "type": "windows_path",
                            "values": []
                        }
                    ],
                    "fqdn_enabled": True,
                    "fqdn": blocked_urls,  # Using the blocked URLs here
                    "icmp": {"icmp_code": "", "icmp_type": ""},
                    "local_address": [{"address": "*", "netmask": 0}],
                    #"local_port": [{"end": 65535, "start": 1}],
                    "log": False,
                    "monitor": {"count": "1", "period_ms": "1000000"},
                    "name": "rule1",
                    "protocol": "*",
                    "remote_address": [{"address": "*", "netmask": 0}],
                    #"remote_port": [{"end": 65535, "start": 1}],
                    "temp_id": "1"
                }

        response = self.mgmt.create_rule_group(
            description="Domain blocking rule group",
            enabled=True,
            name=group_name,
            platform="windows",
            rules=RULES
        )
        print(response)
        rule_group_id = response["body"]["resources"][0]
        print(f"API Responded: {response['status_code']}")
        print(response["body"])
        print("New Rule Group ID: "+rule_group_id)
        return rule_group_id

    def create_firewall_policy(self, policy_name, rule_group_id, host_group_id):
        """Create a firewall policy using the correct format."""
        print("\nCreating firewall policy...")
        
        try:
            response = self.policies.create_policies(
                description="Firewall policy for URL blocking",
                name=policy_name,
                platform_name="Windows"
            )

            if response["status_code"] == 201:
                policy_id = response["body"]["resources"][0]["id"]
                print(f"Successfully created policy: {policy_name}")
                print(f"Policy ID: {policy_id}")

                # Update the policy with rule group and settings
                self.policies.perform_action(action_name="enable",ids=policy_id)
                self.policies.perform_action(action_name="add-host-group",group_id=host_group_id,ids=policy_id)
                update_response = self.mgmt.update_policy_container(
                    default_inbound="ALLOW",
                    default_outbound="ALLOW",
                    platform_id="windows",
                    enforce=True,
                    local_logging=True,
                    is_default_policy=False,
                    test_mode=False,
                    rule_group_ids=rule_group_id,
                    policy_id=policy_id
                )

                if update_response["status_code"] == 200:
                    print("Successfully updated policy with rule group")
                    return policy_id
                else:
                    print(f"Failed to update policy: {update_response['body'].get('errors', 'Unknown error')}")
                    return None

            else:
                print(f"Failed to create policy: {response['body'].get('errors', 'Unknown error')}")
                return None

        except Exception as e:
            print(f"Error creating/updating policy: {str(e)}")
            return None

    def get_rule_group_details(self, group_id):
        """Get details of the created rule group."""
        print("\n\t\tGETTING RULE GROUP DETAILS...")

        response = self.mgmt.get_rule_groups(group_id)
        if response["status_code"] == 200:
            print(f"API Responded: {response['status_code']}")
            print(response["body"])
            return response["body"]["resources"][0].get("tracking"), response["body"]["resources"][0].get("rule_ids")
        return None, None

def parse_command_line():
    """Parse command line arguments."""
    parser = ArgumentParser(description="Create Firewall Rules to Block Domains")
    parser.add_argument("-k", "--key",
                       help="Falcon API Client ID",
                       default=os.getenv("FALCON_CLIENT_ID"))
    parser.add_argument("-s", "--secret",
                       help="Falcon API Client secret",
                       default=os.getenv("FALCON_CLIENT_SECRET"))
    
    parsed = parser.parse_args()
    if not parsed.key or not parsed.secret:
        parser.error("You must provide valid API credentials ('-k' and '-s')")
    
    return parsed

def main():
    # Get command line arguments
    args = parse_command_line()
    
    # Initialize URL Firewall Manager
    manager = URLFirewallManager(args.key, args.secret)

    # Load CSV data
    if not manager.load_csv():
        return

    # Get host group selection
    host_group = manager.get_host_groups()
    if not host_group:
        return

    # Display categories and get selection
    manager.display_categories()
    selected_categories = manager.get_user_selection()

    # Get blocked URLs
    blocked_urls = manager.get_blocked_urls(selected_categories)
    if not blocked_urls:
        print("No URLs found to block!")
        return
    
    print("\nURLs to be blocked:", blocked_urls)

    # Get rule group name
    print("\nEnter the name for the rule group:")
    group_name = input().strip()

    if not group_name:
        print("Rule group name cannot be empty!")
        return

    # Get policy name
    print("\nEnter the name for the firewall policy:")
    policy_name = input().strip()

    if not policy_name:
        print("Policy name cannot be empty!")
        return

    # Create rule group
    rule_group_id = manager.create_rule_group(group_name, blocked_urls)
    
    if rule_group_id:
        # Create and update firewall policy
        policy_id = manager.create_firewall_policy(
            policy_name, 
            rule_group_id, 
            host_group["id"]
        )
        
        if policy_id:
            print("\nFinal Configuration:")
            print(f"Rule Group ID: {rule_group_id}")
            print(f"Policy ID: {policy_id}")
            print(f"Host Group: {host_group['name']} ({host_group['id']})")
            
            # Get and display final rule group details
            tracking, rule_ids = manager.get_rule_group_details(rule_group_id)
            if tracking:
                print(f"Tracking Number: {tracking}")
                print(f"Rule IDs: {rule_ids}")
        else:
            print("Failed to complete policy configuration")

if __name__ == "__main__":
    main()





# from crowdstrike.foundry.function import Function, Request, Response
# from falconpy import FirewallManagement, FirewallPolicies, HostGroup
# import pandas as pd
# import os
# import json
# from argparse import ArgumentParser, RawTextHelpFormatter

# func = Function.instance()

# class URLFirewallManager:
#     def __init__(self, client_id, client_secret):
#         self.csv_file = 'output.csv'
#         self.df = None
#         self.mgmt = FirewallManagement(client_id=client_id, client_secret=client_secret)
#         self.policies = FirewallPolicies(client_id=client_id, client_secret=client_secret)
#         self.host_groups = HostGroup(client_id=client_id, client_secret=client_secret)

#     def load_csv(self):
#         try:
#             self.df = pd.read_csv(self.csv_file)
#             print("csv loaded")
#             return True
#         except Exception as e:
#             print("csv no loaded")
#             return False

#     def get_blocked_urls(self, category):
#         try:
#             url_column = 'url'
#             if url_column not in self.df.columns:
#                 possible_names = ['url', 'urls', 'URL', 'URLs']
#                 for name in possible_names:
#                     if name in self.df.columns:
#                         url_column = name
#                         break
#                 else:
#                     raise KeyError(f"URL column not found")

#             urls = self.df[self.df['category'] == category][url_column].tolist()
#             urls_string = ";".join([
#                 url.strip() 
#                 for url_list in urls 
#                 for url in (url_list.split(',') if isinstance(url_list, str) else []) 
#                 if url.strip()
#             ])
            
#             return urls_string.rstrip(';')
#         except Exception as e:
#             raise Exception(f"Error processing URLs: {str(e)}")

#     def create_rule_group(self, group_name, blocked_urls):
#         rules = {
#             "action": "DENY",
#             "address_family": "NONE",
#             "description": "Domain blocking rule",
#             "direction": "OUT",
#             "enabled": True,
#             "fields": [
#                 {
#                     "name": "image_name",
#                     "value": "",
#                     "type": "windows_path",
#                     "values": []
#                 }
#             ],
#             "fqdn_enabled": True,
#             "fqdn": blocked_urls,
#             "icmp": {"icmp_code": "", "icmp_type": ""},
#             "local_address": [{"address": "*", "netmask": 0}],
#             "log": False,
#             "monitor": {"count": "1", "period_ms": "1000000"},
#             "name": "rule1",
#             "protocol": "*",
#             "remote_address": [{"address": "*", "netmask": 0}],
#             "temp_id": "1"
#         }

#         response = self.mgmt.create_rule_group(
#             description="Domain blocking rule group",
#             enabled=True,
#             name=group_name,
#             platform="windows",
#             rules=rules
#         )
        
#         if response["status_code"] != 200:
#             raise Exception(f"Failed to create rule group: {response['body']}")
            
#         return response["body"]["resources"][0]

# @func.handler(method='POST', path='/create-rule')
# def create_rule(request: Request) -> Response:
#     try:
#         print("sid")
#         # Validate request body
#         if not request.body or 'category' not in request.body:
#             return Response(
#                 code=400,
#                 body={"error": "Category is required in request body"}
#             )

#         category = request.body['category']
#         print(category)
#         group_name = request.body.get('group_name', f"Rule_Group_{category}")
#         print(group_name)

#         # Initialize manager
#         args = parse_command_line()
#         manager = URLFirewallManager(args.key, args.secret)
#         # print(request.access_token)

#         # Load CSV
#         if not manager.load_csv():
#             return Response(
#                 code=500,
#                 body={"error": "Failed to load CSV file"}
#             )

#         #Get blocked URLs for category
#         blocked_urls = manager.get_blocked_urls(category)
#         if not blocked_urls:
#             return Response(
#                 code=404,
#                 body={"error": f"No URLs found for category: {category}"}
#             )

#         # Create rule group
#         rule_group_id = manager.create_rule_group(group_name, blocked_urls)

#         return Response(
#             code=200,
#             body={
#                 "status": "success",
#                 "rule_group_id": rule_group_id,
#                 "group_name": group_name,
#                 "category": category,
#                 "blocked_urls": blocked_urls
#             }
#         )

#     except Exception as e:
#         return Response(
#             code=500,
#             body={"error": str(e)}
#         )
    
# def parse_command_line():
#     """Parse command line arguments."""
#     parser = ArgumentParser(description="Create Firewall Rules to Block Domains")
#     parser.add_argument("-k", "--key",
#                        help="Falcon API Client ID",
#                        default=os.getenv("FALCON_CLIENT_ID"))
#     parser.add_argument("-s", "--secret",
#                        help="Falcon API Client secret",
#                        default=os.getenv("FALCON_CLIENT_SECRET"))
    
#     parsed = parser.parse_args()
#     if not parsed.key or not parsed.secret:
#         parser.error("You must provide valid API credentials ('-k' and '-s')")
    
#     return parsed

# if __name__ == '__main__':
#     func.run()

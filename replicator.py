from collections import namedtuple
from datetime import datetime
import configparser
from getpass import getpass
import json
from math import ceil
import os
from time import sleep

import click
import requests

# TODO: Persist policy enabled state when copying between environments (ticket opened)
# TODO: Update and test custom IOC code with new IOC manager endpoint
# TODO: More robust error handling for API query functions in general.
# TODO: There are slight numeric discrepancies in the number of rules assigned to a group
#  Investigate source of discrepancies
# TODO: Investigate unexpected 405 (method not allowed) error with ioa_exclusions_write_exclusion() function
#  (ticket opened)
# TODO: Can't overwrite existing policies, so in order to copy the default policies from one environment to the other,
#  we change 'platform_default' to 'platform_default_clone'. Might be able to work this in as a request.patch to the
#  existing platform default in target environment.
# TODO: Make better use of click's builtin command line features for progress bar displays, user prompts, etc.

BASE_URL = 'https://api.crowdstrike.com'
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], max_content_width=200)


###############
# Host Groups #
###############

class HostGroupDynamic:
    def __init__(self, assignment_rule, description, group_type, name):
        self.assignment_rule = assignment_rule
        self.description = description
        self.group_type = group_type
        self.name = name

    def to_json(self):
        return {'resources': [self.__dict__]}


# The API rejects Host Groups with a group type of "static" and an assignment rule
# (even though it returns assignment rules with static groups)
class HostGroupStatic:
    def __init__(self, description, group_type, name):
        self.description = description
        self.group_type = group_type
        self.name = name

    def to_json(self):
        return {'resources': [self.__dict__]}


class HostGroups:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.group_ids = self.get_ids()
        self.groups = None

    def get_ids(self):
        """Search for Host Groups in your environment.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/queryHostGroups

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing host group IDs.
        """

        endpoint = '/devices/queries/host-groups/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)
        resources = resp.json()['resources']

        return resources

    def get_groups(self):
        """Retrieve a set of Host Groups by specifying their IDs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/getHostGroups

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of strings representing host group IDs.
        Returns: List of strings representing host group IDs.
        """

        # This call can be time-consuming / resource intensive
        # because some groups return all assigned members, resulting in huge JSON blobs.

        self.groups = []
        endpoint = '/devices/entities/host-groups/v1?ids='
        for group_id in self.group_ids:
            resp = requests.get(BASE_URL + endpoint + group_id, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)
            resources = resp.json()['resources']
            try:
                assignment_rule = resources[0]['assignment_rule']
            except:
                assignment_rule = None
            description = resources[0]['description']
            group_type = resources[0]['group_type']
            name = resources[0]['name']

            # The API rejects host groups with a "static" group_type but including an "assignment_value"
            # (even though that's what it returns)
            # So create a different type depending on group_type but add both to the same list
            if group_type == 'dynamic':
                group = HostGroupDynamic(assignment_rule=assignment_rule,
                                         description=description,
                                         group_type=group_type,
                                         name=name)
                self.groups.append(group)

            elif group_type == 'static':
                group = HostGroupStatic(description=description,
                                        group_type=group_type,
                                        name=name)
                self.groups.append(group)

    def write_groups(self):
        """Create Host Groups by specifying details about the group to create.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/createHostGroups

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of objects representing Host Groups.
        Returns:
        """

        endpoint = '/devices/entities/host-groups/v1'
        for group in self.groups:
            resp = requests.post(BASE_URL + endpoint, json=group.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_groups(self):
        endpoint = '/devices/entities/host-groups/v1?ids='
        for group_id in self.group_ids:
            resp = requests.delete(BASE_URL + endpoint + group_id, headers=self.target_headers, proxies=self.proxies,
                                   verify=self.verify)
            handle_response(resp)


####################
# Custom IOA rules #
####################

class CustomIOARuleGroup:
    def __init__(self, name, description, platform):
        self.name = name
        self.description = description
        self.platform = platform

    def to_json(self):
        # Serialize the attributes of the object in the JSON format expected by the API
        return self.__dict__


class CustomIOARule:
    def __init__(self, description, disposition_id, field_values, name, pattern_severity, rulegroup_id, ruletype_id):
        self.description = description
        self.disposition_id = disposition_id
        self.field_values = field_values
        self.name = name
        self.pattern_severity = pattern_severity
        self.rulegroup_id = rulegroup_id
        self.ruletype_id = ruletype_id

    def to_json(self):
        return self.__dict__


class CustomIOAs:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.rule_group_ids = self.get_ids()
        self.used_rule_group_ids = []
        self.rule_groups = []
        self.rules = []
        self.target_rule_group_ids = []

    def get_ids(self):
        """Finds all rule group IDs matching the query with optional filter.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/custom-ioa/query-rule-groups

        Takes: Dictionary representing headers, including valid authentication token
        Returns: List of strings representing rule group IDs.
        """

        endpoint = '/ioarules/queries/rule-groups/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)
        rule_group_ids = resp.json()['resources']
        return rule_group_ids

    def get_rules(self):
        """Get all rules associated with a specific rule group ID.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/custom-ioa/get-rule-types

        Takes: Dictionary representing headers, including valid authentication token.
               List representing rule group IDs.
        Returns: A list of strings representing rule group IDs that are used (have associated rules).
                 A list of objects representing rule groups.
                 A list of objects representing rules.
        """

        endpoint = '/ioarules/entities/rule-groups/v1?ids='
        for rgid in self.rule_group_ids:
            resp = requests.get(BASE_URL + endpoint + rgid, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)
            resources = resp.json()['resources']

            # It's possible to have a rule group without any rules in it
            # If we avoid saving those empty rule groups it simplifies the logic of associating rules with rule groups
            if resources[0]['rules']:
                rule_group_id = resources[0]['id']
                self.used_rule_group_ids.append(rule_group_id)  # Save rule group IDs that have rules in them

                rule_group_name = resources[0]['name']
                rule_group_description = resources[0]['description']
                rule_group_platform = resources[0]['platform']

                rule_group = CustomIOARuleGroup(name=rule_group_name,
                                                description=rule_group_description,
                                                platform=rule_group_platform)
                self.rule_groups.append(rule_group)

                prod_rules = resources[0]['rules']
                for prod_rule in prod_rules:
                    rule_description = prod_rule['description']
                    rule_disposition_id = prod_rule['disposition_id']
                    rule_field_values = prod_rule['field_values']
                    rule_name = prod_rule['name']
                    rule_pattern_severity = prod_rule['pattern_severity']
                    rule_rulegroup_id = rule_group_id  # Save the original rule group ID for re-mapping
                    rule_ruletype_id = prod_rule['ruletype_id']

                    rule = CustomIOARule(description=rule_description,
                                         disposition_id=rule_disposition_id,
                                         field_values=rule_field_values,
                                         name=rule_name,
                                         pattern_severity=rule_pattern_severity,
                                         rulegroup_id=rule_rulegroup_id,
                                         ruletype_id=rule_ruletype_id)

                    self.rules.append(rule)

    def write_rule_groups(self):
        """Create a rule group for a platform with a name and an optional description. Returns the rule group.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/custom-ioa/create-rule-group

        Takes: Dictionary representing headers, including valid authentication token.
               List of CustomIOARuleGroup objects representing rule groups.
        Returns: List of new rule group IDs necessary for adding rules to rule groups.
        """

        # Write new rule groups to hold replicated rules; retrieve the rule group ID assigned by CrowdStrike
        endpoint = '/ioarules/entities/rule-groups/v1'
        for rule_group in self.rule_groups:
            resp = requests.post(BASE_URL + endpoint, json=rule_group.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)
            if resp.status_code == 201:
                self.target_rule_group_ids.append(resp.json()['resources'][0]['id'])

    def write_rules(self):
        """Create a rule within a rule group. Returns the rule.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/custom-ioa/update-rules

        Takes: Dictionary representing headers, including valid authentication token
               List of objects representing IOA rules.
        Returns: Nothing.
        """

        endpoint = '/ioarules/entities/rules/v1'
        # Replace the original (source) rule group IDs with the new (target) rule group IDs
        source_to_target_map = list(zip(self.used_rule_group_ids, self.target_rule_group_ids))
        # Assign the rules the correct target environment rule group ID
        for rule in self.rules:
            for i in range(len(source_to_target_map)):
                rule.rulegroup_id = rule.rulegroup_id.replace(source_to_target_map[i][0],
                                                              source_to_target_map[i][1])

        for rule in self.rules:
            resp = requests.post(BASE_URL + endpoint, json=rule.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_rule_groups(self):
        """Delete rule groups by ID
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/custom-ioa/delete-rule-groupsMixin0
        """

        endpoint = '/ioarules/entities/rule-groups/v1?ids='
        for rule_group_id in self.rule_group_ids:
            resp = requests.delete(BASE_URL + endpoint + rule_group_id, headers=self.target_headers,
                                   proxies=self.proxies, verify=self.verify)
            handle_response(resp)


###########################
# Device control policies #
###########################

class DevicePolicy:
    def __init__(self, name, description, enabled, platform_name, settings):
        self.name = name
        self.description = description
        self.enabled = enabled
        self.platform_name = platform_name
        self.settings = settings

    def to_json(self):
        return {'resources': [self.__dict__]}


class DeviceControlPolicies:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.policy_ids = self.get_ids()
        self.policies = None

    def get_ids(self):
        """Search for Device Control Policies in your environment by providing an FQL filter and paging details.
        Returns a set of Device Control Policy IDs which match the filter criteria
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/device-control-policies/queryDeviceControlPolicies

        Takes: Dictionary representing headers, including valid authentication token.
        Returns: List of strings representing device control policy IDs.
        """

        endpoint = '/policy/queries/device-control/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)

        if resp.status_code == 200:
            device_control_policies = resp.json()['resources']
            return device_control_policies

    def get_policies(self):
        """Retrieve a set of Device Control Policies by specifying their IDs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/device-control-policies/getDeviceControlPolicies

        Takes: Dictionary representing headers, including valid authentication token.
               List of strings representing device control policy IDs.
        Returns: List of DevicePolicy objects with to_json method for JSON serialization.
        """

        endpoint = '/policy/entities/device-control/v1?ids='
        self.policies = []
        for policy in self.policy_ids:
            resp = requests.get(BASE_URL + endpoint + policy, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)

            json_resp = json.loads(resp.content.decode())['resources'][0]
            name = json_resp['name']
            description = json_resp['description']
            enabled = json_resp['enabled']
            platform_name = json_resp['platform_name']
            settings = json_resp['settings']

            device_control_policy = DevicePolicy(name=name,
                                                 description=description,
                                                 enabled=enabled,
                                                 platform_name=platform_name,
                                                 settings=settings)

            self.policies.append(device_control_policy)

    def write_policies(self):
        """Write the Device Control Policies from production environment in the test environment.

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: Nothing.
        """

        endpoint = '/policy/entities/device-control/v1'
        for policy in self.policies:
            resp = requests.post(BASE_URL + endpoint, json=policy.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_policies(self):
        endpoint = '/policy/entities/device-control/v1?ids='
        for policy_id in self.policy_ids:
            resp = requests.delete(BASE_URL + endpoint + policy_id, headers=self.target_headers, proxies=self.proxies,
                                   verify=self.verify)
            handle_response(resp)


###################################
# IOCs (Indicators of Compromise) #
###################################

class IOC:
    def __init__(self, action, applied_globally, metadata, platforms, severity, ioc_type, value):
        self.action = action
        self.applied_globally = applied_globally
        self.metadata = metadata
        self.platforms = platforms
        self.severity = severity
        self.ioc_type = ioc_type
        self.value = value

    def to_json(self):
        return {'resources': [self.__dict__]}


class CustomIOCs:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.ioc_ids = self.get_ids()
        self.iocs = None

    def get_ids(self):
        """Search the custom IOCs in your customer account.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.get.v1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing custom IOC IDs.
        """

        endpoint = '/iocs/queries/indicators/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies,
                            verify=self.verify)
        handle_response(resp)

        if resp.status_code == 200:
            resources = json.loads(resp.content.decode())['resources']
            return resources
        return False

    def get_iocs(self):
        """Get an IOC by providing a type and value.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.search.v1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing IOC IDs.
        """

        self.iocs = []
        endpoint = '/iocs/entities/indicators/v1?ids='
        for ioc_id in self.ioc_ids:
            resp = requests.get(BASE_URL + endpoint + ioc_id, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)
            resources = resp.json()['resources']

            action = resources[0]['action']
            applied_globally = resources[0]['applied_globally']
            try:
                metadata = resources[0]['metadata']
            except:
                metadata = []
            platforms = resources[0]['platforms']
            severity = resources[0]['severity']
            ioc_type = resources[0]['type']
            value = resources[0]['value']

            ioc = IOC(action=action,
                      applied_globally=applied_globally,
                      metadata=metadata,
                      platforms=platforms,
                      severity=severity,
                      ioc_type=ioc_type,
                      value=value)

            self.iocs.append(ioc)

    def write_iocs(self):
        """Write IOCs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.create.v1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: Nothing.
        """

        endpoint = '/iocs/entities/indicators/v1'
        for ioc in self.iocs:
            resp = requests.post(BASE_URL + endpoint, json=ioc.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_iocs(self):
        """Delete IOCs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.delete.v1
        """

        endpoint = '/iocs/entities/indicators/v1?ids='
        for ioc_id in self.ioc_ids:
            resp = requests.delete(BASE_URL + endpoint + ioc_id, headers=self.target_headers, proxies=self.proxies,
                                   verify=self.verify)
            handle_response(resp)


###############################
# Machine Learning Exclusions #
###############################

class MachineLearningExclusion:
    def __init__(self, excluded_from, regexp_value, value):
        self.excluded_from = excluded_from
        self.groups = ["all"]  # Currently defaulting to "all" since groups in different environments may be different
        self.regexp_value = regexp_value
        self.value = value

    def to_json(self):
        return self.__dict__


class MachineLearningExclusions:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.exclusion_ids = self.get_ids()
        self.exclusions = None

    def get_ids(self):
        """Search for ML exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/queryMLExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing machine learning exclusion IDs.
        """

        endpoint = '/policy/queries/ml-exclusions/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)

        if resp.status_code == 200:
            resources = json.loads(resp.content.decode())['resources']
            return resources
        return False

    def get_exclusions(self):
        """Get a set of ML Exclusions by specifying their IDs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/getMLExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of strings representing machine learning exclusion IDs.
        Returns: List of objects representing Machine Learning Exclusions.
        """

        self.exclusions = []
        endpoint = '/policy/entities/ml-exclusions/v1?ids='
        for ml_id in self.exclusion_ids:
            resp = requests.get(BASE_URL + endpoint + ml_id, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)
            resources = json.loads(resp.content.decode())['resources'][0]
            excluded_from = resources['excluded_from']
            regexp_value = resources['regexp_value']
            value = resources['value']

            machine_learning_exclusion = MachineLearningExclusion(excluded_from=excluded_from,
                                                                  regexp_value=regexp_value,
                                                                  value=value)
            self.exclusions.append(machine_learning_exclusion)
        return self.exclusions

    def write_exclusions(self):
        """Create the ML exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/createMLExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of objects representing machine learning exclusions.
        Returns: Nothing.
        """

        endpoint = '/policy/entities/ml-exclusions/v1'
        for exclusion in self.exclusions:
            resp = requests.post(BASE_URL + endpoint, json=exclusion.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_exclusions(self):
        """Delete ML exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/deleteMLExclusionsV1
        """

        endpoint = '/policy/entities/ml-exclusions/v1?ids='
        for exclusion_id in self.exclusion_ids:
            resp = requests.delete(BASE_URL + endpoint + exclusion_id, headers=self.target_headers,
                                   proxies=self.proxies, verify=self.verify)
            handle_response(resp)


#######################
# Prevention policies #
#######################

class PreventionPolicy:
    def __init__(self, description, enabled, platform_name, name, settings):
        self.description = description
        self.enabled = enabled
        self.platform_name = platform_name
        self.name = name
        self.settings = settings

    def to_json(self):
        return {'resources': [self.__dict__]}


class PreventionPolicies:
    def __init__(self, source_token=None, target_token=None, proxy=None, enable=False, disable=False):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.enable = enable
        self.disable = disable
        self.policy_ids = self.get_ids()
        self.policies_to_enable = []
        self.policies = []

    def get_ids(self):
        """Get Prevention Policy IDs
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies/queryPreventionPolicies
        """

        endpoint = '/policy/queries/prevention/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)

        if resp.status_code == 200:
            return resp.json()['resources']

    def get_policies(self):
        """Search for Prevention Policies in your environment.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies/queryCombinedPreventionPolicies

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of objects representing prevention policies.
        """

        endpoint = '/policy/entities/prevention/v1?ids='
        for policy_id in self.policy_ids:
            resp = requests.get(BASE_URL + endpoint + policy_id, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)

            if resp.status_code == 200:
                resources = json.loads(resp.content.decode())['resources']
                for resource in resources:
                    description = resource['description']
                    enabled = resource['enabled']
                    platform_name = resource['platform_name']
                    name = resource['name']
                    # Can't overwrite policies, but also can't delete "default" policies
                    # So as a kluge rename the default policy before writing it to target environment
                    if description == 'Platform default policy':
                        name = 'Platform default policy - clone'
                    if name == 'platform_default':
                        name = 'platform_default_clone'

                    # Each prevention policy, when retrieved via, API has a set number of 'settings' that correspond to
                    # categorized sensor capabilities for that platform.
                    # For example, Windows has 12 settings, including "Enhanced Visibility", "Firmware",
                    # "Cloud Machine Learning", etc.
                    # We probably only need the non-default settings, but I don't know how to determine which
                    # of the returned settings have been set by operators versus which are default.
                    # This approach loops through all the category settings and combines into one list for writing.
                    all_settings = []
                    for entry in resource['prevention_settings']:
                        all_settings += entry['settings']

                    prevention_policy = PreventionPolicy(description=description,
                                                         enabled=enabled,
                                                         platform_name=platform_name,
                                                         name=name,
                                                         settings=all_settings)

                    self.policies.append(prevention_policy)

    def write_policies(self):
        """Create Prevention Policies by specifying details about the policy to create.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies/createPreventionPolicies

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of objects representing prevention policies.
        Returns: Nothing.
        """

        endpoint = '/policy/entities/prevention/v1'
        for policy in self.policies:
            resp = requests.post(BASE_URL + endpoint, json=policy.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

            if resp.status_code == 201 and policy.enabled:
                # If response is successful store returned ID for any subsequent modifications
                self.policies_to_enable.append(resp.json()['resources'][0]['id'])

        if self.enable:
            self.enable_policies()

    def enable_policies(self):
        """Enable policies that have been written by the script that were enabled in the source environment.
        By default, polices created by the API are left in a
        "disabled" state. Enabling those policies requries a separate API call.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies/performPreventionPoliciesAction
        """

        endpoint = '/policy/entities/prevention-actions/v1?action_name=enable'
        request = {
                      "action_parameters": [
                        {
                          "name": "enable policies",
                          "value": "enable"
                        }
                      ],
                      "ids": self.policies_to_enable
                    }
        resp = requests.post(BASE_URL + endpoint, headers=self.target_headers, json=request, proxies=self.proxies,
                             verify=self.verify)
        handle_response(resp)

    def disable_policies(self):
        """Disable policies to allow removing them. Policies must be disabled before being deleted.
        You cannot disable / delete default policies. If an API call to disable policies includes policy IDs for default
        policies, it will fail (response 400), and no policies will be disabled. Requests to disable policies must
        reference specific non-default policy IDs.


        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies/performPreventionPoliciesAction
        """

        # Retrieve policies to build a list of non-default policies
        self.get_policies()
        # Map policy IDs to their policies
        ids_to_policies = list(zip(self.policy_ids, self.policies))
        # This method identifies default policies based on their description which may be fickle.
        policies_to_disable = [x[0] for x in ids_to_policies if not x[1].description == 'Platform default policy']
        endpoint = '/policy/entities/prevention-actions/v1?action_name=disable'
        request = {
            "action_parameters": [
                {
                    "name": "disable policies",
                    "value": "disable"
                }
            ],
            "ids": policies_to_disable
        }
        resp = requests.post(BASE_URL + endpoint, headers=self.target_headers, json=request, proxies=self.proxies,
                             verify=self.verify)
        handle_response(resp)

    def delete_policies(self):
        """Delete prevention policies.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies/deletePreventionPolicies
        """

        if self.disable:
            self.disable_policies()

        endpoint = '/policy/entities/prevention/v1?ids='
        for policy_id in self.policy_ids:
            resp = requests.delete(BASE_URL + endpoint + policy_id, headers=self.target_headers, proxies=self.proxies,
                                   verify=self.verify)
            handle_response(resp)


##################
# IOA Exclusions #
##################

class IOAExclusionGroup:
    def __init__(self, cl_regex, description, detection_json, ifn_regex, name, pattern_id, pattern_name, groups=None):
        self.cl_regex = cl_regex
        self.description = description
        self.detection_json = detection_json
        if groups is None:
            self.groups = []
        self.ifn_regex = ifn_regex
        self.name = name
        self.pattern_id = pattern_id
        self.pattern_name = pattern_name

    def to_json(self):
        return self.__dict__


class IOAExclusions:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.exclusion_ids = self.get_ids()
        self.exclusions = []

    def get_ids(self):
        """Get a list of Indicators of Attack exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/queryIOAExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing IOA exclusion IDs.
        """
        endpoint = '/policy/queries/ioa-exclusions/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)
        resources = resp.json()['resources']
        return resources

    def get_exclusions(self):
        """Get a set of IOA exclusions by specifying their IDs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/getIOAExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of strings representing IOA exclusion IDs.
        Returns: List of objects representing IOA exclusion groups.
        """

        endpoint = '/policy/entities/ioa-exclusions/v1?ids='
        for exclusion in self.exclusion_ids:
            resp = requests.get(BASE_URL + endpoint + exclusion, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)
            resources = resp.json()['resources']

            # Assuming that this always returns a list of len() = 1
            cl_regex = resources[0]['cl_regex']
            description = resources[0]['description']
            detection_json = resources[0]['detection_json']
            ifn_regex = resources[0]['ifn_regex']
            name = resources[0]['name']
            pattern_id = resources[0]['pattern_id']
            pattern_name = resources[0]['pattern_name']

            ioa_exclusion_group = IOAExclusionGroup(cl_regex=cl_regex,
                                                    description=description,
                                                    detection_json=detection_json,
                                                    ifn_regex=ifn_regex,
                                                    name=name,
                                                    pattern_id=pattern_id,
                                                    pattern_name=pattern_name)

            self.exclusions.append(ioa_exclusion_group)

    def write_exclusions(self):
        """Create the IOA exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/createIOAExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of objects representing IOA exclusion groups.
        Returns: Nothing.
        """

        # Currently receiving an error code 405 (method not allowed) on this endpoint.

        endpoint = '/policy/entities/ioa-exclusions/v1'
        for exclusion in self.exclusions:
            resp = requests.post(BASE_URL + endpoint, json=exclusion.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_exclusions(self):
        """Delete IOA exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/deleteIOAExclusionsV1
        """

        endpoint = '/policy/entities/ioa-exclusions/v1'
        for exclusion_id in self.exclusion_ids:
            resp = requests.delete(BASE_URL + endpoint + exclusion_id, proxies=self.proxies, verify=self.verify)
            handle_response(resp)


##########################
# Sensor update policies #
##########################

class SensorUpdatePolicy:
    def __init__(self, description, name, platform_name, settings):
        self.description = description
        self.name = name
        self.platform_name = platform_name
        self.settings = settings

    def to_json(self):
        return {'resources': [self.__dict__]}


class SensorUpdatePolicies:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.policy_ids = self.get_ids()
        self.policies = []

    def get_ids(self):
        """Retrieve a set of sensor update policy IDs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies/querySensorUpdatePolicies

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing sensor update policy IDs.
        """

        endpoint = '/policy/queries/sensor-update/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)
        resources = resp.json()['resources']
        return resources

    def get_policies(self):
        """Retrieve a set of Sensor Update Policies by specifying their IDs
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies/getSensorUpdatePolicies

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of strings representing sensor policy update IDs.
        Returns: List of objects representing sensor update policies.
        """

        endpoint = '/policy/entities/sensor-update/v1?ids='
        for policy_id in self.policy_ids:
            resp = requests.get(BASE_URL + endpoint + policy_id, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            handle_response(resp)
            resources = resp.json()['resources']

            # Assumes len() of resources is 1 (it was for all policies returned during testing)
            description = resources[0]['description']
            name = resources[0]['name']
            platform_name = resources[0]['platform_name']
            settings = resources[0]['settings']

            sensor_update_policy = SensorUpdatePolicy(description=description,
                                                      name=name,
                                                      platform_name=platform_name,
                                                      settings=settings)

            self.policies.append(sensor_update_policy)

    def write_policies(self):
        """Create Sensor Update Policies by specifying details about the policy to create
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies/createSensorUpdatePolicies

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: Nothing.
        """

        # A 400 error with the message "Release ID is required" means the "build" field
        # (or possibly the "Linux ARM64 build" field) was set to '' in the update policy we attempted to write.
        # Going to allow this for now because that's a reflection of what's in source environment
        # even if the API doesn't like it

        endpoint = '/policy/entities/sensor-update/v1'
        for policy in self.policies:
            resp = requests.post(BASE_URL + endpoint, json=policy.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            # If you try to write a policy without a build / release version specified, you receive
            # error 400 with message "Release ID is required"
            handle_response(resp)

    def delete_policies(self):
        """Delete Sensor Update Policies.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies/deleteSensorUpdatePolicies
        """

        endpoint = '/policy/entities/sensor-update/v1?ids='
        for policy_id in self.policy_ids:
            resp = requests.delete(BASE_URL + endpoint + policy_id, headers=self.target_headers,
                                   proxies=self.proxies, verify=self.verify)
            handle_response(resp)


################################
# Sensor Visibility Exclusions #
################################

class SensorVisibilityPolicy:
    def __init__(self, regexp_value, value, value_hash):
        self.groups = ['all']
        self.regexp_value = regexp_value
        self.value = value
        self.value_hash = value_hash

    def to_json(self):
        return self.__dict__


class SensorVisibilityExclusions:
    def __init__(self, source_token=None, target_token=None, proxy=None):
        if source_token:
            self.source_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + source_token}
        if target_token:
            self.target_headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + target_token}
        self.proxies = {'https': 'http://' + proxy} if proxy else None
        self.verify = False if proxy else True
        self.exclusion_ids = self.get_ids()
        self.exclusions = []

    def get_ids(self):
        """Search for sensor visibility exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-visibility-exclusions/querySensorVisibilityExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
        Returns: List of strings representing sensor visibility exclusion IDs.
        """

        endpoint = '/policy/queries/sv-exclusions/v1'
        resp = requests.get(BASE_URL + endpoint, headers=self.source_headers, proxies=self.proxies, verify=self.verify)
        handle_response(resp)
        resources = resp.json()['resources']
        return resources

    def get_exclusions(self):
        """Get a set of Sensor Visibility Exclusions by specifying their IDs.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-visibility-exclusions/getSensorVisibilityExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of strings representing sensor visibility exclusion IDs.
        Returns: List of objects representing sensor visibility exclusions.
        """

        endpoint = '/policy/entities/sv-exclusions/v1?ids='
        for exclusion_id in self.exclusion_ids:
            resp = requests.get(BASE_URL + endpoint + exclusion_id, headers=self.source_headers, proxies=self.proxies,
                                verify=self.verify)
            resources = resp.json()['resources']

            # Assumes len(resources) is always 1
            regexp_value = resources[0]['regexp_value']
            value = resources[0]['value']
            value_hash = resources[0]['value_hash']

            sensor_visibility_policy = SensorVisibilityPolicy(regexp_value=regexp_value,
                                                              value=value,
                                                              value_hash=value_hash)

            self.exclusions.append(sensor_visibility_policy)

    def write_exclusions(self):
        """Create the sensor visibility exclusions.
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-visibility-exclusions/createSVExclusionsV1

        Takes: Dictionary representing HTTP request headers, including valid authorization token.
               List of objects representing sensor visibility exclusions.
        Returns: Nothing.
        """

        endpoint = '/policy/entities/sv-exclusions/v1'
        for exclusion in self.exclusions:
            resp = requests.post(BASE_URL + endpoint, json=exclusion.to_json(), headers=self.target_headers,
                                 proxies=self.proxies, verify=self.verify)
            handle_response(resp)

    def delete_exclusions(self):
        """Delete Sensor Visibility Exclusions
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-visibility-exclusions/deleteSensorVisibilityExclusionsV1
        """

        endpoint = '/policy/entities/sv-exclusions/v1?ids='
        for exclusion_id in self.exclusion_ids:
            resp = requests.delete(BASE_URL + endpoint + exclusion_id, headers=self.target_headers,
                                   proxies=self.proxies, verify=self.verify)
            handle_response(resp)


######################
# End API Components #
######################

def check_params(env, config_file=None, cid=None, secret=None):
    """Check logic on parameters passed to main function. The order for retrieving API credential information is:
    1. Passed via CLI parameters
    2. Read from config file
    3. Read from OS environment variables CS_SOURCE_ID, CS_SOURCE_SECRET, CS_TARGET_ID, and CS_TARGET_SECRET
    4. Interactive prompt using getpass.getpass()

     Takes: Environment type (source or target) as string and argparse args.
     Returns: Client ID (cid) and client secret as strings.
     """

    Environment = namedtuple('Environment', 'id_var '
                                            'secret_var '
                                            'name '
                                            'id_arg '
                                            'secret_arg '
                                            'conf_section '
                                            'conf_id_name '
                                            'conf_secret_name')

    if env == 'source':
        env = Environment(id_var='CS_SOURCE_ID',
                          secret_var='CS_SOURCE_SECRET',
                          name='source',
                          id_arg='--source-id',
                          secret_arg='--source-secret',
                          conf_section='Source',
                          conf_id_name='source_env_client_id',
                          conf_secret_name='source_env_client_secret')
    elif env == 'target':
        env = Environment(id_var='CS_TARGET_ID',
                          secret_var='CS_TARGET_SECRET',
                          name='target',
                          id_arg='--target-id',
                          secret_arg='--target-secret',
                          conf_section='Target',
                          conf_id_name='target_env_client_id',
                          conf_secret_name='target_env_client_secret')

    # Config file is mandatory argument for all the API information
    # so check that for client ID and secret first if not passed via command-line
    if (not cid) or (not secret):
        config = configparser.ConfigParser()
        config.read(config_file)
        cid = config[env.conf_section][env.conf_id_name]
        secret = config[env.conf_section][env.conf_secret_name]
        if not cid:
            cid = os.getenv(env.id_var)
        if not secret:
            secret = os.getenv(env.secret_var)

    # If either client ID or client secret aren't retrieved from environment variables
    if not cid:
        try:
            cid = getpass(prompt=f'Enter {env.name} client ID: ')
        except:
            print(f'Failed to retrieve {env.name} client ID.')
            exit()

    if not secret:
        try:
            secret = getpass(prompt=f'Enter {env.name} client secret: ')
        except:
            print(f'Failed to retrieve {env.name} client ID.')
            exit()

    if (not cid) or (not secret):
        print(f'[-] Failed to retrieve CrowdStrike {env.name} API credentials from {config_file} or environment '
              f'variables.')
        exit()

    return cid, secret


def authenticate(env, cid, secret, proxy):
    """Authenticate to the CrowdStrike API. Writes local ./.prod_access_token or ./test_access_token file in JSON format
    for subsequent script executions.

    Takes: Environment to which to authenticate (prod or test), client ID, and client secret as strings.
    Returns: Access token as string.
    """

    endpoint = '/oauth2/token'
    data = {'client_id': cid, 'client_secret': secret}
    if proxy:
        proxies = {'https': 'http://' + proxy}
        verify = False
    else:
        proxies = None
        verify = True
    resp = requests.post(BASE_URL + endpoint, data=data, proxies=proxies, verify=verify)
    handle_response(resp)

    if resp.status_code == 201:
        access_token = resp.json()['access_token']
        return access_token
    else:
        print(f'[-] Received status code {resp.status_code}')
        exit()


def handle_response(resp):
    """Skeleton function to monitors CrowdStrike API responses to avoid rate limiting and display error information.
    Prints remaining requests permitted and any error information to console.

    Takes: Requests library response object.
    Returns: Nothing.
    """

    headers = dict(resp.headers)
    limit = headers.get('X-Ratelimit-Limit')  # The documentation depicts it as RateLimit
    remaining = headers.get('X-Ratelimit-Remaining')
    retry_after = headers.get('X-RateLimit-RetryAfter')
    if remaining and limit:
        percent = int(remaining) / int(limit)
        print(f'[*] {remaining} of {limit} ({percent:.2%})', end='\r', flush=True)
        if percent < .50:
            print('[-] Dropped below 50%, sleeping for 10 seconds...')
            sleep(10)

    if retry_after:
        timestamp = datetime.now().timestamp()
        interval = ceil((retry_after - timestamp) / 1000)
        print(f'[*] Retry after: {retry_after}')
        sleep(interval)

    if resp.status_code in range(400, 600):
        error = json.loads(resp.content)['errors'][0]['message']
        print(f'\n[-] Error {resp.status_code}\n'
              f'    Endpoint: {resp.url}\n'
              f'    Message: {error}')


def read_config(config_file):
    Apis = namedtuple('Apis', 'custom_ioa_rules '
                              'device_control_policies '
                              'indicators_of_compromise '
                              'machine_learning_exclusions '
                              'prevention_policies '
                              'ioa_exclusions '
                              'sensor_update_policies '
                              'sensor_visibility_exclusions '
                              'host_groups')

    apis = Apis
    config = configparser.RawConfigParser()
    config.read(config_file)

    apis.host_groups = config.getboolean('APIs', 'host_groups')
    apis.custom_ioa_rules = config.getboolean('APIs', 'custom_ioa_rules')
    apis.device_control_policies = config.getboolean('APIs', 'device_control_policies')
    apis.indicators_of_compromise = config.getboolean('APIs', 'indicators_of_compromise')
    apis.machine_learning_exclusions = config.getboolean('APIs', 'machine_learning_exclusions')
    apis.prevention_policies = config.getboolean('APIs', 'prevention_policies')
    apis.ioa_exclusions = config.getboolean('APIs', 'ioa_exclusions')
    apis.sensor_update_policies = config.getboolean('APIs', 'sensor_update_policies')
    apis.sensor_visibility_exclusions = config.getboolean('APIs', 'sensor_visibility_exclusions')

    proxy = config['Proxy']['proxy_ip']

    return apis, proxy


class AliasedGroup(click.Group):
    """Allows commands to be called by their first unique character."""

    def get_command(self, ctx, cmd_name):
        """Allows commands to be called by their first unique character
        """

        command = click.Group.get_command(self, ctx, cmd_name)
        if command is not None:
            return command
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
def main():
    """
    Select a module:

    backup - Backup rules, policies, exclusions, etc. from a target environment to JSON on disk. Requires an API client
    with read privileges to the source environment (not implemented).

    replicate - Write the rules, policies, exclusions, etc. from a source environment to a target environment. Requires
    an API client with read privileges to the source environment and write privileges to the target environment.

    restore - Restore an environment based on JSON files created by the "backup" module. Requires an API client with
    write privileges to the target environment (not implemented).

    wipe - Wipe rules, policies, exclusions, etc.from a target environment. Requires an API client with write privileges
    to the target environment.

    Run 'replicator.py <module> --help' for more information.
    """
    pass


@main.command(name='backup', short_help='Backup rules, policies, exclusions, etc. from a target environment to '
                                        'JSON on disk. Requires an API client with read privileges to the source '
                                        'environment')
@click.option('-c', '--config', help='Path to config file with API values and selected APIs.', required=True)
@click.option('-sI', '--source-id', help='Source environment API client ID.', required=False)
@click.option('-sS', '--source-secret', help='Source environment API client secret.', required=False)
@click.pass_context
def backup(self, config, source_id=None, source_secret=None):
    apis, proxy = read_config(config)
    if proxy:
        click.secho('[!] Certificate verification is disabled by default when using a proxy.', fg='red', bold=True)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    source_id, source_secret = check_params('source', config, source_id, source_secret)
    source_token = authenticate('source', source_id, source_secret, proxy)
    target_token = None

    print('[*] Preparing to backup source environment...')

    if apis.host_groups:
        host_groups = HostGroups(source_token, target_token, proxy)

    if apis.custom_ioa_rules:
        custom_ioa_rules = CustomIOAs(source_token, target_token, proxy)

    if apis.device_control_policies:
        device_control_policies = DeviceControlPolicies(source_token, target_token, proxy)

    if apis.indicators_of_compromise:
        indicators_of_compromise = CustomIOCs(source_token, target_token, proxy)

    if apis.machine_learning_exclusions:
        machine_learning_exclusions = MachineLearningExclusions(source_token, target_token, proxy)

    if apis.prevention_policies:
        prevention_policies = PreventionPolicies(source_token, target_token, proxy)

    if apis.ioa_exclusions:
        ioa_exclusions = IOAExclusions(source_token, target_token, proxy)

    if apis.sensor_update_policies:
        sensor_update_policies = SensorUpdatePolicies(source_token, target_token, proxy)

    if apis.sensor_visibility_exclusions:
        sensor_visibility_exclusions = SensorVisibilityExclusions(source_token, target_token, proxy)


@main.command(name='replicate', short_help='Write the rules, policies, exclusions, etc. from a source environment '
                                           'to a target environment. Requires an API client with read privileges'
                                           'to the source environment and write privileges to the target environment.')
@click.option('-c', '--config', help='Path to config file with API values and selected APIs.', required=True)
@click.option('-sI', '--source-id', help='Source environment API client ID.', required=False)
@click.option('-sS', '--source-secret', help='Source environment API client secret.', required=False)
@click.option('-tI', '--target-id', help='Target environment API client ID.', required=False)
@click.option('-tS', '--target-secret', help='Target environment API client secret.', required=False)
@click.option('-e', '--enable', help='Automatically enable copied policies.', is_flag=True)
@click.pass_context
def replicate(self, config, source_id=None, source_secret=None, target_id=None, target_secret=None, enable=False):
    apis, proxy = read_config(config)
    if proxy:
        click.secho('[!] Certificate verification is disabled by default when using a proxy.', fg='red', bold=True)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    source_id, source_secret = check_params('source', config, source_id, source_secret)
    source_token = authenticate('source', source_id, source_secret, proxy)

    target_id, target_secret = check_params('target', config, target_id, target_secret)
    target_token = authenticate('target', target_id, target_secret, proxy)

    print('[*] Preparing to replicate source environment to target environment...')

    if apis.host_groups:
        host_groups = HostGroups(source_token, target_token, proxy)
        if host_groups.group_ids:
            host_groups.get_groups()
            host_groups.write_groups()

    if apis.custom_ioa_rules:
        custom_ioa_rules = CustomIOAs(source_token, target_token, proxy)
        if custom_ioa_rules.rule_group_ids:
            custom_ioa_rules.get_rules()
            custom_ioa_rules.write_rule_groups()
            custom_ioa_rules.write_rules()

    if apis.device_control_policies:
        device_control_policies = DeviceControlPolicies(source_token, target_token, proxy)
        if device_control_policies.policy_ids:
            device_control_policies.get_policies()
            device_control_policies.write_policies()

    if apis.indicators_of_compromise:
        indicators_of_compromise = CustomIOCs(source_token, target_token, proxy)
        if indicators_of_compromise.ioc_ids:
            indicators_of_compromise.get_iocs()
            indicators_of_compromise.write_iocs()

    if apis.machine_learning_exclusions:
        ml_exclusions = MachineLearningExclusions(source_token, target_token, proxy)
        if ml_exclusions.exclusion_ids:
            ml_exclusions.get_exclusions()
            ml_exclusions.write_exclusions()

    if apis.prevention_policies:
        prevention_policies = PreventionPolicies(source_token, target_token, proxy, enable=enable)
        if prevention_policies.policy_ids:
            prevention_policies.get_policies()
            prevention_policies.write_policies()

    if apis.ioa_exclusions:
        ioa_exclusions = IOAExclusions(source_token, target_token, proxy)
        if ioa_exclusions.exclusion_ids:
            ioa_exclusions.get_exclusions()
            ioa_exclusions.write_exclusions()  # Returns 405 ("method not allowed") error

    if apis.sensor_update_policies:
        sensor_update_policies = SensorUpdatePolicies(source_token, target_token, proxy)
        if sensor_update_policies.policy_ids:
            sensor_update_policies.get_policies()
            sensor_update_policies.write_policies()

    if apis.sensor_visibility_exclusions:
        sensor_visibility_exclusions = SensorVisibilityExclusions(source_token, target_token, proxy)
        if sensor_visibility_exclusions.exclusion_ids:
            sensor_visibility_exclusions.get_exclusions()
            sensor_visibility_exclusions.write_exclusions()


@main.command(name='restore', short_help='Restore rules, policies, exclusions, etc. to an environment based on'
                                         'JSON files created by the "backup" module.')
@click.option('-c', '--config', help='Path to config file with API values and selected APIs.', required=True)
@click.option('-tI', '--target-id', help='Target environment API client ID.', required=False)
@click.option('-tS', '--target-secret', help='Target environment API client secret.', required=False)
@click.pass_context
def restore(self, config, target_id=None, target_secret=None):
    apis, proxy = read_config(config)
    if proxy:
        click.secho('[!] Certificate verification is disabled by default when using a proxy.', fg='red', bold=True)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    target_id, target_secret = check_params('target', config, target_id, target_secret)
    target_token = authenticate('target', target_id, target_secret, proxy)
    source_token = None

    print('[*] Preparing to restore target environment...')

    if apis.host_groups:
        host_groups = HostGroups(source_token, target_token, proxy)

    if apis.custom_ioa_rules:
        custom_ioa_rules = CustomIOAs(source_token, target_token, proxy)

    if apis.device_control_policies:
        device_control_policies = DeviceControlPolicies(source_token, target_token, proxy)

    if apis.indicators_of_compromise:
        indicators_of_compromise = CustomIOCs(source_token, target_token, proxy)

    if apis.machine_learning_exclusions:
        machine_learning_exclusions = MachineLearningExclusions(source_token, target_token, proxy)

    if apis.prevention_policies:
        prevention_policies = PreventionPolicies(source_token, target_token, proxy)

    if apis.ioa_exclusions:
        ioa_exclusions = IOAExclusions(source_token, target_token, proxy)

    if apis.sensor_update_policies:
        sensor_update_policies = SensorUpdatePolicies(source_token, target_token, proxy)

    if apis.sensor_visibility_exclusions:
        sensor_visibility_exclusions = SensorVisibilityExclusions(source_token, target_token, proxy)


@main.command(name='wipe', short_help='Wipe rules, policies, exclusions, etc.from a target environment. Requires an '
                                      'API client with write privileges to the target environment.')
@click.option('-c', '--config', help='Path to config file with API values and selected APIs.', required=True)
@click.option('-sI', '--source-id', help='Source environment API client ID.', required=False)
@click.option('-sS', '--source-secret', help='Source environment API client secret.', required=False)
@click.option('-tI', '--target-id', help='Target environment API client ID.', required=False)
@click.option('-tS', '--target-secret', help='Target environment API client secret.', required=False)
@click.option('-d', '--disable', help='Automatically disable policies to allow removal.', is_flag=True)
@click.pass_context
def wipe(self, config, source_id=None, source_secret=None, target_id=None, target_secret=None, disable=False):
    apis, proxy = read_config(config)
    if proxy:
        click.secho('[!] Certificate verification is disabled by default when using a proxy.', fg='red', bold=True)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    source_id, source_secret = check_params('source', config, source_id, source_secret)
    source_token = authenticate('source', source_id, source_secret, proxy)

    target_id, target_secret = check_params('target', config, target_id, target_secret)
    target_token = authenticate('target', target_id, target_secret, proxy)

    print('[*] Preparing to wipe target environment...')

    if apis.host_groups:
        host_groups = HostGroups(source_token, target_token, proxy)
        if host_groups.group_ids:
            host_groups.delete_groups()

    if apis.custom_ioa_rules:
        custom_ioa_rules = CustomIOAs(source_token, target_token, proxy)
        if custom_ioa_rules.rule_group_ids:
            custom_ioa_rules.delete_rule_groups()

    if apis.device_control_policies:
        device_control_policies = DeviceControlPolicies(source_token, target_token, proxy)
        if device_control_policies.policy_ids:
            device_control_policies.delete_policies()

    if apis.indicators_of_compromise:
        indicators_of_compromise = CustomIOCs(source_token, target_token, proxy)
        if indicators_of_compromise.ioc_ids:
            indicators_of_compromise.delete_iocs()

    if apis.machine_learning_exclusions:
        ml_exclusions = MachineLearningExclusions(source_token, target_token, proxy)
        if ml_exclusions.exclusion_ids:
            ml_exclusions.delete_exclusions()

    if apis.prevention_policies:
        prevention_policies = PreventionPolicies(source_token, target_token, proxy, disable=disable)
        if prevention_policies.policy_ids:
            prevention_policies.delete_policies()

    if apis.ioa_exclusions:
        ioa_exclusions = IOAExclusions(source_token, target_token, proxy)
        if ioa_exclusions.exclusion_ids:
            ioa_exclusions.delete_exclusions()

    if apis.sensor_update_policies:
        sensor_update_policies = SensorUpdatePolicies(source_token, target_token, proxy)
        if sensor_update_policies.policy_ids:
            sensor_update_policies.delete_policies()

    if apis.sensor_visibility_exclusions:
        sensor_visibility_exclusions = SensorVisibilityExclusions(source_token, target_token, proxy)
        if sensor_visibility_exclusions.exclusion_ids:
            sensor_visibility_exclusions.delete_exclusions()


if __name__ == '__main__':
    main()

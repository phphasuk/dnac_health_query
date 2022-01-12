
# -*- coding: utf-8 -*-
"""

Cisco DNA Center Command Runner

Copyright (c) 2019 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

__author__ = "Gabriel Zapodeanu TME, ENB"
__email__ = "gzapodea@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2020 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import os
import sys
import time
import datetime
import requests
import urllib3
import json
import re

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


# Cisco DNA Center info

username = 'admin'
password = 'password'
DNAC_URL = 'https://dnac_ip'


DNAC_AUTH = HTTPBasicAuth(username, password)


def get_dnac_jwt_token(dnac_auth):
    """
    Create the authorization token required to access DNA C
    Call to Cisco DNA Center - /api/system/v1/auth/login
    :param dnac_auth - Cisco DNA Center Basic Auth string
    :return: Cisco DNA Center JWT token
    """
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    dnac_jwt_token = response.json()['Token']
    return dnac_jwt_token

def get_all_device_info(limit, dnac_jwt_token):
    """
    The function will return all network devices info, using the specified limit of devices/API Call
    :param limit: the number of devices to return per API call
    :param dnac_jwt_token: Cisco DNA C token
    :return: DNA C device inventory info
    """
    offset = 1
    all_devices_list = []
    all_devices_info = ['']  # assign a value, to make sure the API call will run at least once
    while all_devices_info:
        all_devices_info = ''
        url = DNAC_URL + '/dna/intent/api/v1/network-device?offset=' + str(offset) + '&limit=' + str(limit)
        header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
        all_devices_response = requests.get(url, headers=header, verify=False)
        all_devices_json = all_devices_response.json()
        all_devices_info = all_devices_json['response']
        all_devices_list += all_devices_info
        offset += limit
    return all_devices_list


def get_all_site_info(limit, dnac_jwt_token):
    """
    The function will return all site info, using the specified limit of devices/API Call
    :param limit: the number of sites to return per API call
    :param dnac_jwt_token: Cisco DNA C token
    :return: DNA C all site info
    """
    offset = 1
    all_sites_info = []
    sites_info = ['']  # assign a value, to make sure the API call will run at least once
    while sites_info:
        sites_info = ''
        url = DNAC_URL + '/dna/intent/api/v1/site/count'
        header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
        sites_count_response = requests.get(url, headers=header, verify=False)
        total_sites = sites_count_response.json()['response']
        url = DNAC_URL + '/dna/intent/api/v1/site?offset=' + str(offset) + '&limit=' + str(limit)
        header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
        sites_response = requests.get(url, headers=header, verify=False)
        sites_json = sites_response.json()
        sites_info = sites_json['response']
        all_sites_info += sites_info
        offset += limit
        if offset > total_sites:
            break
    return all_sites_info


def get_siteid_mapping_dict(all_sites_info):
    siteid_mapping_dict = {}
    for site in all_sites_info:
        siteid_mapping_dict[site['siteNameHierarchy']] = site['id']
    return siteid_mapping_dict


def get_siteid(all_sites_info, site_keyword):
    siteid = []
    for site in all_sites_info:
        if site_keyword in site['siteNameHierarchy']:
            siteid.append(site['id'])
    return siteid

def get_all_device_dict(limit, dnac_jwt_token):
    """
    The function will return all network devices info, using the specified limit of devices/API Call
    :param limit: the number of devices to return per API call
    :param dnac_jwt_token: Cisco DNA C token
    :return: DNA C device inventory info
    """
    offset = 1
    all_devices_dict = {}
    all_devices_list = []
    all_devices_info = ['']  # assign a value, to make sure the API call will run at least once
    while all_devices_info:
        while all_devices_info:
            all_devices_info = ''
            url = DNAC_URL + '/dna/intent/api/v1/network-device?offset=' + str(offset) + '&limit=' + str(limit)
            header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
            all_devices_response = requests.get(url, headers=header, verify=False)
            all_devices_json = all_devices_response.json()
            all_devices_info = all_devices_json['response']
            all_devices_list += all_devices_info
            offset += limit
    for device in all_devices_list:
        all_devices_dict.update({device['hostname']: device})
    return all_devices_dict


def get_overall_network_health(dnac_jwt_token):
    """
    This function will retrieve the network health at the time the function is called
    :param dnac_jwt_token: Cisco DNA C token
    :return: network health
    """
    epoch_time = get_epoch_current_time()
    url = DNAC_URL + '/dna/intent/api/v1/network-health?timestamp=' + str(epoch_time)
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    network_health_response = requests.get(url, headers=header, verify=False)
    network_health_json = network_health_response.json()
    network_health = {'overall_network_health': network_health_json['response'][0]['healthScore']}
    for device_group in network_health_json['healthDistirubution']:
        network_health.update({device_group['category']: device_group['healthScore']})  # merge the device category health
    return network_health


def get_all_device_health_dict(limit, dnac_jwt_token, deviceRole='', location_key=''):
    """
    The function will return all network devices health info, using the specified limit of devices/API Call
    :param limit: the number of devices to return per API call
    :param dnac_jwt_token: Cisco DNA C token
    :deviceRole: CORE, ACCESS, DISTRIBUTION, ROUTER, WLC, AP
    :return: DNA C device health info
    """
    offset = 1
    all_devices_health_dict = {}
    all_devices_health_list = []
    all_devices_health = ['']  # assign a value, to make sure the API call will run at least once
    runtime = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
    while all_devices_health:
        while all_devices_health:
            all_devices_health = ''
            if deviceRole:
                url = DNAC_URL + '/dna/intent/api/v1/device-health?offset=' + str(offset) + '&limit=' + str(limit) + '&deviceRole=' + deviceRole
            else:
                url = DNAC_URL + '/dna/intent/api/v1/device-health?offset=' + str(offset) + '&limit=' + str(limit)
            header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
            all_devices_health_response = requests.get(url, headers=header, verify=False)
            all_devices_health_json = all_devices_health_response.json()
            all_devices_health = all_devices_health_json['response']
            all_devices_health_list += all_devices_health
            offset += limit
    for device in all_devices_health_list:
        if re.search(location_key, device['location']):
            all_devices_health_dict.update({device['name']: device})
            device['timestamp'] = runtime
    return all_devices_health_dict


def get_overall_devices_health(all_devices_health_dict, deviceRole=''):
    """
    This function will correlate data from the all_devices_health_dict
    :all_devices_health_dict: all_devices_health_dict
    :return: overall devices health
    """
    if not deviceRole:
        deviceRole = 'ALL'
    overall_devices_health = {
                                deviceRole: {
                                                'Total': 0,
                                                'Up': 0,
                                                'Down': 0,
                                                'Reachable': 0,
                                                'Ping Reachable': 0
                                }
                            }
    down_list = []
    up_list = []
    overall_devices_health[deviceRole]['Total'] = len(all_devices_health_dict)
    for device in all_devices_health_dict:
        device_data = {}
        if all_devices_health_dict[device]['reachabilityHealth'] == 'DOWN' or \
            all_devices_health_dict[device]['reachabilityHealth'] == 'UNREACHABLE':
            overall_devices_health[deviceRole]['Down'] += 1
            device_data = all_devices_health_dict[device]
            down_list.append(device_data)
        elif all_devices_health_dict[device]['reachabilityHealth'] == 'REACHABLE' or \
            all_devices_health_dict[device]['reachabilityHealth'] == 'UP':
            overall_devices_health[deviceRole]['Reachable'] += 1
            device_data = all_devices_health_dict[device]
            up_list.append(device_data)
        elif all_devices_health_dict[device]['reachabilityHealth'] == 'PING_REACHABLE':
            overall_devices_health[deviceRole]['Ping Reachable'] += 1
            device_data = all_devices_health_dict[device]
            up_list.append(device_data)
    overall_devices_health[deviceRole]['Up'] = overall_devices_health[deviceRole]['Total'] - overall_devices_health[deviceRole]['Down']
    print(json.dumps(overall_devices_health))
    i = 1
    for item in down_list:
        down_event = { deviceRole + '_down_' + str(i): item }
        print(json.dumps(down_event))
        i += 1
    i = 1
    for item in up_list:
        up_event = { deviceRole + '_up_' + str(i): item }
        print(json.dumps(up_event))
        i += 1
    return


def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data:
    :return:
    """
#    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))
    print(json.dumps(json_data, indent=4))

def get_epoch_current_time():
    """
    This function will return the epoch time for the {timestamp}
    :return: epoch time including msec
    """
    epoch = time.time()*1000
    return int(epoch)


def main():
    # get the Cisco DNA Center Auth
    dnac_auth = get_dnac_jwt_token(DNAC_AUTH)

    # get all the devices info, 500 devices collect per each API call (this is the max), print them as list
    # all_devices_info = get_all_device_info(500, dnac_auth)
    # print(json.dumps(all_devices_info))  # save the all devices info to Splunk App index

    # get all the devices info, 500 devices collect per each API call (this is the max), print them as dict
    # all_devices_info_dict = get_all_device_dict(5, dnac_auth)
    # print(json.dumps(all_devices_info_dict))  # save the all devices info to Splunk App index

    # get the overall network health
    # overall_network_health = get_overall_network_health(dnac_auth)
    # print(json.dumps(overall_network_health))  # save the network health to Splunk App index

    # get all the devices health info, 1000 devices collect per each API call (this is the max), print them as dict
    all_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='', location_key='')
    get_overall_devices_health(all_devices_health_dict, deviceRole='')

    # get all the CORE health info, 1000 devices collect per each API call (this is the max), print them as dict
    # CORE_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='CORE',location_key='')
    # get_overall_devices_health(CORE_devices_health_dict, deviceRole='CORE')

    # get all the ACCESS health info, 1000 devices collect per each API call (this is the max), print them as dict
    ACCESS_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='ACCESS', location_key='')
    get_overall_devices_health(ACCESS_devices_health_dict, deviceRole='ACCESS')

    # get all the DISTRIBUTION health info, 1000 devices collect per each API call (this is the max), print them as dict
    # DISTRIBUTION_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='DISTRIBUTION', location_key='')
    # get_overall_devices_health(DISTRIBUTION_devices_health_dict, deviceRole='DISTRIBUTION')

    # get all the ROUTER health info, 1000 devices collect per each API call (this is the max), print them as dict
    # ROUTER_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='ROUTER', location_key='')
    # get_overall_devices_health(ROUTER_devices_health_dict, deviceRole='ROUTER')

    # get all the WLC health info, 1000 devices collect per each API call (this is the max), print them as dict
    WLC_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='WLC', location_key='')
    get_overall_devices_health(WLC_devices_health_dict, deviceRole='WLC')

    # get all the AP health info, 1000 devices collect per each API call (this is the max), print them as dict
    AP_devices_health_dict = get_all_device_health_dict(1000, dnac_auth, deviceRole='AP', location_key='')
    get_overall_devices_health(AP_devices_health_dict, deviceRole='AP')


if __name__ == '__main__':
    main()



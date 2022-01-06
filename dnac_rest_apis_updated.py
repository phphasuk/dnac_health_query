
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

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


# Cisco DNA Center info

username = 'admin'
password = 'C!sc0123'
DNAC_URL = 'https://10.122.20.139'


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


def get_all_device_health_dict(limit, dnac_jwt_token, deviceRole = ''):
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
        all_devices_health_dict.update({device['name']: device})
    return all_devices_health_dict


def get_overall_devices_health(all_devices_health_dict):
    """
    This function will correlate data from the all_devices_health_dict
    :all_devices_health_dict: all_devices_health_dict
    :return: overall devices health
    """
    overall_devices_health = {
                                'Total': 0,
                                'Up': 0,
                                'Down': 0,
                                'Reachable': 0,
                                'Ping Reachable': 0,
                                'down_list': []
                                }
    overall_devices_health['Total'] = len(all_devices_health_dict)
    for device in all_devices_health_dict:
        if all_devices_health_dict[device]['reachabilityHealth'] == 'DOWN' or \
            all_devices_health_dict[device]['reachabilityHealth'] == 'UNREACHABLE':
            overall_devices_health['Down'] += 1
            overall_devices_health['down_list'] += { all_devices_health_dict[device]['name'],all_devices_health_dict[device]['ipAddress'],all_devices_health_dict[device]['ipAddress'] }
        elif all_devices_health_dict[device]['reachabilityHealth'] == 'REACHABLE':
            overall_devices_health['Reachable'] += 1
        elif all_devices_health_dict[device]['reachabilityHealth'] == 'PING_REACHABLE':
            overall_devices_health['Ping Reachable'] += 1
    overall_devices_health['Up'] = overall_devices_health['Total'] - overall_devices_health['Down']
    return overall_devices_health


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

    # get all the devices health info, 500 devices collect per each API call (this is the max), print them as dict
    all_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='')
    # print(json.dumps(all_devices_health_dict))  # save the all devices info to Splunk App index
    overall_all_devices_health = get_overall_devices_health(all_devices_health_dict)
    print(json.dumps(overall_all_devices_health))

    # get all the CORE health info, 500 devices collect per each API call (this is the max), print them as dict
    CORE_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='CORE')
    overall_CORE_devices_health = get_overall_devices_health(CORE_devices_health_dict)
    print(json.dumps(overall_CORE_devices_health))

    # get all the ACCESS health info, 500 devices collect per each API call (this is the max), print them as dict
    ACCESS_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='ACCESS')
    overall_ACCESS_devices_health = get_overall_devices_health(ACCESS_devices_health_dict)
    print(json.dumps(overall_ACCESS_devices_health))

    # get all the DISTRIBUTION health info, 500 devices collect per each API call (this is the max), print them as dict
    DISTRIBUTION_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='DISTRIBUTION')
    overall_DISTRIBUTION_devices_health = get_overall_devices_health(DISTRIBUTION_devices_health_dict)
    print(json.dumps(overall_DISTRIBUTION_devices_health))

    # get all the ROUTER health info, 500 devices collect per each API call (this is the max), print them as dict
    ROUTER_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='ROUTER')
    overall_ROUTER_devices_health = get_overall_devices_health(ROUTER_devices_health_dict)
    print(json.dumps(overall_ROUTER_devices_health))

    # get all the WLC health info, 500 devices collect per each API call (this is the max), print them as dict
    WLC_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='WLC')
    overall_WLC_devices_health = get_overall_devices_health(WLC_devices_health_dict)
    print(json.dumps(overall_WLC_devices_health))

    # get all the AP health info, 500 devices collect per each API call (this is the max), print them as dict
    AP_devices_health_dict = get_all_device_health_dict(5, dnac_auth, deviceRole='AP')
    overall_AP_devices_health = get_overall_devices_health(AP_devices_health_dict)
    print(json.dumps(overall_AP_devices_health))

if __name__ == '__main__':
    main()



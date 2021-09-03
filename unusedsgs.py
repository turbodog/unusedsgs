#!/usr/bin/env python3

import argparse
import json
import os
import requests
import sys

#
# Parameters to be extracted to the command line
#
lookback = 24*30
cloudAccount = "AWS: RedLock Demo Account"

from datetime import datetime

DEBUG_MODE = False

def output(output_data=''):
    print(output_data)

def login(url, access_key, secret_key, ca_bundle):
    endpoint = '%s/login' % url
    headers = {'Content-Type': 'application/json'}
    data = json.dumps({'username': access_key, 'password': secret_key})
    api_response = requests.request('POST', endpoint, headers=headers, data=data, verify=ca_bundle)
    if api_response.ok:
        api_response = json.loads(api_response.content)
        token = api_response.get('token')
    else:
        output('API (%s) responded with an error\n%s' % (endpoint, api_response.text))
        sys.exit(1)
    if DEBUG_MODE:
        output(endpoint)
        output(token)
    return token

def execute(action, url, token, ca_bundle=None, requ_data=None):
    headers = {'Content-Type': 'application/json'}
    headers['x-redlock-auth'] = token
    api_response = requests.request(action, url, headers=headers, verify=ca_bundle, data=requ_data)
    result = None
    if api_response.status_code in [401, 429, 500, 502, 503, 504]:
        for _ in range(1, 3):
            time.sleep(16)
            api_response = requests.request(action, url, headers=headers, verify=ca_bundle, data=requ_data)
            if api_response.ok:
                break # retry loop
    if api_response.ok:
        try:
            result = json.loads(api_response.content)
        except ValueError:
            output('API (%s) responded with an error\n%s' % (endpoint, api_response.content))
            sys.exit(1)
    else:
        if DEBUG_MODE:
            output(api_response.content)
    return result



CONFIG = {}
try:
    from config import *
except ImportError:
    output('Error reading config')
    exit(1)

ca_bundle = None
token = login(CONFIG['url'], CONFIG['access_key'], CONFIG['secret_key'], ca_bundle)
#output(token)

#AND dest.resource IN ( resource where securitygroup.name = 'Allow All' ) 
activeSGsRQL= \
("""
{
  "query":"network from vpc.flow_record where packets > 0 AND cloud.account = '%s'",
  "timeRange":{
     "type":"relative",
     "value":{
        "unit":"hour",
        "amount":%d
     }
  }
}
""") % (cloudAccount, lookback)
#output(activeSGsRQL)
activeSGsFlowLogs = execute('POST', '%s/search' % CONFIG['url'], token, ca_bundle, activeSGsRQL)
#print(json.dumps(activeSGsFlowLogs, indent=3, sort_keys=True))

activeSGs = set()
for i in activeSGsFlowLogs['data']['nodes']:
    if 'secgroup_ids' in i['metadata']:
        SGs = i['metadata']['secgroup_ids']
        if SGs[0] != "N/A":
            for j in SGs:
                activeSGs.add(j)
output("Active SGs: %d" % (len(activeSGs)))
output(activeSGs)
output("")

allSGsRQL= \
("""
{
  "query":"config from cloud.resource where api.name = 'aws-ec2-describe-security-groups' and cloud.account = '%s' ",
  "timeRange":{
     "type":"relative",
     "value":{
        "unit":"hour",
        "amount":%d
     }
  }
}
""") % (cloudAccount, lookback)
allSGsResults = execute('POST', '%s/search/config' % CONFIG['url'], token, ca_bundle, allSGsRQL)
#print(json.dumps(allSGs, indent=3, sort_keys=True))

allSGs = set()
for i in allSGsResults['data']['items']:
    allSGs.add(i['data']['groupId'])
#    output(i['data']['groupId'])
output("All SGs: %d" % (len(allSGs)))
output(allSGs)
output("")

unusedSGs = allSGs.difference(activeSGs)
output("Unused SGs: %d" % (len(unusedSGs)))
output(unusedSGs)

#!/usr/bin/env python3
# -*- mode: Python;-*-

###############################################################################
# [2022] Ian McCloy
# All Rights Reserved.
###############################################################################

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import sys

# Construct an argument parser
all_args = argparse.ArgumentParser()

# Add arguments to the parser
all_args.add_argument("-u", "--user", required=True,
   help="Username")
all_args.add_argument("-p", "--pass", required=True,
   help="Password")
all_args.add_argument("-c", "--cluster", required=True,
   help="Cluster URL - https://10.145.212.101:18091")
all_args.add_argument("-n", "--noverify", required=False,
   action='store_true', help="No Cert Verification")
all_args.add_argument("-v", "--verbose", required=False,
   action='store_true', help="Output verbose info")
all_args.add_argument("-d", "--debug", required=False,
   action='store_true', help="Output debug info")
args = vars(all_args.parse_args())

if not args['debug']:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def rest_call(url):
    """
    Call to a REST API endpoint
    :param url:
    :return:
    """

    if args['noverify']:
        response = requests.get(url, verify = False,
            auth = HTTPBasicAuth(args['user'], args['pass']))
    else:
        response = requests.get(args['cluster'],
            auth = HTTPBasicAuth(args['user'], args['pass']))
    if args['debug']:
        if response:
            print('Request is successful.')
        else:
            print('Request returned an error.')

        print(response)

    # convert json to Python object
    rest_data = response.json()

    if args['debug']:
        print (str(rest_data))

    return (rest_data)

pools_data = rest_call(args['cluster'] + '/pools')
self_data = rest_call(args['cluster'] + '/nodes/self')
audit_data = rest_call(args['cluster'] + '/settings/audit')
ldap_data = rest_call(args['cluster'] + '/settings/ldap')
pw_policy_data = rest_call(args['cluster'] + '/settings/passwordPolicy')
cert_data = rest_call(args['cluster'] + '/pools/default/certificate?extended=true')
security_data = rest_call(args['cluster'] + '/settings/security/')
query_data = rest_call(args['cluster'] + '/settings/querySettings')

########## /pools checks

#i.e. 7.0.2-6703-enterprise
version_build = pools_data['implementationVersion'].split("-")
version = version_build[0].split(".")

print ('Cluster Version: {}'.format(
                            pools_data['implementationVersion']))

if version_build[2] != "enterprise":
    sys.exit("Error: Only Couchbase Enterprise builds supported")

if args['verbose']:
    print ('Major ({}) - Minor ({}) - Maintence ({})'.format(
        version[0], version[1], version[2]))

########## /nodes/self checks

print ('Node Services: {}'.format(self_data['services']))

if not self_data['nodeEncryption']:
    print ('Node encryption disabled')

########## /settings/audit checks

if not audit_data['auditdEnabled']:
    print ('Audit not enabled')


########## /settings/ldap checks

if not ldap_data['authenticationEnabled']:
    print ('LDAP Authentication not enabled')

if not ldap_data['authorizationEnabled']:
    print ('LDAP Authorization not enabled')

if not ldap_data['encryption']:
    print ('LDAP encryption not enabled')

########## /settings/passwordPolicy checks

if pw_policy_data['minLength'] < 12:
    print ('Password Policy length too short')

########## /pools/default/certificate?extended=true checks

if cert_data['cert']['type'] == 'generated':
    print ('Using self-signed generated cert')

########## /settings/security checks

if security_data['tlsMinVersion'] == 'tlsv1' or security_data['tlsMinVersion'] == 'tlsv1.1' :
    print ('Min TLS is insecure')

########## /settings/querySettings checks

if query_data['queryCurlWhitelist']['all_access']:
    print ('Query cURL not restricted')
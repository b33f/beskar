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
                      help="Cluster URL - "
                           "example: https://10.145.212.101:18091")
all_args.add_argument("-n", "--noverify", required=False,
                      action='store_true', help="No Cert Verification")
all_args.add_argument("-v", "--verbose", required=False,
                      action='store_true', help="Output verbose info")
all_args.add_argument("-d", "--debug", required=False,
                      action='store_true', help="Output debug info")
args = vars(all_args.parse_args())

if not args['debug']:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


print(
    '''
▄▄▄▄· ▄▄▄ ..▄▄ · ▄ •▄  ▄▄▄· ▄▄▄
▐█ ▀█▪▀▄.▀·▐█ ▀. █▌▄▌▪▐█ ▀█ ▀▄ █·
▐█▀▀█▄▐▀▀▪▄▄▀▀▀█▄▐▀▀▄·▄█▀▀█ ▐▀▀▄
██▄▪▐█▐█▄▄▌▐█▄▪▐█▐█.█▌▐█ ▪▐▌▐█•█▌
·▀▀▀▀  ▀▀▀  ▀▀▀▀ ·▀  ▀ ▀  ▀ .▀  ▀
    '''
)


def print_bar():
    """
    output a bar for CLI UI
    :return:
    """
    print('___ ___ ___ ___ ___ ___ ___ ___ ')
    return


def rest_call(url):
    """
    Call to a REST API endpoint
    :param url:
    :return:
    """

    if args['noverify']:
        response = requests.get(url, verify=False,
                                auth=HTTPBasicAuth(args['user'],
                                                   args['pass']))
    else:
        response = requests.get(url,
                                auth=HTTPBasicAuth(
                                    args['user'], args['pass']))
    if args['debug']:
        if response:
            print('Request to {} is successful.'.format(url))
        else:
            print('Request to {} returned an error.'.format(url))

        print(response)

    # convert json to Python object
    rest_data = response.json()

    if args['debug']:
        print(str(rest_data))

    return (rest_data)


pools_data = rest_call(args['cluster'] + '/pools')
self_data = rest_call(args['cluster'] + '/nodes/self')
audit_data = rest_call(args['cluster'] + '/settings/audit')
ldap_data = rest_call(args['cluster'] + '/settings/ldap')
pw_policy_data = rest_call(args['cluster'] + '/settings/passwordPolicy')
cert_data = rest_call(args['cluster'] +
                      '/pools/default/certificate?extended=true')
security_data = rest_call(args['cluster'] + '/settings/security/')
query_data = rest_call(args['cluster'] + '/settings/querySettings')
client_cert_data = rest_call(args['cluster'] + '/settings/clientCertAuth')

########## /pools checks

# i.e. 7.0.2-6703-enterprise
version_build = pools_data['implementationVersion'].split("-")
version = version_build[0].split(".")

print('Cluster Version: {}'.format(
                            pools_data['implementationVersion']))

if args['verbose']:
    print('Major ({}) - Minor ({}) - Maintence ({})'.format(
        version[0], version[1], version[2]))

if version_build[2] != "enterprise":
    sys.exit("Error: Only Couchbase Enterprise builds supported")

print_bar()

########## /nodes/self checks

print('Node Services: {}'.format(self_data['services']))

'''
Best practice is to use Enforce TLS
by setting encryption level to "strict"
'''

if not self_data['nodeEncryption']:
    print('Node encryption disabled')

'''
Best practice to only allow the IP address family
as needed
'''

if not self_data['addressFamilyOnly']:
    print('IP Address family not restricted')

'''
Best practice is to use hostnames with TLS
'''

if self_data['hostname'].\
        replace('.', '').replace(':', '').isdigit():
    print('Using IPs not Hostnames')

########## /settings/audit checks

'''
Best practice is to enable couchbase auditing
this should be used to monitor key system configuration changes
and respond to incidents or perform forensic analysis.
'''

if not audit_data['auditdEnabled']:
    print('Audit not enabled')


########## /settings/ldap checks

'''
The best practice is to make MFA mandatory for all administrator accounts.
It must be implemented as part of external authentication
such as LDAP
'''

if not ldap_data['authenticationEnabled']:
    print('LDAP Authentication not enabled')

if not ldap_data['authorizationEnabled']:
    print('LDAP Authorization not enabled')

if not ldap_data['encryption']:
    print('LDAP encryption not enabled')

########## /settings/passwordPolicy checks

'''
Password Policy best practice is to use a password manager
and use a passphrase of at least 15 characters
separating each word with a special character
OR a password at least 12 characters long
with letters, numbers and special characters.
'''

if pw_policy_data['minLength'] < 12:
    print('Password Policy length too short')

if not pw_policy_data['enforceSpecialChars']:
    print('Password Policy not requiring special characters')

########## /pools/default/certificate?extended=true checks

'''
Best practice, replace self-signed certificates
 with certificates generated from a trusted CA
'''

if cert_data['cert']['type'] == 'generated':
    print('Using self-signed generated TLS cert')

########## /settings/security checks

'''
Best practice, require TLS v1.2 as the minimum
TLS 1.0 and 1.1 are not considered secure
'''

if security_data['tlsMinVersion'] == 'tlsv1' or \
        security_data['tlsMinVersion'] == 'tlsv1.1':
    print('Min TLS is insecure')


'''
Best practice to only allow CA cert changes from
a localhost connection
'''

if security_data['allowNonLocalCACertUpload']:
    print('Allowing non-local CA cert changes')

########## /settings/querySettings checks

'''
Best practice, only allow cURL in N1QL to specific hosts
added to the allowed list
'''

if query_data['queryCurlWhitelist']['all_access']:
    print('Query cURL not restricted')

########## /settings/clientCertAuth checks

'''
Best practice is for applications to auth with x.509 certs
'''

if client_cert_data['state'] == 'disable':
    print('Client x.509 cert auth disabled')

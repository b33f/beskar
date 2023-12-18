#!/usr/bin/env python3
# -*- mode: Python;-*-

###############################################################################
# [2023] Ian McCloy
# All Rights Reserved.
###############################################################################

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import json
import sys
import getpass

print(
    '''
▄▄▄▄· ▄▄▄ ..▄▄ · ▄ •▄  ▄▄▄· ▄▄▄
▐█ ▀█▪▀▄.▀·▐█ ▀. █▌▄▌▪▐█ ▀█ ▀▄ █·
▐█▀▀█▄▐▀▀▪▄▄▀▀▀█▄▐▀▀▄·▄█▀▀█ ▐▀▀▄
██▄▪▐█▐█▄▄▌▐█▄▪▐█▐█.█▌▐█ ▪▐▌▐█•█▌
·▀▀▀▀  ▀▀▀  ▀▀▀▀ ·▀  ▀ ▀  ▀ .▀  ▀
The Couchbase Server Security Scanner
    '''
)

# Construct an argument parser
all_args = argparse.ArgumentParser()

# Add arguments to the parser
all_args.add_argument("-u", "--user", required=True,
                      help="Username, needs to be an Admin")
all_args.add_argument("-p", "--pass", required=False,
                      help="Password, will prompt if not provided")
all_args.add_argument("-c", "--cluster", required=True,
                      help="Cluster URL - "
                           "example: https://10.145.212.101:18091")
all_args.add_argument("-n", "--noverify", required=False,
                      action='store_true', help="No TLS Cert Verification")
all_args.add_argument("-v", "--verbose", required=False,
                      action='store_true', help="Output verbose info")
all_args.add_argument("-d", "--debug", required=False,
                      action='store_true', help="Output debug info")
all_args.add_argument("-f", "--force", required=False,
                      help="Force cluster version - "
                            "example: -f 6.6.5")
args = vars(all_args.parse_args())

if not args['pass']:
    try:
        args['pass'] = getpass.getpass()
    except Exception as tion:
        print('Error Occurred : ', tion)

if not args['debug']:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


try:
    f1 = open('cbserver-cves.json')
    data = json.load(f1)
    cb_cves = data["result"]["CVE_Items"]
    f1.close()
except Exception as tion:
    print('CB Server CVE Parse Error Occurred : ', tion)

try:
    f2 = open('library-cves.json')
    data = json.load(f2)
    library_cves = data["CVE_Items"]
    f2.close()
except Exception as tion:
    print('Library CVE ParseError Occurred : ', tion)


cve_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']


def print_bar():
    """
    output a bar for CLI UI
    :return:
    """
    print('___ ___ ___ ___ ___ ___ ___ ___ ')
    return None


def rest_call(url):
    """
    Call to a REST API endpoint
    :param url:
    :return:
    """

    try:
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
    except Exception as rest_exception:
        response = ""
        print('REST Call Exception : ', rest_exception)
        quit()

    # convert json to Python object
    if response is not None:
        rest_data = response.json()

    if args['debug']:
        print(str(rest_data))

    return rest_data


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

# [REST CALL] /pools checks

# i.e. 7.0.2-6703-enterprise
version_build = pools_data['implementationVersion'].split("-")

if args['force']:
    version = args['force'].split(".")
    print("WARN: Forcing scan as version {}.{}.{}".format(version[0], version[1], version[2]))
else:
    version = version_build[0].split(".")

if pools_data['implementationVersion']:
    print('Cluster Version: {}'.format(
        pools_data['implementationVersion']))

    if args['verbose']:
        print('Major ({}) - Minor ({}) - Maintenance ({})'.format(
            version[0], version[1], version[2]))

    if version_build[2] != "enterprise":
        sys.exit("Error: Only Couchbase Enterprise builds supported")

rest_result = []
cve_result = {"cbserver": {}, "library": {}}

# [READ FILES] check Couchbase Server CVEs


def check_server_cves():
    """
    Check for CVEs in CB Server Version
    :return:
    """

    for cve in cb_cves:
        for node in cve['configurations']['nodes']:
            for cpe in node['cpe_match']:
                if 'versionStartIncluding' in cpe:
                    cpe_start_ver = cpe['versionStartIncluding'].split(".")
                    if cpe_start_ver[0] < version[0] or (cpe_start_ver[0] == version[0]
                                                         and cpe_start_ver[1] < version[1]) \
                            or (cpe_start_ver[0] == version[0] and cpe_start_ver[1] == version[1]
                                and cpe_start_ver[2] <= version[2]):
                        if 'versionEndIncluding' in cpe:
                            cpe_end_ver = cpe['versionEndIncluding'].split(".")
                            if cpe_end_ver[0] > version[0] or (cpe_end_ver[0] == version[0] and
                                                               cpe_end_ver[1] > version[1]) \
                                    or (cpe_end_ver[0] == version[0] and cpe_end_ver[1] == version[1]
                                        and cpe_end_ver[2] >= version[2]):
                                cve_result['cbserver'][cve['cve']['CVE_data_meta']['ID']] = \
                                    {'type': 'inclusive',
                                     'severity': cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                                     'cvss': cve['impact']['baseMetricV3']['cvssV3']['baseScore'],
                                     'start_ver': cpe['versionStartIncluding'], 'end_ver': cpe['versionEndIncluding'],
                                     'description': cve['cve']['description']['description_data'][0]['value']}
                        if 'versionEndExcluding' in cpe:
                            cpe_end_ver = cpe['versionEndExcluding'].split(".")
                            if cpe_end_ver[0] > version[0] or (cpe_end_ver[0] == version[0]
                                                               and cpe_end_ver[1] > version[1]) \
                                    or (cpe_end_ver[0] == version[0] and cpe_end_ver[1] == version[1]
                                        and cpe_end_ver[2] > version[2]):
                                cve_result['cbserver'][cve['cve']['CVE_data_meta']['ID']] = \
                                    {'type': 'exclusive',
                                     'severity': cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                                     'cvss': cve['impact']['baseMetricV3']['cvssV3']['baseScore'],
                                     'start_ver': cpe['versionStartIncluding'], 'end_ver': cpe['versionEndExcluding'],
                                     'description': cve['cve']['description']['description_data'][0]['value']}
                else:
                    cpe_uri = cpe['cpe23Uri'].split(":")
                    vul_ver = cpe_uri[5].split(".")
                    if vul_ver[0] == version[0] and vul_ver[1] == version[1] and vul_ver[2] == version[2]:
                        cve_result['cbserver'][cve['cve']['CVE_data_meta']['ID']] = \
                            {'type': 'single',
                             'severity': cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                             'cvss': cve['impact']['baseMetricV3']['cvssV3']['baseScore'],
                             'vuln_ver': vul_ver,
                             'description': cve['cve']['description']['description_data'][0]['value']}

    # example with range {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:couchbase:couchbase_server:*:*:*:*:*:*:*:*', \
    # 'versionStartIncluding': '3.0.0', 'versionEndExcluding': '7.1.1', 'cpe_name': []}
    # example w/o range {'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:couchbase:couchbase_server:6.0.0:*:*:*:*:*:*:*', \
    # 'cpe_name': []}
    return


# [READ FILES] check Couchbase Server 3rd Party CVEs


def check_library_cves():
    """
    Check for CVEs in CB Server 3rd Party Libraries
    :return:
    """

    for cve in library_cves:
        for cpe in cve['cpe_match']:
            cpe_start_ver = cpe['versionStartIncluding'].split(".")
            if cpe_start_ver[0] < version[0] or (cpe_start_ver[0] == version[0] and cpe_start_ver[1] < version[1]) \
                    or (cpe_start_ver[0] == version[0] and cpe_start_ver[1] == version[1]
                        and cpe_start_ver[2] <= version[2]):
                cpe_end_ver = cpe['versionEndExcluding'].split(".")
                if cpe_end_ver[0] > version[0] or (cpe_end_ver[0] == version[0] and cpe_end_ver[1] > version[1]) \
                        or (cpe_end_ver[0] == version[0] and cpe_end_ver[1] == version[1]
                            and cpe_end_ver[2] > version[2]):
                    cve_result['library'][cve['ID']] = \
                        {'type': 'exclusive',
                         'severity': cve['baseMetricV3']['severity'], 'cvss': cve['baseMetricV3']['cvss'],
                         'start_ver': cpe['versionStartIncluding'], 'end_ver': cpe['versionEndExcluding'],
                         'description': cve['title']}
    return


if 'cb_cves' in globals():
    check_server_cves()
if 'library_cves' in globals():
    check_library_cves()

# [REST CALL] /nodes/self checks

if 'services' in self_data:
    print('Node Services: {}'.format(self_data['services']))

print_bar()

if not self_data['nodeEncryption']:
    rest_result.append({'msg': 'Node encryption disabled', 'sev': 'CRITICAL',
                       'tip': 'Use Enforce TLS by setting encryption level to "strict"'})

if not self_data['addressFamilyOnly']:
    rest_result.append({'msg': 'IP Address family (IPv4/v6) not restricted', 'sev': 'LOW',
                        'tip': 'Only allow the IPv4/v6 address family as needed'})

if self_data['hostname']. \
        replace('.', '').replace(':', '').isdigit():
    rest_result.append({'msg': 'Using IPs not Hostnames', 'sev': 'LOW',
                        'tip': 'Best practice is to use hostnames with TLS'})

# [REST CALL] /settings/audit checks

if not audit_data['auditdEnabled']:
    rest_result.append({'msg': 'Audit not enabled', 'sev': 'HIGH',
                        'tip': 'Use Auditing to monitor key system configuration changes'})

# [REST CALL] /settings/ldap checks

if not ldap_data['authenticationEnabled']:
    rest_result.append({'msg': 'MFA, LDAP Authentication not enabled', 'sev': 'MEDIUM',
                        'tip': 'Make MFA mandatory for all Administrator accounts via LDAP'})

if not ldap_data['authorizationEnabled']:
    rest_result.append({'msg': 'MFA, LDAP Authorization not enabled', 'sev': 'MEDIUM',
                        'tip': 'Make MFA mandatory for all Administrator accounts via LDAP'})

if not ldap_data['encryption']:
    rest_result.append({'msg': 'LDAP encryption not enabled', 'sev': 'HIGH',
                        'tip': 'LDAP connection needs over the wire encryption'})

# [REST CALL] /settings/passwordPolicy checks

'''
Password Policy best practice is to use a password manager
and use a passphrase of at least 15 characters
separating each word with a special character
OR a password at least 12 characters long
with letters, numbers and special characters.
'''

if pw_policy_data['minLength'] < 12:

    rest_result.append(
        {'msg': 'Password Policy length of {} too short'
            .format(pw_policy_data['minLength']), 'sev': 'HIGH',
         'tip': 'Use a passphrase of at least 15 characters separating each word with a '
                'special character OR a password at least 12 characters long with '
                'letters, numbers and special characters'})

if not pw_policy_data['enforceSpecialChars']:
    rest_result.append({'msg': 'Password Policy not requiring special characters',
                        'sev': 'MEDIUM',
                        'tip': 'Use a passphrase of at least 15 characters separating each word with a '
                               'special character OR a password at least 12 characters long with '
                               'letters, numbers and special characters'
                        })

# [REST CALL] /pools/default/certificate?extended=true checks

if cert_data['cert']['type'] == 'generated':
    rest_result.append({'msg': 'Using self-signed generated TLS cert', 'sev': 'MEDIUM',
                        'tip': 'Replace self-signed certificates with certificates generated from a trusted CA'})

# [REST CALL] /settings/security checks

if security_data['tlsMinVersion'] == 'tlsv1' or \
        security_data['tlsMinVersion'] == 'tlsv1.1':
    rest_result.append({'msg': 'Min TLS of {} is insecure'.
                       format(security_data['tlsMinVersion']),
                        'sev': 'MEDIUM',
                        'tip': 'Require TLS v1.2 as the minimum, TLS 1.0 and 1.1 are not secure'})

if security_data['allowNonLocalCACertUpload']:
    rest_result.append({'msg': 'Allowing non-local CA cert changes', 'sev': 'HIGH',
                        'tip': 'Only allow CA cert changes from localhost'})

# [REST CALL] /settings/querySettings checks

if query_data['queryCurlWhitelist']['all_access']:
    rest_result.append({'msg': 'Query cURL not restricted', 'sev': 'HIGH',
                        'tip': 'Only allow cURL in N1QL to specific hosts'})

# [REST CALL] /settings/clientCertAuth checks

if client_cert_data['state'] == 'disable':
    rest_result.append({'msg': 'Client x.509 cert auth disabled', 'sev': 'MEDIUM',
                        'tip': 'Apps should auth with mTLS x.509 client certs'})

# [OUTPUT] Print REST Results

print("{} Configuration Issues".format(len(rest_result)))

if len(rest_result) > 0:
    for sev in cve_order:
        for res_item in rest_result:
            if res_item['sev'] == sev:
                print("{}: {}".format(sev[0], res_item['msg']))
                if args['verbose']:
                    print(res_item['tip'])

# [OUTPUT] Print CVE Results

if (len(cve_result['cbserver'].keys()) + len(cve_result['library'].keys())) > 0:
    if len(cve_result['cbserver'].keys()) > 0:
        print_bar()
        print("{} CVEs in Couchbase Server {}.{}.{}\n".format(len(cve_result['cbserver'].keys()), version[0],
                                                              version[1], version[2]))
        for cve_sev in cve_order:
            for cve_out in cve_result['cbserver']:
                if cve_result['cbserver'][cve_out]['severity'] == cve_sev:
                    print("{} {} ({}) ".format(cve_out, cve_sev, cve_result['cbserver'][cve_out]['cvss']))
                    if args['verbose']:
                        if cve_result['cbserver'][cve_out]['type'] == "single":
                            print("-- vulnerable in version {}.{}.{} - Description: {}".format(
                                cve_result['cbserver'][cve_out]['vuln_ver'][0],
                                cve_result['cbserver'][cve_out]['vuln_ver'][1],
                                cve_result['cbserver'][cve_out]['vuln_ver'][2],
                                cve_result['cbserver'][cve_out]['description']))
                        if cve_result['cbserver'][cve_out]['type'] == "exclusive" or \
                                cve_result['cbserver'][cve_out]['type'] == "inclusive":
                            print("-- vulnerable from {} to {} {} - Description: {}".format(
                                cve_result['cbserver'][cve_out]['start_ver'],
                                cve_result['cbserver'][cve_out]['end_ver'],
                                cve_result['cbserver'][cve_out]['type'],
                                cve_result['cbserver'][cve_out]['description']))
    if len(cve_result['library'].keys()) > 0:
        print_bar()
        print("{} CVEs in 3rd Party Libraries\n".format(len(cve_result['library'].keys())))
        for cve_sev in cve_order:
            for cve_out in cve_result['library']:
                if cve_result['library'][cve_out]['severity'] == cve_sev:
                    print("{} {} ({}) ".format(cve_out, cve_sev, cve_result['library'][cve_out]['cvss']))
                    if args['verbose']:
                        print("-- vulnerable from {} to {} {} - Description: {}".format(
                            cve_result['library'][cve_out]['start_ver'], cve_result['library'][cve_out]['end_ver'],
                            cve_result['library'][cve_out]['type'], cve_result['library'][cve_out]['description']))

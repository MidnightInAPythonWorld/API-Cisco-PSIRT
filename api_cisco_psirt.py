#!/usr/bin/env python
__author__ = 'MidnightInAPythonWorld'

# Check for Python3
import sys
if sys.version_info[0] != 3:
    print("[-] Script requires Python 3")
    print("[-] Exiting script")
    exit()



# stdlib
import requests, json, time
from pprint import pprint
epoch_time =  int(time.time())



###
###The below psirt_auth_headers is required to get auth token from Cisco that is valid for 1 hour
###
psirt_auth_headers = {}
psirt_auth_headers['Accept'] = 'application/json'
psirt_auth_headers['Accept-Language'] = 'en-US'
psirt_auth_headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
psirt_auth_headers['Accept-Encoding'] = 'gzip, deflate'
psirt_auth_headers['Content-Type'] = 'application/x-www-form-urlencoded'
psirt_auth_headers['Connection'] = 'Keep-Alive'


payload = {'client_id': input("Enter Client ID: "), 'client_secret': input("Enter Client Secret: "), 'grant_type': 'client_credentials'}
psirt_auth = requests.post('https://cloudsso.cisco.com/as/token.oauth2', headers = psirt_auth_headers, params=payload, verify=True)
psirt_auth_json = psirt_auth.json()
psirt_auth_data = psirt_auth_json['access_token']

###    
###The below header includes the Cisco psirt_auth_headers token for the GET requests
###

cisco_api_headers = {}
cisco_api_headers['Accept'] = 'application/json'
cisco_api_headers['Authorization'] = "Bearer " + psirt_auth_data
cisco_api_headers['Accept-Language'] = 'en-US'
cisco_api_headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
cisco_api_headers['Accept-Encoding'] = 'gzip, deflate'
cisco_api_headers['Connection'] = 'Keep-Alive'


###
### 
###
def print_results(api_results):
    api_results_json_data = [json.loads(x) for x in api_results]
    for x in api_results_json_data:
        pprint(x)


###
### Cisco API Function
###
def cisco_api(url,type,vendor,product):
    api_results = []
    try:
        api_requests = requests.get(url, headers = cisco_api_headers, timeout=15.000, verify=True)
        api_json = api_requests.json()
        for x in api_json['advisories']:
            json_ping_fields = {'time':epoch_time,
                 'type': type,
                 'vendor': vendor,
                 'product': product,
                 'advisoryId': x['advisoryId'],
                 'advisoryTitle': x['advisoryTitle'],
                 'bugIDs': x['bugIDs'],
                 'cves': x['cves'],
                 'cwe': x['cwe'],
                 'cvssBaseScore': x['cvssBaseScore'],
                 'firstPublished': x['firstPublished'],
                 'lastUpdated': x['lastUpdated'],
                 'productNames': x['productNames'],
                 'ipsSignatures': x['ipsSignatures'],
                 'publicationUrl': x['publicationUrl'],
                 'sir': x['sir'],
                 'summary': x['summary'],
              }
            api_results.append(json.dumps(json_ping_fields))
    except:
        pass
    print_results(api_results)



def cisco_asa():
    url = "https://api.cisco.com/security/advisories/cvrf/product?product=asa"
    type = "cisco_asa_advisory"
    vendor = "cisco"
    product = "asa"
    cisco_api(url,type,vendor,product)


def cisco_asdm():
    url = "https://api.cisco.com/security/advisories/cvrf/product?product=asdm"
    type = "cisco_asdm_advisory"
    vendor = "cisco"
    product = "asdm"
    cisco_api(url,type,vendor,product)


def cisco_csm():
    url = "https://api.cisco.com/security/advisories/cvrf/product?product=csm"
    type = "cisco_csm_advisory"
    vendor = "cisco"
    product = "csm"
    cisco_api(url,type,vendor,product)


def cisco_latest():
    url = "https://api.cisco.com/security/advisories/latest/30"
    type = "cisco_latest_advisory"
    vendor = "cisco"
    product = "various"
    cisco_api(url,type,vendor,product)


def cisco_CVE_2018_0296():
    url = "https://api.cisco.com/security/advisories/cvrf/cve/CVE-2018-0296"
    type = "cisco_ravpn_cve"
    vendor = "cisco"
    product = "ravpn"
    cisco_api(url,type,vendor,product)


def cisco_CVE_2018_0251():
    url = "https://api.cisco.com/security/advisories/cvrf/cve/CVE-2018-0251"
    type = "cisco_ravpn_cve"
    vendor = "cisco"
    product = "ravpn"
    cisco_api(url,type,vendor,product)



def main():
    cisco_asa()
    cisco_asdm()
    cisco_csm()
    cisco_latest()
    cisco_CVE_2018_0296()
    cisco_CVE_2018_0251()


if __name__== "__main__":
  main()



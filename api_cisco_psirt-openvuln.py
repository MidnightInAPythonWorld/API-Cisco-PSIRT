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

# The below psirt_auth_headers is required to get auth token from Cisco that is valid for 1 hour
psirt_auth_headers = {
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.5',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded', 
    'Connection': 'Keep-Alive',
}

# Below will prompt user to enter auth creds for Cisco PSIRT OpenVuln
payload = {'client_id': input("Enter Client ID: "), 'client_secret': input("Enter Client Secret: "), 'grant_type': 'client_credentials'}
psirt_auth = requests.post('https://cloudsso.cisco.com/as/token.oauth2', headers = psirt_auth_headers, params=payload, verify=True)
psirt_auth_json = psirt_auth.json()
psirt_auth_data = psirt_auth_json['access_token']

# The below header includes the Cisco psirt_auth_headers token for the GET requests
cisco_api_headers = {
    'Accept':'application/json',
    'Authorization': "Bearer " + psirt_auth_data,
    'Accept-Language': 'en-US,en;q=0.5',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'Keep-Alive',
}

# Cisco API Function
def cisco_api(url,type,vendor,product):
    """This function is used make the HTTP GET to Cisco OpenVuln API, create a JSON object, and simply pprint to screen.
    """  
    try:
        api_requests = requests.get(url, headers = cisco_api_headers, timeout=15.000, verify=True)
        api_json = api_requests.json()
        for x in api_json['advisories']:
            json_fields = {'time':epoch_time,
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
            pprint(json_fields)
    except:
        pass

def cisco_asa():
    """This function is an example of querying the API for Cisco ASA Product.
    """  
    url = "https://api.cisco.com/security/advisories/cvrf/product?product=asa"
    type = "cisco_asa_advisory"
    vendor = "cisco"
    product = "asa"
    cisco_api(url,type,vendor,product)

def cisco_ios_version():
    """This function is an example of querying the API for IOS 12.3(14)T.
    """  
    url = "https://api.cisco.com/security/advisories/ios?version=12.3(14)T"
    type = "cisco_ios_advisory"
    vendor = "cisco"
    product = "ios"
    cisco_api(url,type,vendor,product)

def cisco_latest():
    """This function is an example of querying the API for 30 latest advisory notices.
    """  
    url = "https://api.cisco.com/security/advisories/latest/30"
    type = "cisco_latest_advisory"
    vendor = "cisco"
    product = "various"
    cisco_api(url,type,vendor,product)

def cisco_CVE_2018_0296():
    """This function is an example of querying the API for VE-2018-0296.
    """  
    url = "https://api.cisco.com/security/advisories/cvrf/cve/CVE-2018-0296"
    type = "cisco_vpn_cve"
    vendor = "cisco"
    product = "vpn"
    cisco_api(url,type,vendor,product)

def main():
    cisco_asa()
    cisco_ios_version()
    cisco_latest()
    cisco_CVE_2018_0296()

if __name__== "__main__":
  main()

exit()

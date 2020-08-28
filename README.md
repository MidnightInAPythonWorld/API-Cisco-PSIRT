# API-Cisco-PSIRT



### Purpose

This script will query Cisco PSIRT OpenVuln API.  

### Input
 - Users will be prompted to enter Client Secret and Client ID.
 
### Output
 - The script simply prints results to the screen in JSON format. This will dump a lot of text to the scresn so just comment out the functions in main to see results from different API calls.
 - These results can easily be sent to SIEM or other endpoints.
 t- For example, This script could be used to send results to Splunk HEC for alerting or dashboarding.
 
### API Options
 - By Advisory ID
 - All Advisories
 - By CVE ID
 - By Lastest Advisories
 - By Product Name
 - By IOS, IOS-XE, or NX-OS software version


For more information on Cisco PSIRT OpenVuln, please reference the following:
https://developer.cisco.com/psirt/

For more information on the API Capabilities, please reference the following:
https://developer.cisco.com/docs/psirt/#!api-reference


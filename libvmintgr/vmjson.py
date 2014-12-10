import sys
import json
import calendar
import time

import vuln

DEFDESC = "system vulnerability management automation"

def wf_to_json(w):
    ret = {}

    ret['check'] = {}
    ret['check']['description'] = DEFDESC
    ret['check']['timestamp'] = int(calendar.timegm(time.gmtime()))

    ret['asset'] = {}
    ret['asset']['ipv4'] = w.vulnerability.ipaddr
    ret['asset']['hostname'] = w.vulnerability.hostname
    ret['asset']['macaddr'] = w.vulnerability.macaddr

    ret['vuln'] = {}
    ret['vuln']['title'] = w.vulnerability.title
    ret['vuln']['cvss'] = w.vulnerability.cvss
    ret['vuln']['exploits'] = w.vulnerability.known_exploits
    ret['vuln']['malware'] = w.vulnerability.known_malware
    ret['vuln']['discovery_time'] = w.vulnerability.discovered_date_unix

    return json.dumps(ret)

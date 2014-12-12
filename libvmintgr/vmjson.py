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
    if w.status == vuln.WorkflowElement.STATUS_ESCALATED:
        ret['vuln']['status'] = 'new'
    elif w.status == vuln.WorkflowElement.STATUS_CLOSED:
        ret['vuln']['status'] = 'closed'
    else:
        ret['vuln']['status'] = 'unknown'
    ret['vuln']['title'] = w.vulnerability.title
    ret['vuln']['cvss'] = w.vulnerability.cvss
    ret['vuln']['exploits'] = w.vulnerability.known_exploits
    ret['vuln']['malware'] = w.vulnerability.known_malware
    ret['vuln']['discovery_time'] = w.vulnerability.discovered_date_unix

    return json.dumps(ret)

def ce_to_json(w):
    ret = {}

    ret['hostname'] = w.failvuln.hostname
    
    ret['policy'] = {}
    ret['policy']['url'] = ''
    ret['policy']['name'] = 'system'
    ret['policy']['level'] = 'medium'

    ret['check'] = {}
    ret['check']['name'] = 'vulnerability scanner check'
    ret['check']['description'] = 'validate system patch level'
    ret['check']['location'] = 'endpoint'
    ret['check']['ref'] = 'sysmediumupdates1'
    ret['check']['test'] = {}
    ret['check']['test']['name'] = 'vulnerability scan'
    ret['check']['test']['value'] = w.failvuln.title

    ret['compliance'] = False
    ret['link'] = ''
    # XXX This needs to be converted to the correct format
    ret['utctimestamp'] = w.lasthandled

    return json.dumps(ret)


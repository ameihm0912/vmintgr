# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import json
import calendar
import time
import pytz
import datetime

import vuln

DEFDESC = "system vulnerability management automation"

srcname = 'unset'
compliance_url = 'unset'
compliance_link = 'unset'

def set_sourcename(s):
    global srcname
    srcname = s

def set_compliance_urls(u1, u2):
    global compliance_url
    global compliance_link
    compliance_url = u1
    compliance_link = u2

def wf_to_json(w):
    ret = {}

    ret['description'] = DEFDESC
    ret['utctimestamp'] = \
        pytz.timezone('UTC').localize(datetime.datetime.utcnow()).isoformat()
    ret['sourcename'] = srcname

    ret['asset'] = {}
    ret['asset']['assetid'] = w.vulnerability.assetid
    ret['asset']['ipv4address'] = w.vulnerability.ipaddr
    ret['asset']['hostname'] = w.vulnerability.hostname
    ret['asset']['macaddress'] = w.vulnerability.macaddr
    ret['asset']['autogroup'] = w.vulnerability.autogroup

    ret['vuln'] = {}
    if w.status == vuln.WorkflowElement.STATUS_ESCALATED:
        ret['vuln']['status'] = 'open'
    elif w.status == vuln.WorkflowElement.STATUS_CLOSED:
        ret['vuln']['status'] = 'closed'
    else:
        ret['vuln']['status'] = 'unknown'
    ret['vuln']['title'] = w.vulnerability.title
    ret['vuln']['cvss'] = w.vulnerability.cvss
    ret['vuln']['known_exploits'] = w.vulnerability.known_exploits
    ret['vuln']['known_malware'] = w.vulnerability.known_malware
    ret['vuln']['discovery_time'] = w.vulnerability.discovered_date_unix
    ret['vuln']['age_days'] = w.vulnerability.age_days
    ret['vuln']['patch_in'] = w.vulnerability.patch_in
    ret['vuln']['vulnid'] = w.vulnerability.vid_classified
    ret['vuln']['cves'] = []
    for i in w.vulnerability.cves:
        ret['vuln']['cves'].append(i)

    return json.dumps(ret)

def ce_to_json(w, target):
    ret = {}

    ret['target'] = target
    
    ret['policy'] = {}
    ret['policy']['url'] = compliance_url
    ret['policy']['name'] = 'system'
    ret['policy']['level'] = 'medium'

    ret['check'] = {}
    ret['check']['name'] = 'vulnerability scanner check'
    ret['check']['description'] = 'validate system patch level'
    ret['check']['location'] = 'endpoint'
    ret['check']['ref'] = 'sysmediumupdates1'
    ret['check']['test'] = {}
    ret['check']['test']['name'] = 'vulnerability scan'
    ret['check']['test']['type'] = 'nexpose'
    ret['check']['test']['value'] = 'nexpose'

    if w == None:
        ret['compliance'] = True
    else:
        ret['compliance'] = False
    ret['utctimestamp'] = \
        pytz.timezone('UTC').localize(datetime.datetime.utcnow()).isoformat()
    ret['link'] = compliance_link

    return json.dumps(ret)


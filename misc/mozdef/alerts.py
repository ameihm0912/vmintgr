#!/usr/bin/python

import sys
import os
import pyes
import dateutil.parser
import csv

indexname = 'alerts'
eshost = None
esconn = None
start_date = None
end_date = None

class Alert(object):
    def __init__(self):
        self.summary = ''
        self.category = ''
        self.severity = ''
        self.utctimestamp = None
        self.tags = []
        self.events = []

    def parse_result(self, esdict):
        if 'utctimestamp' not in esdict: return False
        self.utctimestamp = dateutil.parser.parse(esdict['utctimestamp'])
        self.summary = esdict.get('summary', '')
        self.severity = esdict.get('severity', '')
        self.category = esdict.get('category', '')
        if 'tags' in esdict:
            self.tags = esdict['tags']
        for x in esdict['events']:
            ne = Event()
            ne.parse_event(x)
            self.events.append(ne)
        return True

class Event(object):
    def __init__(self):
        self.category = ''
        self.summary = ''
        self.timestamp = None

    def parse_event(self, esdict):
        ds = esdict['documentsource']
        self.category = ds.get('category', '')
        self.summary = ds.get('summary', '')
        if 'utctimestamp' in ds:
            self.timestamp = dateutil.parser.parse(ds['utctimestamp'])

def pdata(alerts):
    ccount = {}
    for x in alerts:
        if x.category not in ccount:
            ccount[x.category] = 1
        else:
            ccount[x.category] += 1

    scount = {}
    for x in alerts:
        if x.severity not in scount:
            scount[x.severity] = 1
        else:
            scount[x.severity] += 1

    tcount = {}
    for x in alerts:
        for t in x.tags:
            if t not in tcount:
                tcount[t] = 1
            else:
                tcount[t] += 1

    cw = csv.writer(sys.stdout)

    cw.writerow(['total alerts', len(alerts)])

    for x in sorted(alerts, key=lambda x: x.utctimestamp):
        cw.writerow(['alert', x.utctimestamp, x.summary])

    for x in ccount:
        cw.writerow(['alert_category', x, ccount[x]])

    for x in scount:
        cw.writerow(['alert_severity', x, scount[x]])

    for x in tcount:
        cw.writerow(['alert_tags', x, tcount[x]])

def usage():
    sys.stdout.write('usage: alerts.py mozdefurl start_date end_date\n')
    sys.exit(1)

def make_query():
    qrange = pyes.RangeQuery(pyes.ESRange('utctimestamp', start_date, end_date))
    qterm = pyes.TermQuery('_type', 'alert')
    q = pyes.BoolQuery(must=[qrange, qterm])
    results = esconn.search(q, indices=indexname)
    ret = []
    for x in results:
        na = Alert()
        if na.parse_result(x): ret.append(na)
    return ret

def domain():
    global start_date
    global end_date
    global eshost
    global esconn

    if len(sys.argv) != 4:
        usage()
    eshost = sys.argv[1]
    try:
        start_date = dateutil.parser.parse(sys.argv[2]).replace(tzinfo=dateutil.tz.tzutc())
        end_date = dateutil.parser.parse(sys.argv[3]).replace(tzinfo=dateutil.tz.tzutc())
    except ValueError as e:
        sys.stderr.write('error parsing date: {}\n'.format(e))
        sys.exit(1)

    try:
        esconn = pyes.ES(eshost)
    except RuntimeError as e:
        sys.stderr.write('error parsing es host argument: {}\n'.format(e))
        sys.exit(1)
    try:
        if not esconn.indices.exists_index(indexname):
            sys.stderr.write('error: index {} not found\n'.format(indexname))
            sys.exit(1)
    except pyes.exceptions.NoServerAvailable:
        sys.stderr.write('error checking for index on specified es host\n')
        sys.exit(1)

    alerts = make_query()
    pdata(alerts)

if __name__ == '__main__':
    domain()

sys.exit(0)

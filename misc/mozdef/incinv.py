#!/usr/bin/python

import sys
import getopt
from datetime import datetime
from pymongo import MongoClient
import pytz

mclient = None

incident_tagcnt = {}
inves_tagcnt = {}

def tag_summary():
    sys.stdout.write('######## tag summary (incidents) ########\n')
    for x in incident_tagcnt:
        sys.stdout.write('{} {}\n'.format(x, incident_tagcnt[x]))
    sys.stdout.write('######## tag summary (investigations) ########\n')
    for x in inves_tagcnt:
        sys.stdout.write('{} {}\n'.format(x, inves_tagcnt[x]))

def dump_incidents(q):
    global incident_tagcnt

    mozdefdb = mclient['meteor']
    incidents = mozdefdb['incidents']
    cursor = incidents.find(q).sort("dateOpened", 1)
    cnt = 0
    sys.stdout.write('######## incidents ########\n')
    for i in cursor:
        sys.stdout.write('-------- {} --------\n'.format(cnt))
        sys.stdout.write(i['summary'] + '\n')
        sys.stdout.write(i['description'] + '\n')
        sys.stdout.write('Date opened: {}\n'.format(i['dateOpened']))
        for x in i['tags']:
            sys.stdout.write(x + '\n')
            if x not in incident_tagcnt:
                incident_tagcnt[x] = 1
            else:
                incident_tagcnt[x] += 1
        cnt += 1

def dump_investigations(q):
    global inves_tagcnt

    mozdefdb = mclient['meteor']
    incidents = mozdefdb['investigations']
    cursor = incidents.find(q).sort("dateOpened", 1)
    cnt = 0
    sys.stdout.write('######## investigations ########\n')
    for i in cursor:
        sys.stdout.write('-------- {} --------\n'.format(cnt))
        sys.stdout.write(i['summary'] + '\n')
        sys.stdout.write(i['description'] + '\n')
        sys.stdout.write('Date opened: {}\n'.format(i['dateOpened']))
        for x in i['tags']:
            sys.stdout.write(x + '\n')
            if x not in inves_tagcnt:
                inves_tagcnt[x] = 1
            else:
                inves_tagcnt[x] += 1
        cnt += 1

def usage():
    sys.stdout.write('usage: incinv.py mozdef_host start_date end_date\n')
    sys.exit(1)

def domain():
    global mclient

    if len(sys.argv) != 4:
        usage()
    mozdef_host = sys.argv[1]
    utc = pytz.utc
    start_date = utc.localize(datetime.strptime(sys.argv[2], '%Y-%m-%d'))
    end_date = utc.localize(datetime.strptime(sys.argv[3], '%Y-%m-%d'))

    q = {}
    q['dateOpened'] = {"$gte": start_date, "$lte": end_date}

    mclient = MongoClient(mozdef_host, 3002)
    dump_incidents(q)
    dump_investigations(q)
    tag_summary()

if __name__ == '__main__':
    domain()

sys.exit(0)

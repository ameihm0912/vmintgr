#!/usr/bin/python2
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import getopt
from elasticsearch_dsl.connections import connections

es = None
index = 'vulnerabilities'

MODE_UNSET  = 0
MODE_LIST   = 1
MODE_CREATE = 2
MODE_DELETE = 3

def usage():
    sys.stdout.write('usage: indexmgr.py [-cdh] [-e eshost]\n')
    sys.exit(0)

def domain():
    global es

    opmode = MODE_UNSET
    eshost = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'cde:h')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
    for o, a in opts:
        if o == '-h':
            usage()
        elif o == '-c':
            opmode = MODE_CREATE
        elif o == '-d':
            opmode = MODE_DELETE
        elif o == '-e':
            eshost = a

    if opmode == MODE_UNSET:
        opmode = MODE_LIST

    if eshost == None:
        sys.stderr.write('error: eshost must be specified with -e\n')
        sys.exit(1)
    connections.create_connection(hosts=[eshost])

    if opmode == MODE_LIST:
        for x in connections.get_connection().indices.get_aliases().keys():
            sys.stdout.write('{}\n'.format(x))
    elif opmode == MODE_CREATE:
        stgs = {
                'mappings': {
                        'vulnerability_state': {
                            'properties': {
                                'vuln': {
                                    'properties': {
                                        'title': {
                                            'type': 'string',
                                            'index': 'not_analyzed'
                                            },
                                        'cves': {
                                            'type': 'string',
                                            'index': 'not_analyzed'
                                            }
                                        }
                                    }
                                }
                            }
                    }
                }
        connections.get_connection().indices.create(index, body=stgs)
    elif opmode == MODE_DELETE:
        connections.get_connection().indices.delete(index)

if __name__ == '__main__':
    domain()

sys.exit(0)

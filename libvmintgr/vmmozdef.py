# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
try:
    import cPickle
except ImportError:
    import pickle as cPickle

import json
import debug

import mozdef_client as mozdef

def mozdef_proc(escdir, mozdef_compliance_urls, mozdef_vuln_urls):
    escfiles = os.listdir(escdir)

    escfiles = sorted(escfiles, key=lambda x: x.split('-')[1])

    for i in escfiles:
        p = os.path.join(escdir, i)
        fd = open(p, 'r')
        events = cPickle.load(fd)
        fd.close()

        if 'vulns' in i:
            for x in mozdef_vuln_urls:
                debug.printd('writing to %s' % x)
                msg = mozdef.MozDefMsg(x)
                msg.fire_and_forget_mode = False
                for j in events:
                    d = json.loads(j)
                    msg.send_vulnerability(d)
        elif 'compliance' in i:
            for x in mozdef_compliance_urls:
                debug.printd('writing to %s' % x)
                msg = mozdef.MozDefMsg(x)
                msg.fire_and_forget_mode = False
                for j in events:
                    d = json.loads(j)
                    msg.send_compliance(d['target'], d['policy'],
                        d['check'], d['compliance'], d['link'], d['tags'])

        os.remove(p)

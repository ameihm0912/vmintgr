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

def mozdef_proc(escdir, mozdef_compliance_urls, mozdef_vuln_urls,
    mozdef_hint_urls):
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
                msg = mozdef.MozDefVulnerability(x)
                msg.set_fire_and_forget(False)
                for j in events:
                    d = json.loads(j)
                    msg.log = d
                    msg.send()
        elif 'compliance' in i:
            for x in mozdef_compliance_urls:
                debug.printd('writing to %s' % x)
                msg = mozdef.MozDefCompliance(x)
                msg.set_fire_and_forget(False)
                for j in events:
                    d = json.loads(j)
                    msg.summary = 'vmintgr compliance item'
                    msg.details = d
                    msg.tags = ['vmintgr', 'compliance']
                    msg.send()
        elif 'hint' in i:
            for x in mozdef_hint_urls:
                debug.printd('writing to %s' % x)
                msg = mozdef.MozDefAssetHint(x)
                msg.set_fire_and_forget(False)
                for j in events:
                    d = json.loads(j)
                    msg.summary = d['summary']
                    msg.details = d['details']
                    msg.send()

        os.remove(p)

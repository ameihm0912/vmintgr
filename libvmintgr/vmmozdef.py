# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
import cPickle
import json

import mozdef_client as mozdef

def mozdef_proc(escdir, mozdef_compliance_url, mozdef_vuln_url):
    escfiles = os.listdir(escdir)

    escfiles = sorted(escfiles, key=lambda x: x.split('-')[1])

    for i in escfiles:
        p = os.path.join(escdir, i)
        fd = open(p, 'r')
        events = cPickle.load(fd)
        fd.close()

        if 'vulns' in i:
            msg = mozdef.MozDefMsg(mozdef_vuln_url)
            msg.fire_and_forget_mode = False
            for j in events:
                d = json.loads(j)
                msg.send_vulnerability(d)
        elif 'compliance' in i:
            msg = mozdef.MozDefMsg(mozdef_compliance_url)
            msg.fire_and_forget_mode = False
            for j in events:
                d = json.loads(j)
                msg.send_compliance(d['target'], d['policy'],
                    d['check'], d['compliance'], d['link'])

        os.remove(p)

import sys
import os
import cPickle
import json

import mozdef

def mozdef_proc(escdir, mozdef_url):
    escfiles = os.listdir(escdir)

    escfiles = sorted(escfiles, key=lambda x: x.split('-')[1])

    for i in escfiles:
        p = os.path.join(escdir, i)
        fd = open(p, 'r')
        events = cPickle.load(fd)
        fd.close()

        if 'vulns' in i:
            summary = 'vmintgr-vulnerability'
            tags = ['vmintgr', 'vulnerability']
        elif 'compliance' in i:
            summary = 'vmintgr-compliance'
            tags = ['vmintgr', 'compliance']
        else:
            continue

        msg = mozdef.MozDefMsg(mozdef_url, summary=summary,
            tags=tags)
        msg.fire_and_forget_mode = False
        for j in events:
            d = json.loads(j)
            msg.send(details=d)

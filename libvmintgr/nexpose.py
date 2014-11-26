import sys

sys.path.append('../../pnexpose')

import pnexpose

class nexpose_connector(object):
    def __init__(self, server, port, user, pw):
        self._conn = pnexpose.nexposeClient(server, port, user, pw)

def site_extraction(conf):
    pass

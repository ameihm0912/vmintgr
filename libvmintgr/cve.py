# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys

def cve_expand_cvss_vector(s):
    if s == None or s == "":
        return {}
    ret = {}
    for elem in s.split('/'):
        buf = elem.split(':')
        if len(buf) != 2:
            return {}
        key = buf[0]
        val = buf[1]
        if key == 'AV':
            l = 'access_vector'
            if val == 'N':
                ret[l] = 'network'
            elif val == 'A':
                ret[l] = 'adjacent network'
            elif val == 'L':
                ret[l] = 'local'
        elif key == 'AC':
            l = 'access_complexity'
            if val == 'H':
                ret[l] = 'high'
            elif val == 'M':
                ret[l] = 'medium'
            elif val == 'L':
                ret[l] = 'low'
        elif key == 'Au':
            l = 'authentication'
            if val == 'M':
                ret[l] = 'multiple'
            elif val == 'S':
                ret[l] = 'single'
            elif val == 'N':
                ret[l] = 'none'
        elif key == 'C':
            l = 'confidentiality_impact'
            if val == 'N':
                ret[l] = 'none'
            elif val == 'P':
                ret[l] = 'partial'
            elif val == 'C':
                ret[l] = 'complete'
        elif key == 'I':
            l = 'integrity_impact'
            if val == 'N':
                ret[l] = 'none'
            elif val == 'P':
                ret[l] = 'partial'
            elif val == 'C':
                ret[l] = 'complete'
        elif key == 'A':
            l = 'availability_impact'
            if val == 'N':
                ret[l] = 'none'
            elif val == 'P':
                ret[l] = 'partial'
            elif val == 'C':
                ret[l] = 'complete'
    return ret

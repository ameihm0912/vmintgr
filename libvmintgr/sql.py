import sqlite3
import datetime
import pytz
import calendar
import time

import vuln

class VMIntDB(object):
    SVER = 1

    def __init__(self, path):
        self._path = path
        self._conn = sqlite3.connect(self._path)

    def add_version(self):
        c = self._conn.cursor()
        c.execute('''INSERT INTO status VALUES (%d)''' % self.SVER)
        self._conn.commit()
        
    def create(self):
        c = self._conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS status (version INTEGER)''')
        c.execute('''SELECT MAX(version) FROM status''')
        rows = c.fetchall()

        v = rows[0][0]
        if v == None:
            self.add_version()

        c.execute('''CREATE TABLE IF NOT EXISTS assets
            (id INTEGER PRIMARY KEY, uid TEXT, aid INTEGER, ip TEXT,
            hostname TEXT, mac TEXT,
            UNIQUE (uid))''')

        c.execute('''CREATE TABLE IF NOT EXISTS vulns
            (id INTEGER PRIMARY KEY, asset INTEGER,
            vid INTEGER, title TEXT, cvss REAL,
            detected INTEGER,
            UNIQUE (asset, vid),
            FOREIGN KEY(asset) REFERENCES assets(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS workflow
            (id INTEGER PRIMARY KEY, vid INTEGER,
            lasthandled INTEGER, contact INTEGER,
            status INTEGER,
            FOREIGN KEY(vid) REFERENCES vulns(vid))''')

        c.execute('''CREATE TABLE IF NOT EXISTS cves
            (id INTEGER PRIMARY KEY, vid INTEGER, cve TEXT,
            UNIQUE (vid, cve),
            FOREIGN KEY (vid) REFERENCES vulns(vid))''')

        c.execute('''CREATE TABLE IF NOT EXISTS rhsas
            (id INTEGER PRIMARY KEY, vid INTEGER, rhsa TEXT,
            UNIQUE (vid, rhsa),
            FOREIGN KEY (vid) REFERENCES vulns(vid))''')

    def add_references(self, v, vid):
        c = self._conn.cursor()

        if v.cves != None:
            for cve in v.cves:
                try:
                    c.execute('''INSERT INTO cves VALUES (NULL,
                        %s, "%s")''' % (vid, cve))
                except sqlite3.IntegrityError:
                    continue
        if v.rhsa != None:
            for rhsa in v.rhsa:
                try:
                    c.execute('''INSERT INTO rhsas VALUES (NULL,
                        %s, "%s")''' % (vid, rhsa))
                except sqlite3.IntegrityError:
                    continue
        self._conn.commit()
            
    def add_vulnerability(self, v, dbassetid):
        c = self._conn.cursor()
        c.execute('''SELECT id, asset, vid, cvss FROM vulns
            WHERE asset=%d AND vid=%s''' % (dbassetid, v.vid))
        rows = c.fetchall()
        if len(rows) == 0:
            # This is a new issue for this asset
            c.execute('''INSERT INTO vulns VALUES (NULL, %d,
                %s, "%s", %f, %d)''' % (dbassetid, v.vid,
                v.title, v.cvss, v.discovered_date_unix))
            c.execute('''INSERT INTO workflow VALUES (NULL, %s,
                0, %d, 0)''' % (v.vid, int(calendar.timegm(time.gmtime()))))
            self._conn.commit()
        self.add_references(v, v.vid)

    def add_asset(self, uid, aid, address, mac, hostname):
        c = self._conn.cursor()
        c.execute('''SELECT id FROM assets WHERE uid="%s"''' % uid)
        rows = c.fetchall()
        if len(rows) == 0:
            c.execute('''INSERT INTO assets VALUES (NULL, "%s", %d,
                "%s", "%s", "%s")''' % (uid, aid, address, hostname, mac))
            self._conn.commit()
            return c.lastrowid
        else:
            return rows[0][0]

def db_init(path):
    ret = VMIntDB(path)
    return ret

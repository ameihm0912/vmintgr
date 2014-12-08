import sqlite3

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

def db_init(path):
    ret = VMIntDB(path)
    return ret

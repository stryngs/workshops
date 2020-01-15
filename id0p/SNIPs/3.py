import getpass
import psycopg2
import time

"""
This lesson is an intro into using the psycopg2 library.

It will take the user through the concepts of creating a table and then
inserting to the same table.
"""

pWord = getpass.getpass('password?\n')
dbName = 'workshop'
cStr = "dbname='workshop' user='tc' host='192.168.10.254' password={0}".format(pWord)
con = psycopg2.connect(cStr)
con.autocommit = True             ## Can cause speed issues depending on commits
db = con.cursor()

## pgsql table create
db.execute("""
           CREATE TABLE IF NOT EXISTS {0}(foo TEXT,
                                          bar INT,
                                          tstamp TIMESTAMPTZ);
           """.format(dbName))

## pgsql table insert
lDate = time.strftime('%Y-%m-%d', time.localtime())
lTime = time.strftime('%H:%M:%S', time.localtime())
db.execute("""
           INSERT INTO {0} (foo,
                            bar,
                            tstamp)
                       VALUES (%s,
                               %s,
                               %s);
           """.format('workshop'),
               ('hello',
                1,
                str(lDate) + ' ' + str(lTime) + '-05'))

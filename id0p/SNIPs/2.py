#!/usr/bin/python

import sqlite3 as lite
import time

"""
This lesson is an intro into using sqlite3 library.

It will take the user through the concepts of creating a table and then
inserting to the same table.
"""

sqlName ='workshop.sqlite3'
dbName = 'workshop'
con = lite.connect(sqlName, isolation_level = None)     ## Isolate == AutoCommit >> May cause speed issues
con.text_factory = str                                  ## Useful for goofy text
db = con.cursor()

## sqlite3 table create
db.execute("""
           CREATE TABLE IF NOT EXISTS {0}(foo TEXT,
                                          bar INTEGER,
                                          tstamp INTEGER);
           """.format(dbName))

## sqlite3 table INSERT
lDate = time.strftime('%Y-%m-%d', time.localtime())
lTime = time.strftime('%H:%M:%S', time.localtime())
db.execute("""
           INSERT INTO `{0}` VALUES(?,
                                   ?,
                                   ?);
           """.format(dbName), ('hello',
                 1,
                 str(lDate) + ' ' + str(lTime) + '-05'))

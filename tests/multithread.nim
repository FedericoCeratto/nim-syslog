# Compile with --threads:on
# Purpose of this test is to ensure that syslog module is thread-safe
# THREAD0 is expected to output same counter in APP-NAME and message content
# THREAD1 and THREAD2 are expected to output somethimes different counters
# in APP-NAME and message content due to async calls to openlog() and alert()
# in different threads

import threadpool
import os
import syslog

const maxIterations = 10

proc myLog(id: string) =
    for i in 0..maxIterations:
        syslog.openlog(id & "_" & $i)
        sleep(50)
        syslog.alert(id & "_" & $i)

spawn myLog("THREAD0")
sync()

spawn myLog("THREAD1")
sleep(170)
spawn myLog("THREAD2")
sync()

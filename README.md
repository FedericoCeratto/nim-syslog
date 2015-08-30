### nim-syslog
A simple syslog module for Nim. Supports Linux, BSD and Mac OS X.

Usage:

``` nim
import syslog

syslog.openlog("MyApp", logUser)  # optional
syslog.info("Good news")
syslog.debug("Psst")
syslog(logAlert, "Alert!")
syslog.closelog()  # optional
```

Supported priorities: emerg, alert, crit, error, info, debug, notice, warn[ing]

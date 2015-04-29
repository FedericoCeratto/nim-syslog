### nim-syslog
A simple syslog module for Nim. Supports Linux, BSD and mac os.

Usage:

``` nim
import syslog

syslog.info("Good news")
syslog.debug("Psst")
```

Supported priorities: emerg, alert, crit, error, info, debug, notice, warn[ing]

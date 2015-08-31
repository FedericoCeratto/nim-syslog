# Works both with --threads:off and --threads:on

import syslog

openlog("singlethread", logUser)
debug("Debug")
info("Info")
notice("Notice")
warning("Warning")
warn("Warn")
error("Error")
crit("Crit")
alert("Alert")
emerg("Emerg")
closelog()

#
#
#            Nim Unix Syslog Library
#     (c) Copyright 2015 Federico Ceratto
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#

## Module for Unix Syslog

import posix
import strutils
import times

type
  # severity codes
  SeverityEnum* = enum
    logEmerg = 0  # system is unusable
    logAlert = 1  # action must be taken immediately
    logCrit = 2  # critical conditions
    logErr = 3  # error conditions
    logWarning = 4  # warning conditions
    logNotice = 5  # normal but significant condition
    logInfo = 6  # informational
    logDebug = 7  # debug-level messages
  # facility codes
  FacilityEnum* = enum
    logKern = 0  # kernel messages
    logUser = 1  # random user-level messages
    logMail = 2  # mail system
    logDaemon = 3  # system daemons
    logAuth = 4  # security/authorization messages
    logSyslog = 5  # messages generated internally by syslogd
    logLpr = 6  # line printer subsystem
    logNews = 7  # network news subsystem
    logUucp = 8  # uucp subsystem
    logCron = 9  # clock daemon
    logAuthpriv = 10  # security/authorization messages (private)
    # other codes through 15 reserved for system use
    logLocal0 = 16  # reserved for local use
    logLocal1 = 17  # reserved for local use
    logLocal2 = 18  # reserved for local use
    logLocal3 = 19  # reserved for local use
    logLocal4 = 20  # reserved for local use
    logLocal5 = 21  # reserved for local use
    logLocal6 = 22  # reserved for local use
    logLocal7 = 23  # reserved for local use

const
  default_ident = ""
  default_facility = logUser
  default_use_ident_colon = true

# Globals
var module_ident = ""  # APP-NAME
var module_host_ident = ""  # HOSTNAME concatenated with APP-NAME
var module_facility = default_facility  # facility

proc array256(s: string): array[0..255, char] =
  var
    cnt = 0

  for i in s:
    result[cnt] = i
    cnt.inc()

  return result


when defined(macosx):
  const syslog_socket_fname = "/var/run/syslog"
else:
  const syslog_socket_fname = "/dev/log"

const syslog_socket_fname_a = syslog_socket_fname.array256

proc calculate_priority(facility: FacilityEnum, severity: SeverityEnum): int =
  ## Calculate priority value
  result = (cast[int](facility) shl 3) or cast[int](severity)

proc emit_log(facility: FacilityEnum, severity: SeverityEnum, msg: string) {.raises: [].} =

  var
    sock_addr: SockAddr
    tstamp: string
    logmsg: string

  let
    addr_len = Socklen(sizeof(sock_addr))
    flag: cint = 0
    sock = socket(AF_UNIX, SOCK_DGRAM, 0)
    pri = calculate_priority(facility, severity)

  try:
    tstamp = getTime().getLocalTime().format("MMM d HH:mm:ss")
    logmsg = "<$#>$# $#$#" % [$pri, $tstamp, $module_host_ident, msg]
  except ValueError:
    discard

  sock_addr = SockAddr(sa_family: posix.AF_UNIX, sa_data: syslog_socket_fname_a)

  var r = sock.connect(addr sock_addr, addr_len)
  if r != 0:
    try:
      writeLine(stderr, "Unable to connect to syslog unix socket " & syslog_socket_fname)
      return
    except IOError:
      return

  discard sock.send(cstring(logmsg), cint(logmsg.len), flag)

proc openlog*(ident: string = default_ident, facility: FacilityEnum = default_facility, use_ident_colon: bool = default_use_ident_colon) =
  module_ident = ident
  module_facility = facility
  if module_ident != "":
    if use_ident_colon:
      module_ident.add(":")
    # We have to skip HOSTNAME field (write two spaces) if ident is not empty
    # That's why we adding space in the beginning
    module_host_ident = " " & module_ident & " "

proc emerg*(msg: string) =
  emit_log(module_facility, logEmerg, msg)

proc alert*(msg: string) =
  emit_log(module_facility, logAlert, msg)

proc crit*(msg: string) =
  emit_log(module_facility, logCrit, msg)

proc error*(msg: string) =
  emit_log(module_facility, logErr, msg)

proc info*(msg: string) =
  emit_log(module_facility, logInfo, msg)

proc debug*(msg: string) =
  emit_log(module_facility, logDebug, msg)

proc notice*(msg: string) =
  emit_log(module_facility, logNotice, msg)

proc warn*(msg: string) =
  emit_log(module_facility, logWarning, msg)

proc warning*(msg: string) =
  emit_log(module_facility, logWarning, msg)

proc syslog*(severity: SeverityEnum, msg:string) =
  emit_log(module_facility, severity, msg)

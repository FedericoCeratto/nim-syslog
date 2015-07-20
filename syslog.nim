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
import locks

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
# TODO: Ensure locks are not reentrant
# Module settings
var glock_module_vars: Lock
var module_ident = ""  # APP-NAME
var module_host_ident = ""  # HOSTNAME concatenated with APP-NAME
var module_facility = default_facility  # facility
# Syslog socket
var glock_sock: Lock
var sock: SocketHandle = SocketHandle(-1)

proc array256(s: string): array[0..255, char] =
  var
    cnt = 0

  for i in s:
    result[cnt] = i
    cnt.inc()

  return result

proc reopen_syslog_connection() =
  when defined(macosx):
    const syslog_socket_fname = "/var/run/syslog"
  else:
    const syslog_socket_fname = "/dev/log"
  const syslog_socket_fname_a = syslog_socket_fname.array256

  var sock_addr {.global.}: SockAddr = SockAddr(sa_family: posix.AF_UNIX, sa_data: syslog_socket_fname_a)
  let addr_len {.global.} = Socklen(sizeof(sock_addr))

  acquire(glock_sock)
  if sock == SocketHandle(-1):
    sock = socket(AF_UNIX, SOCK_DGRAM, 0)
  var r = sock.connect(addr sock_addr, addr_len)
  release(glock_sock)
  if r != 0:
    try:
      writeLine(stderr, "Unable to connect to syslog unix socket " & syslog_socket_fname)
    except IOError:
      discard

proc check_sock_and_send(logmsg: string, flag: cint) =
  acquire(glock_sock)
  if sock == SocketHandle(-1):
    release(glock_sock)
    reopen_syslog_connection()
  else:
    release(glock_sock)

  acquire(glock_sock)
  var r = sock.send(cstring(logmsg), cint(logmsg.len), flag)
  release(glock_sock)

  if r == -1:
    if errno == ENOTCONN:
      reopen_syslog_connection()

proc calculate_priority(facility: FacilityEnum, severity: SeverityEnum): int =
  ## Calculate priority value
  result = (cast[int](facility) shl 3) or cast[int](severity)

proc emit_log(severity: SeverityEnum, msg: string) {.raises: [].} =
  var
    tstamp: string
    logmsg: string
    pri: int

  let flag: cint = 0

  try:
    tstamp = getTime().getLocalTime().format("MMM d HH:mm:ss")
    acquire(glock_module_vars)
    pri = calculate_priority(module_facility, severity)
    logmsg = "<$#>$# $#$#" % [$pri, $tstamp, $module_host_ident, msg]
    release(glock_module_vars)
  except ValueError:
    discard

  check_sock_and_send(logmsg, flag)

proc openlog*(ident: string = default_ident, facility: FacilityEnum = default_facility, use_ident_colon: bool = default_use_ident_colon) =
  acquire(glock_module_vars)
  module_ident = ident
  module_facility = facility
  if module_ident != "":
    if use_ident_colon:
      module_ident.add(":")
    # We have to skip HOSTNAME field (write two spaces) if ident is not empty
    # That's why we adding space in the beginning
    module_host_ident = " " & module_ident & " "
  release(glock_module_vars)
  reopen_syslog_connection()

proc emerg*(msg: string) =
  emit_log(logEmerg, msg)

proc alert*(msg: string) =
  emit_log(logAlert, msg)

proc crit*(msg: string) =
  emit_log(logCrit, msg)

proc error*(msg: string) =
  emit_log(logErr, msg)

proc info*(msg: string) =
  emit_log(logInfo, msg)

proc debug*(msg: string) =
  emit_log(logDebug, msg)

proc notice*(msg: string) =
  emit_log(logNotice, msg)

proc warn*(msg: string) =
  emit_log(logWarning, msg)

proc warning*(msg: string) =
  emit_log(logWarning, msg)

proc syslog*(severity: SeverityEnum, msg:string) =
  emit_log(severity, msg)

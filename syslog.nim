#
#
#            Nim Unix Syslog Library
#     (c) Copyright 2015 Federico Ceratto
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## Module for Unix Syslog

import posix
import os
import strutils
import times
import locks

# Maximum ident (APP-NAME) length - it is limited for GC safety
const identMaxLengh = 1024

type
  # severity codes
  SyslogSeverity* = enum
    logEmerg = 0  # system is unusable
    logAlert = 1  # action must be taken immediately
    logCrit = 2  # critical conditions
    logErr = 3  # error conditions
    logWarning = 4  # warning conditions
    logNotice = 5  # normal but significant condition
    logInfo = 6  # informational
    logDebug = 7  # debug-level messages
  # facility codes
  SyslogFacility* = enum
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
  # Type to store module ident gcsafe way
  IdentArray = tuple[length: int, content: array[0..identMaxLengh-1, char]]

# Helper procs
proc array256(s: string): array[0..255, char] =
  var
    cnt = 0
  for i in s:
    if cnt > 254:
      break
    result[cnt] = i
    cnt.inc()

proc stringToIdentArray(s: string): IdentArray =
  var
    cnt = 0
  for i in s:
    if cnt >= result.content.len-1:
      break
    result.content[cnt] = i
    cnt.inc()
  result.length = cnt

proc identArrayToString(arr: IdentArray): string =
  result = newString(arr.length)
  for i in 0..arr.length-1:
    result[i] = arr.content[i]
  result[arr.length] = '\0'

proc calculatePriority(facility: SyslogFacility, severity: SyslogSeverity): int =
  ## Calculate priority value
  result = (cast[int](facility) shl 3) or cast[int](severity)

proc makeHostIdent(ident: string): string =
  if ident != "":
    # We have to skip HOSTNAME field (write two spaces) if ident is not empty
    # That's why we adding space in the beginning
    result = " " & ident & ": "
  else:
    result = ""

# TODO: Use reliable algorithm for all OSes
proc appName(): string =
  result = getAppFilename().extractFilename()

# Constants
when defined(macosx):
  const syslog_socket_fname = "/var/run/syslog"
else:
  const syslog_socket_fname = "/dev/log"
const
  syslog_socket_fname_a = syslog_socket_fname.array256
  defaultIdent = ""
  defaultFacility = logUser

# Globals
# TODO: Ensure lock is not reentrant
var gLockSyslog: Lock
# Module settings
var moduleIdent = appName().stringToIdentArray()  # APP-NAME
var moduleFacility = defaultFacility
# Syslog socket
var sock: SocketHandle = SocketHandle(-1)

# Internal procs (used inside critical section)
proc reopenSyslogConnectionInternal() =
  var sock_addr {.global.}: SockAddr = SockAddr(sa_family: posix.AF_UNIX, sa_data: syslog_socket_fname_a)
  let addr_len {.global.} = Socklen(sizeof(sock_addr))
  if sock == SocketHandle(-1):
    sock = socket(AF_UNIX, SOCK_DGRAM, 0)
  var r = sock.connect(addr sock_addr, addr_len)
  if r != 0:
    try:
      writeLine(stderr, "Unable to connect to syslog unix socket " & syslog_socket_fname)
    except IOError:
      discard

proc openlogInternal(ident: string, facility: SyslogFacility) =
  module_ident = ident.stringToIdentArray()
  module_facility = facility
  reopenSyslogConnectionInternal()

proc checkSockAndSendInternal(logMsg: string, flag: cint) =
  if sock == SocketHandle(-1):
    reopenSyslogConnectionInternal()
  var r = sock.send(cstring(logMsg), cint(logMsg.len), flag)
  if r == -1:
    if errno == ENOTCONN:  # TODO: Ensure errno is thread-safe
      reopenSyslogConnectionInternal()

# Send syslog message proc (acquires global syslog lock)
proc emitLog(severity: SyslogSeverity, msg: string) =
  let
    flag: cint = 0
  var
    pri: int
    timeStamp: string
    logMsg: string
    hostIdent: string
  acquire(gLockSyslog)
  defer: release(gLockSyslog)
  pri = calculate_priority(moduleFacility, severity)
  timeStamp = getTime().getLocalTime().format("MMM d HH:mm:ss")
  hostIdent = make_host_ident(module_ident.ident_array_to_string())
  logMsg = "<$#>$# $#$#" % [$pri, $timeStamp, $hostIdent, msg]
  checkSockAndSendInternal(logMsg, flag)

# Exported procs
proc openlog*(ident: string = defaultIdent, facility: SyslogFacility = defaultFacility) {.gcsafe.} =
  acquire(gLockSyslog)
  defer: release(gLockSyslog)
  openlogInternal(ident, facility)

proc emerg*(msg: string) {.gcsafe.} =
  emitLog(logEmerg, msg)

proc alert*(msg: string) {.gcsafe.} =
  emitLog(logAlert, msg)

proc crit*(msg: string) {.gcsafe.} =
  emitLog(logCrit, msg)

proc error*(msg: string) {.gcsafe.} =
  emitLog(logErr, msg)

proc info*(msg: string) {.gcsafe.} =
  emitLog(logInfo, msg)

proc debug*(msg: string) {.gcsafe.} =
  emitLog(logDebug, msg)

proc notice*(msg: string) {.gcsafe.} =
  emitLog(logNotice, msg)

proc warn*(msg: string) {.gcsafe.} =
  emitLog(logWarning, msg)

proc warning*(msg: string) {.gcsafe.} =
  emitLog(logWarning, msg)

proc syslog*(severity: SyslogSeverity, msg:string) {.gcsafe.} =
  emitLog(severity, msg)

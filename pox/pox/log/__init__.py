# Copyright 2011,2023 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from logging.handlers import *
import traceback
import json

_formatter = logging.Formatter(logging.BASIC_FORMAT)


class TextSocketHandler (SocketHandler):
  _initted = False

  def __init__ (self, host, port, *args, **kw):
    super().__init__(host, port)
    self._args = (args,kw)

  def _init (self, color=False, entire=False, autolevels=False):
    # This needs to be called later, once other log stuff has happened
    self._initted = True
    if color:
      old_format = self.formatter.format
      from log.color import _proc, _color, LEVEL_COLORS
      # This is mostly taken from log.color
      if entire:
        def new_format (record):
          msg = _proc(old_format(record), record.levelname)
          color = LEVEL_COLORS.get(record.levelname)
          if color is None:
            return msg
          return _color(color, msg)
      else:
        def new_format (record):
          color = LEVEL_COLORS.get(record.levelname)
          oldlevelname = record.levelname
          if (color is not None) and autolevels:
            record.levelname = "@@@level" + record.levelname + "@@@reset"
          r = _proc(old_format(record), oldlevelname)
          record.levelname = oldlevelname
          return r
      self.formatter.format = new_format

  def makePickle (self, record):
    if not self._initted: self._init(*self._args[0], **self._args[1])
    return self.formatter.format(record).encode() + b'\n'


class JSONSocketHandler (SocketHandler):
  _attributes = [
    'created','filename','funcName','levelname','levelno','lineno',
    'module','msecs','name','pathname','process','processName',
    'relativeCreated','thread','threadName','args','asctime',
  ]

  def __init__ (self, host, port, nl=True, full=False, attrs="", xattrs=""):
    super().__init__(host, port)
    if not full and not attrs and not xattrs:
      attrs = 'levelname levelno name'

    self._attributes = list(self._attributes)

    if attrs:
      attrs = attrs.strip().replace(","," ").replace(":"," ").split()
      self._attributes = []
      for x in attrs:
        assert x in JSONSocketHandler._attributes,x
        self._attributes.append(x)
    if xattrs:
      xattrs = xattrs.replace(","," ").replace(":"," ").split()
      for x in xattrs:
        if x in self._attributes:
          self._attributes.remove(x)

    self._asctime = False
    if 'asctime' in self._attributes:
      self._attributes.remove('asctime')
      self._asctime = True

    self._sep = b''
    if nl: self._sep = b'\n'

  def makePickle (self, record):
    # This is based on messenger.log_service
    o = {'message' : self.format(record)}
    #o['message'] = record.getMessage()
    for attr in self._attributes:
      o[attr] = getattr(record, attr)
    if self._asctime:
      o['asctime'] = self.formatter.formatTime(record) #, self._dateFormat)
    if record.exc_info:
      o['exc_info'] = [str(record.exc_info[0]),
                       str(record.exc_info[1]),
                       traceback.format_tb(record.exc_info[2],1)]
      o['exc'] = traceback.format_exception(*record.exc_info)
    return json.dumps(o).encode() + self._sep


def _parse (s):
  if s.lower() == "none": return None
  if s.lower() == "false": return False
  if s.lower() == "true": return True
  if s.startswith("0x"): return int(s[2:], 16)
  try:
    return int(s)
  except:
    pass
  try:
    return float(s)
  except:
    pass
  if s.startswith('"') and s.endswith('"') and len(s) >= 2:
    return s[1:-1]
  return s


#NOTE: Arguments are not parsed super-intelligently.  The result is that some
#      cases will be wrong (i.e., filenames that are only numbers or strings
#      with commas).  But I think this should be usable for most common cases.
#      You're welcome to improve it.

def launch (__INSTANCE__ = None, **kw):
  """
  Allows you to configure log handlers from the commandline.

  Examples:
   ./pox.py log --file=pox.log,w --syslog --no-default
   ./pox.py log --*TimedRotatingFile=filename=foo.log,when=D,backupCount=5

  The handlers are most of the ones described in Python's logging.handlers,
  and the special one --no-default, which turns off the default logging to
  stderr.

  Arguments are passed positionally by default.  A leading * makes them pass
  by keyword.

  If a --format="<str>" is specified, it is used as a format string for a
  logging.Formatter instance for all loggers created with that invocation
  of the log module.  If no loggers are created with this instantiation,
  it is used for the default logger.
  If a --format is specified, you can also specify a --datefmt="<str>"
  where the string is a strftime format string for date/time stamps.
  If --format is specified without a parameter, the format from the default
  logger is used.
  """

  if 'format' in kw:
    import pox.core
    df = None
    if kw['format'] is True:
      kw['format'] = pox.core._default_log_handler.formatter._fmt # Hacky
      df = pox.core._default_log_handler.formatter.datefmt
    df = kw.pop("datefmt", df)
    if not df: df = None
    formatter = logging.Formatter(kw['format'], datefmt=df)
    del kw['format']
    if len(kw) == 0:
      # Use for the default logger...
      pox.core._default_log_handler.setFormatter(formatter)
  else:
    formatter = _formatter

  def standard (use_kw, v, C):
    # Should use a better function than split, which understands
    # quotes and the like.
    if v is True:
      h = C()
    else:
      if use_kw:
        v = dict([x.split('=',1) for x in v.split(',')])
        v = {k:_parse(v) for k,v in v.items()}
        h = C(**v)
      else:
        v = [_parse(p) for p in v.split(',')]
        h = C(*v)
    h.setFormatter(formatter)
    logging.getLogger().addHandler(h)

  for _k,v in kw.items():
    k = _k
    use_kw = k.startswith("*")
    if use_kw: k = k[1:]
    k = k.lower()
    if k == "no_default" and v:
      import pox.core
      logging.getLogger().removeHandler(pox.core._default_log_handler)
      logging.getLogger().addHandler(logging.NullHandler())
    elif k == "stderr":
      standard(use_kw, v, lambda : logging.StreamHandler())
    elif k == "stdout":
      import sys
      standard(use_kw, v, lambda : logging.StreamHandler(sys.stdout))
    elif k == "file":
      standard(use_kw, v, logging.FileHandler)
    elif k == "watchedfile":
      standard(use_kw, v, WatchedFileHandler)
    elif k == "rotatingfile":
      standard(use_kw, v, RotatingFileHandler)
    elif k == "timedrotatingfile":
      standard(use_kw, v, TimedRotatingFileHandler)
    elif k == "socket":
      standard(use_kw, v, SocketHandler)
    elif k == "textsocket":
      standard(use_kw, v, TextSocketHandler)
    elif k == "jsonsocket":
      standard(use_kw, v, JSONSocketHandler)
    elif k == "datagram":
      standard(use_kw, v, DatagramHandler)
    elif k == "syslog":
      if v is True:
        v = []
        use_kw = False
      else:
        v = [_parse(p) for p in v.split(',')]
      if use_kw:
        v = dict([x.split('=',1) for x in v])
        if 'address' in v or 'port' in v:
          address = ('localhost', SYSLOG_UDP_PORT)
          v['address'] = (v.get('address', 'localhost'),
                          v.get('port', SYSLOG_UDP_PORT))
          if 'port' in v: del v['port']
        elif 'address' == '' or 'address' == '*':
          v['address'] = '/dev/log'
        h = SysLogHandler(**v)
      else:
        if len(v) > 1:
          v[0] = (v[0], v[1])
          del v[1]
        elif len(v) > 0:
          if v[0] == '' or v[0] == '*':
            v[0] = '/dev/log'
          else:
            v[0] = (v[0], SYSLOG_UDP_PORT)
        h = SysLogHandler(*v)
      logging.getLogger().addHandler(h)
    elif k == "http":
      standard(use_kw, v, HTTPHandler)
    else:
      raise TypeError("Invalid argument: " + _k)

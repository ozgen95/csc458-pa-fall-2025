# Copyright 2011,2012 James McCauley
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

"""
A library for implementing JSON-RPC based web services

This is lightweight, low on features, and not a whole lot of effort
has been paid to really complying with the JSON-RPC spec.  Feel
free to improve it. ;)

It'd be nice to factor the JSON-RPC stuff out so that it could
be used with something besides just HTTP.

Also, it has some capability for compatibility with Qooxdoo.

See the openflow.webservice component for an example.

IMPORTANT NOTE:
Per the specifiction, JSON-RPC requests without an "id" field are
*notifications* which do not require and should not receive responses.
In other words, if you want to get a reply to a request, you must
include an "id" member in the request.  You can, for example, just
set it to 1 if you don't have anything better to set it to.
"""

import json
import sys
from pox.web.webcore import *
from pox.core import core
log = core.getLogger()


# A long polling handler can return this if it notices that the
# connection has closed.
ABORT = object()


class JSONRPCHandler (SplitRequestHandler):
  """
  Meant for implementing JSON-RPC web services

  Implement RPC methods by prefacing them with "_exec_".

  config keys of note:
   "auth" is a function which takes a username and password and returns
       True if they are a valid user.  If set, turns on authentication.
   "auth_realm" is the optional authentication realm name.
   "qx" turns on Qooxdoo mode by default (it's usually switched on by
       seeing a "service" key in the request).

  There are a couple of extensions to JSON-RPC:

  If you want to use positional AND named parameters, in a request, use
  "params" for the former and "kwparams" for the latter.

  There's an optional "service" key in requests.  This comes from qooxdoo.
  If it is given, look for the _exec_ method on some otherobject instead
  of self.  Put the additional services in an arg named 'services'.
  """
  protocol_version = 'HTTP/1.1'

  QX_ERR_ILLEGAL_SERVICE = 1
  QX_ERR_SERVICE_NOT_FOUND = 2
  QX_ERR_CLASS_NOT_FOUND = 3
  QX_ERR_METHOD_NOT_FOUND = 4
  QX_ERR_PARAMETER_MISMATCH = 5
  QX_ERR_PERMISSION_DENIED = 6

  QX_ORIGIN_SERVER = 1
  QX_ORIGIN_METHOD = 2

  ERR_PARSE_ERROR = -32700             # WE USE THIS
  ERR_INVALID_REQUEST = -32600
  ERR_METHOD_NOT_FOUND = -32601        # WE USE THIS
  ERR_INVALID_PARAMS = -32602
  ERR_INTERNAL_ERROR = -32603          # WE USE THIS
  ERR_SERVER_ERROR = -32000 # to -32099  WE USE THIS

  ERR_METHOD_ERROR = 99 # We use this for errors in methods

  RPC_TO_HTTP_ERR = {
    ERR_PARSE_ERROR      : 500,
    ERR_INVALID_REQUEST  : 400,
    ERR_METHOD_NOT_FOUND : 404,
    ERR_INVALID_PARAMS   : 500,
    ERR_INTERNAL_ERROR   : 500,
  }

  RPC_TO_TEXT_ERR = {
    ERR_PARSE_ERROR      : 'ERR_PARSE_ERROR',
    ERR_INVALID_REQUEST  : 'ERR_INVALID_REQUEST',
    ERR_METHOD_NOT_FOUND : 'ERR_METHOD_NOT_FOUND',
    ERR_INVALID_PARAMS   : 'ERR_INVALID_PARAMS',
    ERR_INTERNAL_ERROR   : 'ERR_INTERNAL_ERROR',
    ERR_SERVER_ERROR     : 'ERR_SERVER_ERROR',
    ERR_METHOD_ERROR     : 'ERR_METHOD_ERROR',
  }

  ERROR_XLATE = {
    ERR_PARSE_ERROR      : (1, QX_ERR_ILLEGAL_SERVICE), # Nonsense
    ERR_METHOD_NOT_FOUND : (1, QX_ERR_METHOD_NOT_FOUND),
    ERR_INTERNAL_ERROR   : (),
    ERR_SERVER_ERROR     : (),
  }

  # Use Qooxdoo mode
  _qx = False

  # Use HTTP status codes?
  # True, False, or None (only for JSON-RPC 1.0)
  _use_http_codes = None

  def _init (self):
    # Maybe the following arg-adding feature should just be part of
    # SplitRequestHandler?

    if self.args is None: self.args = {}
    for k,v in self.args.items():
      setattr(self, "_arg_" + k, v)

    self.auth_function = self.args.get('auth', None)
    self.auth_realm = self.args.get('auth_realm', "JSONRPC")

    self._qx = self.args.get('qx', self._qx)
    self._use_http_codes = self.args.get('use_http_codes',
                                         self._use_http_codes)

  def _send_auth_header (self):
    if self.auth_function:
      self.send_header('WWW-Authenticate',
                       'Basic realm="%s"' % (self.auth_realm,))

  def _do_auth (self):
    if not self.auth_function:
      return True

    auth = self.headers.get("Authorization", "").strip()
    success = False
    if auth.lower().startswith("basic "):
      try:
        auth = base64.decodebytes(auth[6:].strip()).split(':', 1)
        success = self.auth_function(auth[0], auth[1])
      except:
        pass
    if not success:
      self.send_response(401, "Authorization Required")
      self._send_auth_header()
      self.end_headers()
    return success

  def _translate_error (self, e):
    if not 'error' in e: return
    if self._qx:
      if e['code'] < 0:
        c,o = ERROR_XLATE.get(e['code'], (1, self.QX_ERR_ILLEGAL_SERVICE))
        e['code'] = c
        e['origin'] = o
      else:
        e['origin'] = QX_ORIGIN_METHOD

  def _handle (self, data):
    try:
      try:
        service = self
        if 'services' in self.args:
          if 'service' in data:
            service = self.args['services'].get(data['service'], self)
            self._qx = True # This is a qooxdoo request
        method = "_exec_" + data.get('method')
        method = getattr(service, method)
      except:
        response = {}
        response['error'] = {'code':self.ERR_METHOD_NOT_FOUND,
                             'message':'Method not found'}
        return response

      params = data.get('params', [])
      if isinstance(params, dict):
        kw = params
        params = []
      else:
        kw = data.get('kwparams', {})

      try:
        r = method(*params,**kw)

        # If they don't care about the return value, don't make them actually
        # return a dict.
        if r is None: r = {}

        # If it hasn't been locally overriden, just echo back whatever
        # version the request said it was.
        if 'jsonrpc' in data:
          if 'jsonrpc' not in r:
            r['jsonrpc'] = data['jsonrpc']

        return r
      except:
        response = {}
        t,v,_ = sys.exc_info()
        response['error'] = {'message': "%s: %s" % (t,v),
                             'code':self.ERR_METHOD_ERROR}
        import traceback
        response['error']['data'] = {'traceback':traceback.format_exc()}
        log.exception("While handling %s...", data.get('method'))
        return response

    except:
      response = {}
      t,v,_ = sys.exc_info()
      response['error'] = {'message': "%s: %s" % (t,v),
                           'code':self.ERR_INTERNAL_ERROR}
      return response

  def do_POST (self):
    if not self._do_auth():
      return

    dumps_opts = {}

    #FIXME: this is a hack
    if 'pretty' in self.path:
      dumps_opts = {'sort_keys':True, 'indent':2}

    def reply (response, version=None):
      code = 200
      message = "OK"

      # Use HTTP codes?
      http_codes = self._use_http_codes
      if http_codes is None: # Only for 1.0
        http_codes = version is None

      orig = response
      #if not isinstance(response, basestring):
      if isinstance(response, list):
        # For batched mode, don't bother with the HTTP status code (which I
        # think is a bad idea under any circumstance, but whatever).
        # (We *do* still send 204 if none returned anything.)
        for r in response: self._translate_error(r)
      elif response is not None:
        if http_codes:
          if response.get('error'):
            ocode = response['error'].get('code')
            code = self.RPC_TO_HTTP_ERR.get(ocode, 500)
            message = self.RPC_TO_TEXT_ERR.get(ocode, "Unknown error")

        self._translate_error(response)

      if response is None:
        response = ''
        if http_codes:
          code = 204
          message = "No Content"
      else:
        response = json.dumps(response, default=str, **dumps_opts)
        response = response.strip()
        if len(response) and not response.endswith("\n"): response += "\n"

      try:
        self.send_response(code, message)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response.encode())
      except IOError as e:
        if e.errno == 32:
          if isinstance(orig, dict) and 'error' in orig:
            log.info("Socket closed when writing error response")
          else:
            log.warning("Socket closed when writing response")
            #log.debug(" response was: " + response)
        else:
          log.exception("Exception while trying to send JSON-RPC response")
        try:
          self.wfile.close()
        except:
          pass
        return False
      except:
        log.exception("Exception while trying to send JSON-RPC response")
        return False
      return True

    l = self.headers.get("Content-Length", "")
    data = ''
    if l == "":
      data = self.rfile.read()
    else:
      data = self.rfile.read(int(l))
    try:
      data = json.loads(data)
    except Exception:
      # This is a tricky case.  We don't really know how to respond, because
      # we don't know the version, because we didn't parse the request
      # successfully.  So we sort of split the difference.  We add the
      # version 2.0 field to the response, with the idea that some 2.0
      # clients might need it, but 1.0 clients probably won't notice.
      # But we don't pass 'version' into reply(), so we may get HTTP error
      # codes in some cases that we normally wouldn't.  The worst thing
      # that can probably happen due to that is that the client isn't
      # expecting it and throws an exception, though, which seems fine
      # since if we've got a parse error, things have already gone
      # very, very wrong (and its probably their fault anyway).
      response = {'jsonrpc': '2.0'}
      response['error'] = {'code':self.ERR_PARSE_ERROR,
                           'message':'Parse error'}
      return reply(response)

    single = False
    if not isinstance(data, list):
      data = [data]
      single = True

    responses = []
    rversion = False
    mixed_warn = False

    for req in data:
      response = self._handle(req) # Should never raise an exception
      if response is ABORT:
        return
      version = req.get('jsonrpc')
      if rversion is not False and version != rversion:
        if not mixed_warn:
          mixed_warn = True
          log.warning("Batch-mode RPCs with mixed versions!")
      rversion = version

      if 'id' in req or 'error' in response:
        response['id'] = req.get('id')
        responses.append(response)
        if 'error' in response:
          if version == '2.0':
            response.pop('result', None)
          else:
            response['result'] = None
        elif 'result' not in response:
          # Have 'id' but no result...
          response['result'] = None

    if len(responses) == 0:
      responses = None
    else:
      if single:
        responses = responses[0]

    reply(responses, version=rversion)


class QXJSONRPCHandler (JSONRPCHandler):
  """
  A subclass of JSONRPCHandler which speaks something closer to
  qooxdoo's version JSON-RPC.
  """
  _qx = True
  #TODO: Implement the <SCRIPT> based GET method for cross-domain


def make_error (msg = "Unknown Error",
                code = JSONRPCHandler.ERR_SERVER_ERROR,
                data = None):
  e = {'code':code,'message':msg}
  if data is not None:
    e['data'] = data
  r = {'error':e}
  return r



class ExampleHandler (JSONRPCHandler):
  """
  A simple example for JSON-RPC
  """

  def _exec_subtract (self, minuend, subtrahend):
    """
    Subtract numbers

    This is compatible with an example from the JSON-RPC 2.0 spec.
    """
    return dict(result=minuend - subtrahend)

  def _exec_log (self, message):
    log.info("RPC: %s", str(message))


def example (no_cookieguard=False):
  """
  Sets up the simple ExampleHandler
  """
  class MyExampleHandler (ExampleHandler):
    pass
  if no_cookieguard:
    MyExampleHandler.pox_cookieguard = False

  def _launch ():
    core.WebServer.set_handler("/json-rpc/", MyExampleHandler)
  core.call_when_ready(_launch, ["WebServer"], name = "jsonrpc:example")

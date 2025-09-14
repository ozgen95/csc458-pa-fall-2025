# Copyright 2023 James McCauley
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
A simple JSON-RPC-Over-HTTP client library

To use it, you create a Server object.  You then just call methods on it.

  server = Server("http://my_api_endpoint.example.com/invoke")
  print( server.subtract(43, 23) )

Only JSON-RPC 2.0 is supported, and it always does normal function calls,
not notifications (i.e., it always says it expects a return value).

It works with asyncio too.  Just use AsyncServer instead of Server, and
await your RPC calls.  (This is not currently efficient at all -- it
internally uses blocking code on a separate thread.  But it works.)

It doesn't really have any POX dependencies, and could be used outside
of POX easily.
"""

from urllib import request
import asyncio
import json

try:
  from pox.lib.util import multi_instance
  from pox.lib.config_eval import eval_list
  from pox.core import core
  _ua = "POX/%s(%s)" % (".".join(map(str, core.version)),
                        core.version_name)
  def _dbg (msg):
    core.getLogger("psjsonrpc").debug("%s", msg)

except Exception:
  multi_instance = lambda x: x
  _ua = None
  _dbg = print


class ProxyFunctionBase:
  def __init__ (self, server, name):
    self.server = server
    self.name = name

  def _build_request (self, args, kw):
    if args and kw: raise RuntimeError("Can't have named and unnamed arguments")
    if kw: args = kw
    rid = self.server._new_id()
    req = dict(jsonrpc="2.0", method=self.name, params=kw or args, id=rid)
    return rid,req

  def _process_response (self, rid, response):
    err = response.get('error')
    if err:
      # Assume err is proper error object; otherwise weird exception!
      code = err.get('code')
      message = err.get('message')
      data = err.get('data')
      o = f"RPC err {code}/{message}"
      if data: o += f": {data}"
      raise RuntimeError(o)

    assert response.get('jsonrpc') == "2.0"
    assert response.get('id') == rid
    return response['result']

  def _make_request (self, data):
    headers = {'Content-Type': 'application/json-rpc',
               'Accept':       'application/json-rpc'}
    if _ua: headers['User-Agent'] = _ua
    data = json.dumps(data).encode()
    if self.server._debug:
      _dbg(f"> {data.decode()}")
    req = request.Request(self.server._url, data=data, headers=headers)
    with request.urlopen(req, timeout=self.server._timeout) as response:
      ct = response.headers.get('Content-Type', '')
      assert ct.startswith('application/json')
      rdata = response.read()
      if self.server._debug:
        _dbg(f"< {rdata.decode().strip()}")
      return json.loads(rdata.decode())


class AsyncProxyFunction (ProxyFunctionBase):
  async def __call__ (self, *args, **kw):
    rid,req = self._build_request(args, kw)
    response = await asyncio.to_thread(self._make_request, req)
    return self._process_response(rid, response)


class ProxyFunction (ProxyFunctionBase):
  def __call__ (self, *args, **kw):
    rid,req = self._build_request(args, kw)
    response = self._make_request(req)
    return self._process_response(rid, response)


class Server:
  _next_id = 1
  _timeout = 3
  _debug = False
  _proxyclass = ProxyFunction

  def __init__ (self, url):
    self._url = url

  def _new_id (self):
    r = self._next_id
    self._next_id += 1
    return r

  def _get_proxy (self, name):
    return self._proxyclass(self, name)

  def __getattr__ (self, name):
    return self._get_proxy(name)


class AsyncServer (Server):
  _proxyclass = AsyncProxyFunction



@multi_instance
def debug (disable=False):
  """
  Turn on (or off) debugging logs
  """
  enable = not disable
  Server._debug = enable



@multi_instance
def call (invocation, **kw):
  """
  A test method -- lets you invoke RPCs from the command line

  JSON-RPC supports both named and unnamed parameters, and this launcher can
  be used either way.  For example, the following are equivalent:
    lib.pxjsonrpc:call="subtract@http://127.0.0.1:8000/json-rpc/(42,23)"
    lib.pxjsonrpc:call="subtract@http://127.0.0.1:8000/json-rpc/" \
      --minuend=42 --subtrahend=23"

  The above examples work with the example service, which you can run like:
    web web.jsonrpc:example --no-cookieguard
  """
  method,rest = invocation.split("@", 1)
  if '(' in rest:
    url,args = rest.split("(", 1)
    if not args.endswith(")"):
      raise RuntimeError("Expected parameter list ending with ')'")
    args = args[:-1]
    if kw:
      raise RuntimeError("Cannot mix named and unnamed arguments")
    args = eval_list(args)
  else:
    url = rest
    args = []
    import ast
    kw = {k:ast.literal_eval(v) for k,v in kw.items()}


  def _handle_UpEvent (e):
    server = Server(url=url)
    func = server._get_proxy(method)
    result = func(*args, **kw)
    log = core.getLogger("JSON-RPC")
    log.info("Got return value: " + str(result))

  core.add_listener(_handle_UpEvent)

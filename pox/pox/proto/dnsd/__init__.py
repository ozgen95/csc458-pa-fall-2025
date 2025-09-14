# Copyright 2021,2023 James McCauley
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
A not-particularly-good, but working DNS server

It's definitely not full featured, and doesn't even really try to honor
all of the RFCs... but it works well enough to resolve A and AAAA records
to all the software I've tried.  It also can serve HTTPS records with
ALPN info, which is how you can, for example, convince browsers to
connect via HTTP/2 or HTTP/3 without first connecting via HTTP/1.1.

Besides serving over the usual UDP protocol described in RFC1035, it can
also use the webcore component to serve DNS Over HTTPS (DoH) as described
in RFC8484.

There's a related component that allows some simple web-based administration,
and another which provides a web-based API compatible with existing
dynamic DNS services and therefore with existing DNS-update tools.
"""

from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, IPAddr6, IP_ANY
import threading
from pox.core import core
from pox.lib.util import multi_instance
from socket import *
from select import select
import re
import struct
import base64
import random
import time
from pox.web.webcore import SplitRequestHandler, cgi_parse_header

log = core.getLogger()

DNS = pkt.dns
RR = pkt.dns.rr

log = core.getLogger()


# Default list of queries to outright ignore.  These are known probes or
# amplification attacks.
_default_ignore = set("""
sl
id.server
version.bind
hostname.bind
www.cybergreen.net
access-board.gov
qq.com
www.qq.com
mz.gov.pl
ip.parrotdns.com
dnsscan.shadowserver.org
test.openresolver.com
cyberresilience.io
rr-mirror.research.nawrocki.berlin
dns-test.research.a10protects.com
*.openresolvertest.net
*.asertdnsresearch.com
*.odns.m.dnsscan.top
*.openresolve.rs
*.openresolverproject.org
*.open-resolver-scan.research.icann.org
""".strip().lower().split())


def _fa (addr):
  """ Format address """
  if isinstance(addr, tuple) and len(addr) == 2:
    # Probably an IP address!
    p = addr[1]
    if p == -1: p = "Web"
    return f"{addr[0]}:{p}"
  return str(addr)


class DNSRecord (object):
  DEFAULT_TTL = 60 * 10
  DEFAULT_ALPN = False
  https_addr_hint = False
  shuffle = False

  def __init__ (self, name, value, type=RR.A_TYPE, ttl=DEFAULT_TTL):
    if not isinstance(value, list):
      value = [value]
    self.name = name
    self._values = value
    self.type = type
    self.ttl = ttl
    self._synthetic_https_alpn = self.DEFAULT_ALPN # Can be a str like 'h2,h3'

  @property
  def synthetic_https_alpn (self):
    # Should this also be allowed for CNAMEs?
    if not self.is_address: return False
    return self._synthetic_https_alpn

  @synthetic_https_alpn.setter
  def synthetic_https_alpn (self, value):
    self._synthetic_https_alpn = value

  @property
  def value (self):
    return self.values[0]

  @property
  def values (self):
    if not self.shuffle: return self._values
    t = list(self._values)
    random.shuffle(t)
    return t

  @property
  def value_str (self):
    if len(self.values) == 1:
      return str(self.values[0])
    return ",".join(str(x) for x in self.values)

  @property
  def is_address (self):
    return self.type == RR.A_TYPE or self.type == RR.AAAA_TYPE

  def __repr__ (self):
    t = pkt.DNS.rrtype_to_str.get(self.type, str(self.type))
    n = self.name
    if isinstance(n, bytes): n = n.decode("ascii")
    alpn = ''
    if self.synthetic_https_alpn:
      alpn = f" alpn={self.synthetic_https_alpn}"
    return (f"{type(self).__name__}(name={n} value={self.value_str}"
           +f" type={t} ttl={self.ttl}{alpn})")

  def make_https_record (self, alpn=None, addr_hint=None):
    """
    Synthesize an HTTPS record

    If alpn is None, use the default from synthesize_https_alpn

    Note that since this synthetically generates an HTTPS record from a
    single A or AAAA record, if addr_hint is turned on, it will only
    have one of the A or AAAA addresses!
    """
    assert self.is_address

    if addr_hint is None: addr_hint = self.https_addr_hint

    if alpn is None: alpn = self.synthetic_https_alpn
    if not alpn: alpn = ''

    if isinstance(alpn, str):
      alpn = alpn.encode("ascii")
    if isinstance(alpn, bytes):
      alpn = alpn.replace(b",", b" ").split()
    alpn = [x.encode() if isinstance(x,str) else x for x in alpn]
    alpn = [struct.pack("B", len(x)) + x for x in alpn]
    alpn = b''.join(alpn)
    parms = {}
    hv = [1,b'',parms]
    parms[DNS.SVCPK_ALPN] = alpn
    if addr_hint: # Address hints?
      if self.type == RR.A_TYPE:
        parms[DNS.SVCPK_IPV4HINT] = self.value.raw
      else: # AAAA
        parms[DNS.SVCPK_IPV6HINT] = self.value.raw
    if not addr_hint and not alpn:
      return None
    hr = DNSRecord(self.name, [hv], RR.HTTPS_TYPE, self.ttl)

    return hr


class DNSServer (object):
  counter_badclass = 0
  counter_ignore   = 0
  counter_norecord = 0
  counter_novalue  = 0
  counter_okay     = 0

  def __init__ (self, bind_ip=None, default_suffix=None, udp=True, doh=None,
                bind_port=53, history=0, ignore=None):
    self.wild_ignore = []
    if ignore is not None:
      ignore = set(ignore)
      if "." in ignore:
        ignore.remove(".")
        ignore.update(_default_ignore)
      def fixb (s):
        if isinstance(s, str):
          return s.encode("ascii")
        return s
      ignore = [fixb(x) for x in ignore]
      self.wild_ignore = set(x[1:] for x in ignore if x.startswith(b"*"))
      ignore = set(x for x in ignore if not x.startswith(b"*"))
    self.ignore = ignore

    self.history_length = history
    self.history = [] # (time, name, requester)
    self.log = log
    self.db = {}
    self.bind_ip = bind_ip
    self.bind_port = bind_port or 53
    self.default_suffix = default_suffix

    self._enable_udp = udp
    self._enable_doh = doh

    core.add_listener(self._handle_GoingUpEvent)

  def _get (self, name, qtype):
    if isinstance(name, bytes): name = name.decode("ascii")
    name = name.lower()
    rs = [x for x in self.db.get(name, []) if x.type == qtype]
    if not rs: return None
    return rs[0]

  def _set (self, name, r):
    if isinstance(name, bytes): name = name.decode("ascii")
    if name not in self.db:
      self.db[name] = []

    self.del_record(name, r.type)

    self.db[name].append(r)
    self.log.debug(f"Set record {r}")
    return True

  def _handle_GoingUpEvent (self, event):
    if self._enable_udp:
      try:
        self._do_enable_udp()
      except Exception:
        self.log.exception("Couldn't enable UDP")
    if self._enable_doh is not False:
      try:
        self._do_enable_doh()
      except Exception:
        self.log.exception("Couldn't enable DNS-Over-HTTPS")

  def _do_enable_doh (self):
    def enable_dns_over_https ():
      self.log.info("Starting to serve DNS-Over-HTTPS")
      core.WebServer.set_handler("/dns-query/", DOHHandler)
    if hasattr(core, 'WebServer'):
      enable_dns_over_https()
    elif self._enable_doh:
      self.log.error("Can't do DoH without web server running!")

  def _do_enable_udp (self):
    self.sock = s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    if self.bind_ip is None:
      bind = ""
    else:
      bind = str(self.bind_ip)
    try:
      s.bind( (bind, self.bind_port) )
    except Exception:
      if bind == "": bind = "<Any>"
      self.log.exception("Error while binding to %s:%s", bind, 53)
      return

    s.setblocking(False)

    self.thread = t = threading.Thread(target=self._server_thread)
    t.daemon = True
    t.start()

  @staticmethod
  def is_valid_name (n):
    if re.match('^[a-zA-Z0-9-.]+$', n): return True
    return False

  def _fixname (self, n):
    if isinstance(n, bytes):
      n = n.decode("ascii")
    if '.' not in n:
      if self.default_suffix:
        n = n + "." + self.default_suffix.lstrip(".")
    if not self.is_valid_name(n): return None
    return n.lower()

  def del_record (self, name, qtype=None):
    name = self._fixname(name)
    if name not in self.db: return False
    if qtype is None:
      self.db.pop(name)
      return True
    if isinstance(qtype, str):
      qtype = qtype.upper()
      # There should be a good way to do this but currently isn't.
      t = [k for k,v in pkt.DNS.rrtype_to_str.items() if v == qtype]
      if not t: return False
      qtype = t[0]

    for i,r in enumerate(self.db[name]):
      if r.type == qtype:
        del self.db[name][i]
        return True

    return False

  def add_record (self, name, v, ttl=None, https_alpn=None, qtype=None,
                  shuffle=None):
    name = self._fixname(name)
    if not name: return False
    if ttl is None: ttl = DNSRecord.DEFAULT_TTL
    if isinstance(v, list):
      pass
    else:
      if isinstance(v, list):
        v = ",".join(str(x) for x in v)
      else:
        v = str(v)
      if "," in v:
        v = v.split(',')
      else:
        v = [v]
      v = [x.replace('"', '').replace("'", '').strip() for x in v]
    try:
      if v[0].count(".") == 3:
        t = RR.A_TYPE
        v = [IPAddr(x) for x in v]
      elif ":" in v[0]:
        t = RR.AAAA_TYPE
        v = [IPAddr6(x) for x in v]
      else:
        raise RuntimeError(f"Bad record {name}={v}")
      r = DNSRecord(name, v, t if qtype is None else qtype, ttl)

      if https_alpn is not None:
        r.synthetic_https_alpn = https_alpn
      # Old method -- generate it and add it as normal.  We now generate it
      # on the fly if it's requested and we're configured to do so.
      #if https_alpn:
      #  # At present, this is how you make this type of record (ugly)...
      #  alpn = https_alpn
      #  if isinstance(alpn, str):
      #    alpn = alpn.encode("ascii")
      #  if isinstance(alpn, bytes):
      #    alpn = alpn.replace(b",", b" ").split()
      #  alpn = [x.encode() if isinstance(x,str) else x for x in alpn]
      #  alpn = [struct.pack("B", len(x)) + x for x in alpn]
      #  alpn = b''.join(alpn)
      #  parms = {}
      #  hv = [1,b'',parms]
      #  parms[DNS.SVCPK_ALPN] = alpn
      #  if False: # Address hints?
      #    if t == RR.A_TYPE:
      #      parms[DNS.SVCPK_IPV4HINT] = v[0].raw
      #    else: # AAAA
      #      parms[DNS.SVCPK_IPV6HINT] = v[0].raw
      #  hr = DNSRecord(name, [hv], RR.HTTPS_TYPE, ttl)
      #  self._set(name, hr)

    except Exception:
      if len(v) > 1: return False
      if not self.is_valid_name(v[0]): return False
      r = DNSRecord(name, v, RR.CNAME_TYPE if qtype is None else qtype, ttl)

    if shuffle is not None:
      r.shuffle = shuffle

    return self._set(name, r)

  def _do_request (self, sock, addr, data):
    req = DNS(raw=data)
    if req.qr: return
    if not req.questions: return
    r = DNS()
    r.qr = 1
    r.id = req.id
    #r.rd = req.rd
    #r.ra = True
    #r.aa = True

    anything = False

    for q in req.questions:
      if self._do_question(sock, addr, data, req, q, r) is not False:
        anything = True

    if anything:
      return r

  def _note_request (self, sock, addr, data,req, q):
    self.log.debug("< %s (from %s)", req, _fa(addr))

    if not self.history_length: return

    ts = time.time()
    a = _fa(addr)
    q = q.name
    done = False

    for i,(ots,oq,oa) in enumerate(reversed(self.history)):
      if (ts - ots) > 5: break
      if oq != q: continue
      if i > 8: break
      oa.add( a )
      done = True
      break

    if not done:
      self.history.append( (ts, q, {a}) )

    while len(self.history) > self.history_length:
      del self.history[0]

  def _do_question (self, sock, addr, data, req, q, res):
    qnl = q.name.lower().strip()
    if not qnl: # Empty query = automatic fail
      self.counter_ignore += 1
      return False
    if qnl in self.ignore:
      self.counter_ignore += 1
      return False
    # Definitely not the fastest algorithm we could use...
    for w in self.wild_ignore:
      if qnl.endswith(w):
        self.counter_ignore += 1
        return False
    if q.qclass != 1:
      # Only IN
      self.counter_badclass += 1
      return
    self._note_request(sock, addr, data, req, q)

    res.questions.append(q)

    rec = self._get(q.name, q.qtype)

    if not rec and q.qtype == RR.HTTPS_TYPE:
      # See about synthesizing an HTTPS record.
      # We currently only do this for A/AAAA records; it's possible
      # we should for CNAME too... what do browsers actually check?
      t = self._get(q.name, RR.A_TYPE)
      if not t: t = self._get(q.name, RR.AAAA_TYPE)
      if t:
        rec = t.make_https_record()

    if not rec and q.qtype != RR.CNAME_TYPE:
      rec = self._get(q.name, RR.CNAME_TYPE)

    if not rec:
      # Might want to send an NXDOMAIN, but we don't currently have SOA stuff
      # at all.  So just send back an empty reply; they'll probably get the
      # hint!
      self.log.info("No such domain: %s (from %s)",
                    q.name.decode("utf8", errors="ignore"), _fa(addr))
      self.counter_norecord += 1
    else:
      if not rec.values:
        self.counter_novalue += 1
      else:
        self.counter_okay += 1

      for value in rec.values:
        rr = RR(q.name, rec.type, 1, rec.ttl, 0, value)
        res.answers.append(rr)

    return rec

  def _send_response (self, sock, addr, data, r):
    self.log.info("> %s (to %s)", r, _fa(addr))
    sock.sendto(r.pack(), addr)

  def _respond (self, sock, addr, data):
    r = self._do_request(sock, addr, data)
    if r is not None:
      self._send_response(sock, addr, data, r)

  def _server_thread (self):
    s = self.sock
    self.log.info("Starting to serve DNS via UDP")
    while True:
      rr,_,_ = select([s],[],[], 5)
      if rr:
        data,addr = s.recvfrom(1500)
        core.call_later(self._respond, s, addr, data)


class DOHHandler (SplitRequestHandler):
  """
  Request handler for DNS-Over-HTTPS
  """
  ac_headers = False
  pox_cookieguard = False

  def do_GET (self):
    self._do_get_or_head()

  def do_HEAD (self):
    self._do_get_or_head(head_only=True)

  def do_POST (self):
    mime,params = cgi_parse_header(self.headers.get('content-type'))
    if mime != 'application/dns-message':
      self.send_error(400, "Expected DNS data")
      return

    try:
      l = int(self.headers.get("content-length", "0"))
    except Exception:
      l = 0
    if l <= 0:
      self.send_error(400, "Expected DNS data")
      return

    data = self.rfile.read(l)
    self._process(data)

  def _do_get_or_head (self, head_only=False):
    q = self.path.split("?dns=", 1)
    if len(q) != 2:
      self.send_error(404, "File not found")
      self.log_error("Malformed DoH GET URL")
      return
    q = q[1]
    data = base64.urlsafe_b64decode(q+"===") # Extra padding is ignored
    self._process(data, head_only=head_only)

  def _process (self, data, head_only=False):
    try:
      ip = self.headers.get("x-forwarded-for", self.client_address[0])
      ip = "".join(filter(lambda x: x in set("0123456789.:"), ip))
      addr = (ip,-1)
    except Exception:
      addr = ("Web", -1)

    res = core.DNSServer._do_request(None, addr, data)
    if res is None:
      # Hmm!
      self.log_error("%s", "No DNS response")
      r = b''
    else:
      core.DNSServer.log.info("> %s (to %s)", DNS(raw=res.pack()), _fa(addr))
      r = res.pack()

    self.send_response(200)
    self.send_header("Content-Type", "application/dns-message")
    self.send_header("Content-Length", str(len(r)))
    if res is not None and res.answers:
      ttl = min(x.ttl for x in res.answers)
      self.send_header("Access-Control-Allow-Max-Age", str(ttl))
      self.send_header("Access-Control-Allow-Origin", "*")
    self.end_headers()
    if not head_only:
      self.wfile.write(r)



@multi_instance
def add (**kw):
  """
  Adds A, AAAA, or CNAME records

  Use options like --example.com=127.0.0.1.  You can specify more than one.
  To specify multiple options for the same domain, separate them with commas
  like --example.com=::1,::2.

  You can also set options; these affect all records added with the same
  invocation of the "add" launcher.  To add records with different options,
  use a new instance of "add".

  Options like --HTTPS-ALPN=h3,h2 or whatever will cause added A/AAAA records
  to have synthesized HTTPS records.

  The --TTL=seconds option will set the TTL.

  Finally, You can pass --TYPE=type to override the record type.  This is
  most likely to be useful for setting --TYPE=NS.
  """
  alpn = None
  ttl = None
  qtype = None
  entries = {}
  for k,v in kw.items():
    k = k.replace("_", "-")
    v = str(v).replace("_", "-")
    if k == "HTTPS-ALPN":
      alpn = v
      continue
    if k == "TTL":
      ttl = int(v)
      continue
    if k == "TYPE":
      if (not v) or (v is True):
        t = None
      else:
        try:
          t = int(v)
        except Exception:
          t = getattr(RR, v.upper() + "_TYPE")
          if not isinstance(t, int): raise RuntimeError("Bad record type")
      qtype = t
      continue
    entries[k] = v

  for k,v in entries.items():
    if not core.DNSServer.add_record(k, v, https_alpn=alpn,
                                     ttl=ttl,qtype=qtype):
      log.warning(f"Could not add DNS record {k} = {v}")
  #log.debug(core.DNSServer.db)


@multi_instance
def ttl (ttl):
  DNSRecord.DEFAULT_TTL = int(ttl)


@multi_instance
def shuffle (disable=False):
  """
  Causes subsequent records to have multiple addresses shuffled
  """
  DNSRecord.shuffle = not disable


@multi_instance
def https_alpn (alpn=False):
  """
  Configures the default for synthetic HTTPS record ALPNs

  If specified with no argument, synthetic HTTPS records are turned off.
  Otherwise, it's an ALPN string, e.g., "h2,h3".
  """
  if alpn is True:
    raise RuntimeError("You must presently specify an actual value")
  DNSRecord.DEFAULT_ALPN = alpn


@multi_instance
def https_addr_hints (enable=False):
  """
  Configures the default for synthetic HTTPS record address hints

  If specified with no argument, synthetic HTTPS records will have address
  hints disabled.  Add --enable to turn them on.
  """
  DNSRecord.https_addr_hint = True if enable else False


def launch (protocols = "udp", local_ip = None, local_port = None,
            history = 0, default_suffix = None, ignore = None):
  """
  Start a DNS server

  --protocols=<protocols>  A comma-separated list of protocols or "all".  The
                           default is "udp".  See below.
  --local-ip=<IP>          IP address for serving DNS over UDP.
  --local-port=<port>      UDP port number for DNS over UDP
  --default-suffix=<name>  The default suffix for domain names.
  --history[=<size>]       Keep history of requests.
  --ignore=<hostnames>     Comma-separated list of names to ignore.  "." is a
                           special value which adds a default list.

  DNS can be served atop multiple other protocols, with "udp" being the
  most common.  DNS Over HTTPS ("doh") is also supported.  Other notable
  examples are TCP and TLS, but POX does not presently support these.
  """
  if ignore is True: ignore = "."
  elif not ignore: ignore = ""
  ignore = ignore.strip().lower().replace(","," ").split()

  if history is True: history = 10
  elif history: history = int(history)

  if protocols is True or protocols == "*": protocols = "all"
  protocols = protocols.lower().replace(","," ")
  protocols = {x.strip():True for x in protocols.split()}
  everything = protocols.pop("all", False)
  check = lambda x: protocols.pop(x, False) or everything

  udp = check("udp")
  doh = check("doh")
  if protocols:
    raise RuntimeError(f"Unknown protocol(s): {', '.join(protocols)}")

  local_port = int(local_port) if local_port else None

  core.registerNew(DNSServer, bind_ip=local_ip, default_suffix=default_suffix,
                   udp=udp, doh=doh, bind_port=local_port, history=history,
                   ignore=ignore)

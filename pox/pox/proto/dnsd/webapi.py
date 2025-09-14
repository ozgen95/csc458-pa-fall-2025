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
Implements a DNS update web API compatible with other dynamic DNS
services.

NOTE: You should probably turn on https and HTTP authentication!
      See samples/create_web_pki.sh for a script that helps set up
      https.  See samples/basic_tls_web.cfg for a basic configuration
      (which uses the stuff the script creates).  See the
      web.authentication component for more on setting up
      authentication (short version: you can make the curl example
      below work with web.authentication:basic --user=pass).

A request done with curl would look something like this:
  curl "http://user:pass@localhost:8000/nic/update?\
        hostname=test.somedns.com&myip=11.22.33.44"

The API is basically a baseline version of the API that's used by many
existing dynamic DNS providers and common dynamic DNS tools.  See:
  https://www.noip.com/integrate/request
  https://help.dyn.com/remote-access-api/

Two tools which seem to work just fine are ddclient and inadyn.
For ddclient, you want the "dyndns2" protocol, which is the default.
The only slightly unusual thing you need to do for ddclient is to
set the "server" option in the config file to point at POX (and
possibly add the -ssl command line option).  For inadyn, you'll
have to use a custom configuration.  There's a section in its README
called "Custom DDNS Providers", and it has an example which
"emulates dyndns.org".  If you just modify the "server" to point at
your POX, and tweak the "ddns-path" to not hardcode the "dyndns.org"
suffix, this works fine.

Note that many existing update tools do not handle redirections, so
POX CookieGuard does not work.  You can set --no-cookieguard for
this module, which disables it for just the DNS web API.  If you
use the POX web server for other things, however, this means the
DNS database may be vulnerable to spoofed entries via CSRF.

The API also supports a couple of extensions to the usual API:
  ttl - lets users specify the desired TTL for the entry
  alpn - lets users specify an ALPN for synthetic HTTPS records
         (the meaning is the same as in the DNSd web UI)

These extensions may need to be enabled when launching the API
component (with, e.g., --allow-alpn).  See the launcher doc.
"""

from pox.core import core
from pox.web.webcore import InternalContentHandler
from urllib.parse import parse_qsl
from pox.lib.addresses import IPAddr, IPAddr6

log = core.getLogger()


class DNSWebAPIHandler (InternalContentHandler):
  args_content_lookup = False

  dns_allow_alpn = False
  dns_default_alpn = None
  dns_allow_ttl = False
  dns_default_ttl = None

  dns_min_ttl = 0

  @property
  def _dns (self):
    r = self.args.get("dns_component")
    if r: return r
    return core.DNSServer

  def GETANY (self, _):
    p = self.path
    if not self.path.startswith("/update?"):
      self.send_error(404)
      return
    p = p.split("?", 1)[1]
    qs = dict(parse_qsl(p))

    hn = qs.get("hostname")
    ip = qs.get("myip", None)
    ip6 = qs.get("myip6", None)

    alpn = self.dns_default_alpn
    t = qs.get("alpn", None)
    if self.dns_allow_alpn and t is not None: alpn = t

    ttl = self.dns_default_ttl
    t = qs.get("ttl", None)
    if self.dns_allow_ttl and t is not None: ttl = t
    try:
      if ttl is not None:
        ttl = int(ttl)
        if ttl < self.dns_min_ttl: ttl = dns_min_ttl
    except Exception:
      log.error(f"Bad TTL processing hostname {hn}")
      return ("text/plain", "dnserror") # Random error

    # "ip" will definitely get set to either "myip" or "myip6" or the client
    # IP address.  If "myip" *and* "myip6" are set, then ip6 is also set.
    if (not ip) and (not ip6):
      ip = self.headers.get("x-forwarded-for", self.client_address[0])
      ip = "".join(filter(lambda x: x in set("0123456789.:"), ip))
    if (not ip) and ip6:
      ip = ip6
      ip6 = None

    if ip6:
      # Do a bonus IPv6 update, which won't influence the output at all
      # (it will work or it won't; life is mysterious).
      self._update(hn, ip6, alpn=alpn, ttl=ttl)

    return self._update(hn, ip, alpn=alpn, ttl=ttl)

    # Some of the errors:
    #  badauth
    #  notgqdn
    #  numhost
    #  nohost
    #  abuse
    #  badagent
    #  dnserror
    # Who knows we if we use them right, but if you
    # get one, something has definitely gone wrong.

  def _update (self, hn, ip, alpn, ttl):
    if not hn: return ("text/plain", "nohost")

    try:
      ip = IPAddr(ip)
    except Exception:
      try:
        ip = IPAddr6(ip)
      except Exception:
        log.warn("Bad IP address: %s", ip)
        return ("text/plain", "dnserr")

    hn = hn.split(",")

    try:
      for h in hn:
        self._dns.add_record(h, ip, ttl=ttl, https_alpn=alpn)
    except Exception:
      log.exception("While adding %s -> %s", h, ip)
      return ("text/plain", "dnserr")

    return ("text/plain", "good " + str(ip))


def launch (no_cookieguard=False, allow_ttl=False, allow_alpn=False,
            default_ttl=None, default_alpn=None, minimum_ttl=0):
  """
  Launch the web API

  allow_ttl:    Allow web API to set TTL of new entries
  allow_alpn:   Allow web API to enable synthetic HTTPS records by setting
                the desired ALPN (see ALPN docs elsewhere in POX's dnsd)
  default_ttl:  Set a default TTL different than the DNS server's default
  default_alpn: Set a default ALPN for all added records
  minimum_ttl:  Set a minimum value for user-specified TTL
  """
  class Handler (DNSWebAPIHandler):
    pass

  if no_cookieguard:
    Handler.pox_cookieguard = False

  Handler.dns_allow_ttl = allow_ttl
  Handler.dns_allow_alpn = allow_alpn
  Handler.dns_default_ttl = default_ttl
  Handler.dns_default_alpn = default_alpn
  Handler.dns_min_ttl = minimum_ttl

  def config ():
    core.WebServer.set_handler("/nic/", Handler,
                               args = dict(_dns=core.DNSServer))

  core.call_when_ready(config, ["WebServer", "DNSServer"])

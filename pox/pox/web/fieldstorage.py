# Copyright 2024 Sharon Kang
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

import email
from email import policy
from email.message import EmailMessage
from io import BytesIO


def parse_header (headers):
  msg = EmailMessage()
  msg['content-type'] = headers
  return msg.get_content_type(), msg['Content-Type'].params


class FieldStorage (dict):
  """
  Substitute class for cgi.FieldStorage.
  """
  def __init__ (self, fp=None, headers=None, environ=None):
    super().__init__()
    if fp is not None:
      self.parser(headers, fp)

  def parser (self, headers, rfile):
    content_length = int(headers.get('content-length', 0) or 0)
    content_header = headers.get('content-type')

    # Create a BytesFeedParser object for EmailMessage instance
    # (applicable only for versions above 3.6)
    p = email.parser.BytesFeedParser(policy=policy.default)
    p.feed(
      (f'content-type: {content_header}\n')
      .encode('utf-8', errors='surrogateescape')
    )

    chunk_length = 2048 * 16
    while (content_length > chunk_length):
      chunk = rfile.read(chunk_length)
      content_length -= len(chunk)
      p.feed(chunk)
    p.feed(rfile.read(content_length))
    # Always call close() to retrieve the root message object
    m = p.close()

    if m.is_multipart():
      for part in m.walk():
        if not part.is_multipart():
          f = FieldStorage()
          # The official document says `get_param()` and `get_payload()` are
          # legacy methods. However, all value retrieval functions within the
          # source code are utilizing these methods.
          f["name"] = part.get_param('name', header='content-disposition')
          f["filename"] = part.get_filename(None)
          f['mime'] = part.get_content_type()
          # if decode is True and part is not multipart (False)
          # get_payload() returns _payload decoded (bytes)
          f["value"] = part.get_payload(decode=True)
          self[f["name"]] = f

  @property
  def value (self):
    return self["value"]

  @property
  def file (self):
    return BytesIO(self.value)

  @property
  def name (self):
    return self["name"]

  @name.setter
  def name (self, value):
    self["name"] = value

  @property
  def filename (self):
    return self["filename"]

  @filename.setter
  def filename (self, value):
    self["filename"] = value

  @property
  def mime (self):
    return self["mime"]

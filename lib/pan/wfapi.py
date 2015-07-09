#
# Copyright (c) 2013-2015 Kevin Steves <kevin.steves@pobox.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

"""Interface to the WildFire  API

The pan.wfapi module implements the PanWFapi class.  It provides an
interface to the WildFire API on Palo Alto Networks' WildFire Cloud.
"""

# XXX Using the requests module which uses urllib3 and has support
# for multipart form-data would make this much simpler/cleaner (main
# issue is support for Python 2.x and 3.x in one source).  However I
# decided to not require non-default modules.  That decision may need
# to be revisited as some parts of this are not clean.

from __future__ import print_function
import sys
import re
import os
from tempfile import NamedTemporaryFile
from io import BytesIO
import email.utils
import logging
try:
    # 3.2
    from urllib.request import Request, urlopen, \
        build_opener, install_opener, HTTPErrorProcessor
    from urllib.request import HTTPSHandler, OpenerDirector
    from urllib.error import URLError
    from urllib.parse import urlencode
    from http.client import responses
    _legacy_urllib = False
except ImportError:
    # 2.7
    from urllib2 import Request, urlopen, URLError, \
        build_opener, install_opener, HTTPErrorProcessor
    from urllib import urlencode
    from httplib import responses
    _legacy_urllib = True

import xml.etree.ElementTree as etree
from . import __version__, DEBUG1, DEBUG2, DEBUG3
import pan.rc

import socket
try:
    import ssl
except ImportError:
    raise ValueError('SSL support not available')

try:
    ssl.SSLContext(ssl.PROTOCOL_SSLv23)
except AttributeError:
    _have_sslcontext = False
else:
    _have_sslcontext = True

_cloud_server = 'wildfire.paloaltonetworks.com'
_encoding = 'utf-8'
_rfc2231_encode = False
_wildfire_responses = {
    418: 'Unsupported File Type',
}

BENIGN = 0
MALWARE = 1
GRAYWARE = 2
PENDING = -100
ERROR = -101
UNKNOWN = -102
INVALID = -103

VERDICTS = {
    BENIGN: ('benign', None),
    MALWARE: ('malware', None),
    GRAYWARE: ('grayware', None),
    PENDING: ('pending', 'sample exists and verdict not known'),
    ERROR: ('error', 'sample is in error state'),
    UNKNOWN: ('unknown', 'sample does not exist'),
    INVALID: ('invalid', 'hash is invalid'),
}


def _isunicode(s):
    try:
        if isinstance(s, unicode):
            return True
        return False
    except NameError:
        if isinstance(s, str):
            return True
        return False


def _isbytes(s):
    try:
        if isinstance(s, basestring) and isinstance(s, bytes):
            return True
        return False
    except NameError:
        if isinstance(s, bytes):
            return True
        return False


class PanWFapiError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg


class PanWFapi:
    def __init__(self,
                 tag=None,
                 hostname=None,
                 api_key=None,
                 timeout=None,
                 http=False,
                 cacloud=True,
                 cafile=None,
                 capath=None):
        self._log = logging.getLogger(__name__).log
        self.tag = tag
        self.hostname = hostname
        self.api_key = None
        self.timeout = timeout
        self.cafile = cafile
        self.capath = capath

        self._log(DEBUG3, 'Python version: %s', sys.version)
        self._log(DEBUG3, 'xml.etree.ElementTree version: %s', etree.VERSION)
        self._log(DEBUG3, 'pan-python version: %s', __version__)

        if ((cacloud and sys.hexversion >= 0x03020000) and
                (self.cafile is None and self.capath is None)):
            tempfile = self.__cacloud()
            if tempfile is None:
                raise PanWFapiError(self._msg)
            self.cacloud_tempfile = tempfile
            self.cafile = self.cacloud_tempfile.name

        if self.timeout is not None:
            try:
                self.timeout = int(self.timeout)
                if not self.timeout > 0:
                    raise ValueError
            except ValueError:
                raise PanWFapiError('Invalid timeout: %s' % self.timeout)

        init_panrc = {}  # .panrc args from constructor
        if hostname is not None:
            init_panrc['hostname'] = hostname
        if api_key is not None:
            init_panrc['api_key'] = api_key

        try:
            panrc = pan.rc.PanRc(tag=self.tag,
                                 init_panrc=init_panrc)
        except pan.rc.PanRcError as msg:
            raise PanWFapiError(str(msg))

        if 'api_key' in panrc.panrc:
            self.api_key = panrc.panrc['api_key']
        if 'hostname' in panrc.panrc:
            self.hostname = panrc.panrc['hostname']
        else:
            self.hostname = _cloud_server

        if self.api_key is None:
            raise PanWFapiError('api_key required')

        if http:
            self.uri = 'http://%s' % self.hostname
        else:
            self.uri = 'https://%s' % self.hostname

        if _legacy_urllib:
            self._log(DEBUG2, 'using legacy urllib')

    def __str__(self):
        return '\n'.join((': '.join((k, str(self.__dict__[k]))))
                         for k in sorted(self.__dict__))

    def __clear_response(self):
        # XXX naming
        self._msg = None
        self.http_code = None
        self.http_reason = None
        self.response_body = None
        self.response_type = None
        self.xml_element_root = None
        self.attachment = None

    def __get_header(self, response, name):
        """use getheader() method depending or urllib in use"""

        s = None
        body = set()

        if hasattr(response, 'getheader'):
            # 3.2, http.client.HTTPResponse
            s = response.getheader(name)
        elif hasattr(response.info(), 'getheader'):
            # 2.7, httplib.HTTPResponse
            s = response.info().getheader(name)
        else:
            raise PanWFapiError('no getheader() method found in ' +
                                'urllib response')

        if s is not None:
            body = [x.lower() for x in s.split(';')]
            body = [x.lstrip() for x in body]
            body = [x.rstrip() for x in body]
            body = set(body)

        self._log(DEBUG3, '__get_header(%s): %s', name, s)
        self._log(DEBUG3, '__get_header: %s', body)

        return body

    def __set_response(self, response):
        message_body = response.read()

        content_type = self.__get_header(response, 'content-type')
        if not content_type:
            if self._msg is None:
                self._msg = 'no content-type response header'
            return False

        if 'application/octet-stream' in content_type:
            return self.__set_stream_response(response, message_body)

        # XXX text/xml RFC 3023
        elif ('application/xml' in content_type or
              'text/xml' in content_type):
            return self.__set_xml_response(message_body)

        elif 'text/html' in content_type:
            return self.__set_html_response(message_body)

        else:
            msg = 'no handler for content-type: %s' % content_type
            self._msg = msg
            return False

    def __set_stream_response(self, response, message_body):
        content_disposition = self.__get_header(response,
                                                'content-disposition')
        if not content_disposition:
            self._msg = 'no content-disposition response header'
            return False

        if 'attachment' not in content_disposition:
            msg = 'no handler for content-disposition: %s' % \
                content_disposition
            self._msg = msg
            return False

        filename = None
        for type in content_disposition:
            result = re.search(r'^filename=([-\w\.]+)$', type)
            if result:
                filename = result.group(1)
                break

        attachment = {}
        attachment['filename'] = filename
        attachment['content'] = message_body
        self.attachment = attachment
        return True

    def __set_xml_response(self, message_body):
        self._log(DEBUG2, '__set_xml_response: %s', repr(message_body))
        self.response_type = 'xml'

        _message_body = message_body.decode(_encoding)
        if len(_message_body) == 0:
            return True

        self.response_body = _message_body

        # ParseError: "XML or text declaration not at start of entity"
        # fix: remove leading blank lines if exist
        _message_body = message_body
        while (_message_body[0:1] == b'\r' or
               _message_body[0:1] == b'\n'):
            _message_body = _message_body[1:]

        if len(_message_body) == 0:
            return True

        try:
            element = etree.fromstring(_message_body)
        except etree.ParseError as msg:
            self._msg = 'ElementTree.fromstring ParseError: %s' % msg
            return False

        self.xml_element_root = element

        return True

    def __set_html_response(self, message_body):
        self._log(DEBUG2, '__set_html_response: %s', repr(message_body))
        self.response_type = 'html'

        _message_body = message_body.decode()
        if len(_message_body) == 0:
            return True

        self.response_body = _message_body

        return True

    # XXX store tostring() results?
    # XXX rework this
    def xml_root(self):
        if self.xml_element_root is None:
            return None

        s = etree.tostring(self.xml_element_root, encoding=_encoding)

        if not s:
            return None

        self._log(DEBUG3, 'xml_root: %s', type(s))
        self._log(DEBUG3, 'xml_root.decode(): %s', type(s.decode(_encoding)))
        return s.decode(_encoding)

    # see http://bugs.python.org/issue18543
    # this is a modified urllib.request.urlopen()
    @staticmethod
    def _urlopen(url, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 cafile=None, capath=None, cadefault=False):

        def http_response(request, response):
            return response

        http_error_processor = HTTPErrorProcessor()
        http_error_processor.https_response = http_response

        if _have_sslcontext and (cafile or capath or cadefault):
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_SSLv2
            context.verify_mode = ssl.CERT_REQUIRED
            if cafile or capath:
                context.load_verify_locations(cafile, capath)
            else:
                context.set_default_verify_paths()
            https_handler = HTTPSHandler(context=context, check_hostname=True)
            opener = build_opener(https_handler, http_error_processor)
        else:
            opener = build_opener(http_error_processor)
        return opener.open(url, data, timeout)

# XXX Unicode notes
# 2.7
# decode() str (bytes) -> unicode
# encode() unicode -> str (bytes)
# encode() of str will call decode()
# 3.x
# decode() bytes -> str (unicode)
# encode() str (unicode) -> bytes
# cannot encode() bytes
# cannot decode() str

    def __api_request(self, request_uri, body, headers={}):
        url = self.uri
        url += request_uri

        self._log(DEBUG1, 'URL: %s', url)
        self._log(DEBUG1, 'headers: %s', headers)

        # body must by type 'bytes' for 3.x
        if _isunicode(body):
            body = body.encode()

        self._log(DEBUG3, 'body: %s', repr(body))

        request = Request(url, body, headers)

        self._log(DEBUG1, 'method: %s', request.get_method())
        self._log(DEBUG1, 'headers: %s', request.header_items())

        kwargs = {
            'url': request,
            }
        # Changed in version 3.2: cafile and capath were added.
        if sys.hexversion >= 0x03020000:
            kwargs['cafile'] = self.cafile
            kwargs['capath'] = self.capath
        # Changed in version 3.3: cadefault added
        if sys.hexversion >= 0x03030000:
            pass
#            kwargs['cadefault'] = True

        if self.timeout is not None:
            kwargs['timeout'] = self.timeout

        try:

            response = PanWFapi._urlopen(**kwargs)

        # invalid cafile, capath
        except (URLError, IOError) as e:
            self._log(DEBUG2, 'urlopen() exception: %s', sys.exc_info())
            self._msg = str(e)
            return False

        self.http_code = response.getcode()
        if hasattr(response, 'reason'):
            # 3.2
            self.http_reason = response.reason
        elif hasattr(response, 'msg'):
            # 2.7
            self.http_reason = response.msg

        if self.http_reason == '':
            if self.http_code in _wildfire_responses:
                self.http_reason = _wildfire_responses[self.http_code]
            elif self.http_code in responses:
                self.http_reason = responses[self.http_code]

        self._log(DEBUG2, 'HTTP response code: %s', self.http_code)
        self._log(DEBUG2, 'HTTP response reason: %s', self.http_reason)
        self._log(DEBUG2, 'HTTP response headers:')
        self._log(DEBUG2, '%s', response.info())

        if not (200 <= self.http_code < 300):
            self._msg = 'HTTP Error %s: %s' % (self.http_code,
                                               self.http_reason)
            self.__set_response(response)
            return False

        return response

    def _read_file(self, path):
        try:
            f = open(path, 'rb')
        except IOError as e:
            msg = 'open: %s: %s' % (path, e)
            self._msg = msg
            return None

        buf = f.read()
        f.close()

        self._log(DEBUG2, 'path: %s %d', type(path), len(path))
        self._log(DEBUG2, 'path: %s size: %d', path, len(buf))
        if logging.getLogger(__name__).getEffectiveLevel() == DEBUG3:
            import hashlib
            md5 = hashlib.md5()
            md5.update(buf)
            sha256 = hashlib.sha256()
            sha256.update(buf)
            self._log(DEBUG3, 'MD5: %s', md5.hexdigest())
            self._log(DEBUG3, 'SHA256: %s', sha256.hexdigest())

        return buf

    def report(self,
               hash=None,
               format=None):
        self.__clear_response()

        request_uri = '/publicapi/get/report'

        query = {}
        query['apikey'] = self.api_key
        if hash is not None:
            query['hash'] = hash
        if format is not None:
            query['format'] = format

        response = self.__api_request(request_uri=request_uri,
                                      body=urlencode(query))
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def verdict(self,
                hash=None):
        self.__clear_response()

        request_uri = '/publicapi/get/verdict'

        query = {}
        query['apikey'] = self.api_key
        if hash is not None:
            query['hash'] = hash

        response = self.__api_request(request_uri=request_uri,
                                      body=urlencode(query))
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def verdicts(self,
                 hashes=None):
        self.__clear_response()

        request_uri = '/publicapi/get/verdicts'

        form = _MultiPartFormData()
        form.add_field('apikey', self.api_key)
        if hashes is not None:
            form.add_field('file', '\n'.join(hashes))

        headers = form.http_headers()
        body = form.http_body()

        response = self.__api_request(request_uri=request_uri,
                                      body=body, headers=headers)
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def verdicts_changed(self,
                         date=None):
        self.__clear_response()

        request_uri = '/publicapi/get/verdicts/changed'

        query = {}
        query['apikey'] = self.api_key
        if date is not None:
            query['date'] = date

        response = self.__api_request(request_uri=request_uri,
                                      body=urlencode(query))
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def sample(self,
               hash=None):
        self.__clear_response()

        request_uri = '/publicapi/get/sample'

        query = {}
        query['apikey'] = self.api_key
        if hash is not None:
            query['hash'] = hash

        response = self.__api_request(request_uri=request_uri,
                                      body=urlencode(query))
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def pcap(self,
             hash=None,
             platform=None):
        self.__clear_response()

        request_uri = '/publicapi/get/pcap'

        query = {}
        query['apikey'] = self.api_key
        if hash is not None:
            query['hash'] = hash
        if platform is not None:
            query['platform'] = platform

        response = self.__api_request(request_uri=request_uri,
                                      body=urlencode(query))
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def testfile(self):
        self.__clear_response()

        request_uri = '/publicapi/test/pe'

        query = {}

        response = self.__api_request(request_uri=request_uri,
                                      body=urlencode(query))
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def submit(self,
               file=None,
               url=None,
               links=None):
        self.__clear_response()

        if (sum(bool(x) for x in [file, url, links]) != 1):
            raise PanWFapiError('must submit one of file, url or links')

        if file is not None:
            request_uri = '/publicapi/submit/file'
        elif url is not None:
            request_uri = '/publicapi/submit/url'
        elif len(links) < 2:
            request_uri = '/publicapi/submit/link'
        elif len(links) > 1:
            request_uri = '/publicapi/submit/links'

        form = _MultiPartFormData()
        form.add_field('apikey', self.api_key)

        if file is not None:
            buf = self._read_file(file)
            if buf is None:
                raise PanWFapiError(self._msg)
            filename = os.path.basename(file)
            form.add_file(filename, buf)

        if url is not None:
            form.add_field('url', url)

        if links is not None:
            magic = 'panlnk\r\n'  # XXX remove in future
            if len(links) == 1:
                form.add_field('link', links[0])
            elif len(links) > 1:
                # XXX requires filename in Content-Disposition header
                form.add_file(filename='pan', body=magic + '\n'.join(links))

        headers = form.http_headers()
        body = form.http_body()

        response = self.__api_request(request_uri=request_uri,
                                      body=body, headers=headers)
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def change_request(self,
                       hash=None,
                       verdict=None,
                       email=None,
                       comment=None):
        self.__clear_response()

        request_uri = '/publicapi/submit/change-request'

        form = _MultiPartFormData()
        form.add_field('apikey', self.api_key)
        if hash is not None:
            form.add_field('hash', hash)
        if verdict is not None:
            form.add_field('verdict', verdict)
        if email is not None:
            form.add_field('email', email)
        if comment is not None:
            form.add_field('comment', comment)

        headers = form.http_headers()
        body = form.http_body()

        response = self.__api_request(request_uri=request_uri,
                                      body=body, headers=headers)
        if not response:
            raise PanWFapiError(self._msg)

        if not self.__set_response(response):
            raise PanWFapiError(self._msg)

    def __cacloud(self):
        # WildFire cloud cafile:
        #   https://certs.godaddy.com/anonymous/repository.pki
        #   Go Daddy Class 2 Certification Authority Root Certificate
        # use:
        #   $ openssl x509 -in wfapi.py -text
        # to view text form.

        gd_class2_root_crt = b'''
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh
MB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE
YWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3
MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo
ZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg
MiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN
ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA
PVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w
wdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi
EqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY
avx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+
YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE
sNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h
/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5
IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
ggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy
OO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P
TMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ
HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER
dEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf
ReYNnyicsbkqWletNw+vHX/bvZ8=
-----END CERTIFICATE-----
'''

        try:
            tf = NamedTemporaryFile(suffix='.crt')
            tf.write(gd_class2_root_crt)
            tf.flush()
        except (OSError, IOError) as e:
            self._msg = "Can't create cloud cafile: %s" % e
            return None

        self._log(DEBUG2, '__cacloud: %s', tf.name)

        return tf


# Minimal RFC 2388 implementation

# Content-Type: multipart/form-data; boundary=___XXX
#
# Content-Disposition: form-data; name="apikey"
#
# XXXkey
# --___XXX
# Content-Disposition: form-data; name="file"; filename="XXXname"
# Content-Type: application/octet-stream
#
# XXXfilecontents
# --___XXX--

class _MultiPartFormData:
    def __init__(self):
        self._log = logging.getLogger(__name__).log
        self.parts = []
        self.boundary = self._boundary()

    def add_field(self, name, value):
        part = _FormDataPart(name=name,
                             body=value)
        self.parts.append(part)

    def add_file(self, filename=None, body=None):
        part = _FormDataPart(name='file')
        if filename is not None:
            part.append_header('filename', filename)
        if body is not None:
            part.add_header(b'Content-Type: application/octet-stream')
            part.add_body(body)
        self.parts.append(part)

    def _boundary(self):
        rand_bytes = 48
        prefix_char = b'_'
        prefix_len = 16

        import base64
        try:
            import os
            seq = os.urandom(rand_bytes)
            self._log(DEBUG1, '_MultiPartFormData._boundary: %s',
                      'using os.urandom')
        except NotImplementedError:
            import random
            self._log(DEBUG1, '_MultiPartFormData._boundary: %s',
                      'using random')
            seq = bytearray()
            [seq.append(random.randrange(256)) for i in range(rand_bytes)]

        prefix = prefix_char * prefix_len
        boundary = prefix + base64.b64encode(seq)

        return boundary

    def http_headers(self):
        # headers cannot be bytes
        boundary = self.boundary.decode('ascii')
        headers = {
            'Content-Type':
                'multipart/form-data; boundary=' + boundary,
            }

        return headers

    def http_body(self):
        bio = BytesIO()

        boundary = b'--' + self.boundary
        for part in self.parts:
            bio.write(boundary)
            bio.write(b'\r\n')
            bio.write(part.serialize())
            bio.write(b'\r\n')
        bio.write(boundary)
        bio.write(b'--')

        return bio.getvalue()


class _FormDataPart:
    def __init__(self, name=None, body=None):
        self._log = logging.getLogger(__name__).log
        self.headers = []
        self.add_header(b'Content-Disposition: form-data')
        self.append_header('name', name)
        self.body = None
        if body is not None:
            self.add_body(body)

    def add_header(self, header):
        self.headers.append(header)
        self._log(DEBUG1, '_FormDataPart.add_header: %s', self.headers[-1])

    def append_header(self, name, value):
        self.headers[-1] += b'; ' + self._encode_field(name, value)
        self._log(DEBUG1, '_FormDataPart.append_header: %s', self.headers[-1])

    def _encode_field(self, name, value):
        self._log(DEBUG1, '_FormDataPart._encode_field: %s %s',
                  type(name), type(value))
        if not _rfc2231_encode:
            s = '%s="%s"' % (name, value)
            self._log(DEBUG1, '_FormDataPart._encode_field: %s %s',
                      type(s), s)
            if _isunicode(s):
                s = s.encode('utf-8')
                self._log(DEBUG1, '_FormDataPart._encode_field: %s %s',
                          type(s), s)
            return s

        if not [ch for ch in '\r\n\\' if ch in value]:
            try:
                return ('%s="%s"' % (name, value)).encode('ascii')
            except UnicodeEncodeError:
                self._log(DEBUG1, 'UnicodeEncodeError 3.x')
            except UnicodeDecodeError:  # 2.x
                self._log(DEBUG1, 'UnicodeDecodeError 2.x')
        # RFC 2231
        value = email.utils.encode_rfc2231(value, 'utf-8')
        return ('%s*=%s' % (name, value)).encode('ascii')

    def add_body(self, body):
        if _isunicode(body):
            body = body.encode('latin-1')
        self.body = body
        self._log(DEBUG1, '_FormDataPart.add_body: %s %d',
                  type(self.body), len(self.body))

    def serialize(self):
        bio = BytesIO()
        bio.write(b'\r\n'.join(self.headers))
        bio.write(b'\r\n\r\n')
        if self.body is not None:
            bio.write(self.body)

        return bio.getvalue()

if __name__ == '__main__':
    # python -m pan.wfapi [tag] [sha256]
    import pan.wfapi

    tag = None
    sha256 = '5f31d8658a41aa138ada548b7fb2fc758219d40b557aaeab80681d314f739f92'

    if len(sys.argv) > 1 and sys.argv[1]:
        tag = sys.argv[1]
    if len(sys.argv) > 2:
        hash = sys.argv[2]

    try:
        wfapi = pan.wfapi.PanWFapi(tag=tag)
    except pan.wfapi.PanWFapiError as msg:
        print('pan.wfapi.PanWFapi:', msg, file=sys.stderr)
        sys.exit(1)

    try:
        wfapi.report(hash=sha256)

    except pan.wfapi.PanWFapiError as msg:
        print('report: %s' % msg, file=sys.stderr)
        sys.exit(1)

    if (wfapi.response_body is not None):
        print(wfapi.response_body)

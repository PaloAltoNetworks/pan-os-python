#
# Copyright (c) 2017 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
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

import inspect
import json
import logging
import ssl
import sys
import time

from .. import __version__, DEBUG1, DEBUG2, DEBUG3
import pan.rc
import pan.http
from pan.licapi import PanLicapiError

_cloud_server = 'api.paloaltonetworks.com'


def _wall_time(x):
    from functools import wraps
    from timeit import default_timer

    @wraps(x)
    def wrapper(self, *args, **kwargs):
        start = default_timer()
        r = x(self, *args, **kwargs)
        end = default_timer()

        secs = end-start
        r.wall_time = secs

        time_str = 'wall time %.2f seconds' % secs
        if logging.getLogger(__name__).getEffectiveLevel() == DEBUG1:
            self._log(DEBUG1, '%s() %s' %
                      (x.__name__, time_str))
        elif (logging.getLogger(__name__).getEffectiveLevel() in
              [DEBUG2, DEBUG3]):
            self._log(DEBUG2, '%s(%s, %s) %s' %
                      (x.__name__, args, kwargs, time_str))
        return r

    return wrapper


class PanLicapiRequest:
    def __init__(self, name=None):
        self.name = name
        self.http_code = None
        self.http_reason = None
        self.http_headers = None
        self.http_encoding = None
        self.http_content_type = None
        self.http_content = None
        self.http_text = None
        self.json = None

    def raise_for_status(self):
        if self.http_code is None:
            return None

        if not (200 <= self.http_code < 300):
            e = 'HTTP Error %s' % self.http_code
            if self.http_reason is not None:
                e += ': %s' % self.http_reason
            if self.json is not None and 'Message' in self.json:
                e += ' ' + self.json['Message']
            raise PanLicapiError(e)

        return None


class PanLicapi:
    def __init__(self,
                 api_version=None,
                 panrc_tag=None,
                 hostname=None,
                 api_key=None,
                 timeout=None,
                 verify_cert=True):
        self._log = logging.getLogger(__name__).log
        self.api_version = api_version
        self.panrc_tag = panrc_tag
        self.hostname = hostname
        self.api_key = api_key
        self.timeout = timeout
        self.verify_cert = verify_cert

        self._log(DEBUG3, 'Python version: %s', sys.version)
        self._log(DEBUG3, 'ssl: %s', ssl.OPENSSL_VERSION)
        self._log(DEBUG3, 'pan-python version: %s', __version__)

        init_panrc = {}  # .panrc args from constructor
        if hostname is not None:
            init_panrc['hostname'] = hostname
        if api_key is not None:
            init_panrc['api_key'] = api_key

        try:
            panrc = pan.rc.PanRc(tag=self.panrc_tag,
                                 init_panrc=init_panrc)
        except pan.rc.PanRcError as e:
            raise PanLicapiError(e)

        if 'api_key' in panrc.panrc:
            self.api_key = panrc.panrc['api_key']
        if 'hostname' in panrc.panrc:
            self.hostname = panrc.panrc['hostname']
        else:
            self.hostname = _cloud_server

        if self.api_key is None:
            raise PanLicapiError('api_key required')

        self.uri = 'https://' + self.hostname
        self.base_uri = self.uri + '/api/license'
        self.headers = {
            'apikey': self.api_key,
            # requests header value must be str:
            #   https://github.com/kennethreitz/requests/issues/3477
            'version': str(int(api_version)),
        }

        try:
            self.http = pan.http.PanHttp(timeout=self.timeout,
                                         verify_cert=self.verify_cert)
        except pan.http.PanHttpError as e:
            raise PanLicapiError(e)

        if self.http.using_requests:
            s = 'using requests %s' % self.http.requests_version
        else:
            s = 'using urllib'
        self._log(DEBUG2, s)

    def _set_attributes(self, r):
        r.http_code = self.http.code
        r.http_reason = self.http.reason
        r.http_headers = self.http.headers
        r.http_encoding = self.http.encoding
        if r.http_encoding is None:
            r.http_encoding = 'utf8'
        r.http_content_type = self.http.content_type
        self._log(DEBUG2, r.http_encoding)
        self._log(DEBUG2, r.http_headers)
        r.http_content = self.http.content
        r.http_text = self.http.text

        if r.http_content_type == 'application/json':
            try:
                r.json = json.loads(r.http_text)
            except ValueError as e:
                self._log(DEBUG1, 'json.loads: ', e)
        self._log(DEBUG3, r.http_text)

    def _api_request(self, url, headers, data=None, params=None):
        self._log(DEBUG1, url)
        if params is not None:
            self._log(DEBUG1, params)
        self._log(DEBUG1, data)

        try:
            self.http.http_request(url=url,
                                   headers=self.headers,
                                   data=data,
                                   params=params)
        except pan.http.PanHttpError as e:
            raise PanLicapiError(str(e))

        r = PanLicapiRequest(inspect.stack()[1][3])
        self._set_attributes(r)
        return r

    @_wall_time
    def activate(self,
                 authcode=None,
                 uuid=None,
                 cpuid=None,
                 serialnumber=None):
        endpoint = '/activate'
        url = self.base_uri + endpoint
        data = {}
        if authcode is not None:
            data['authcode'] = authcode
        if uuid is not None:
            data['uuid'] = uuid
        if cpuid is not None:
            data['cpuid'] = cpuid
        if serialnumber is not None:
            data['serialnumber'] = serialnumber

        r = self._api_request(url, self.headers, data)
        return r

    @_wall_time
    def deactivate(self, encryptedtoken=None):
        endpoint = '/deactivate'
        url = self.base_uri + endpoint
        data = {}
        if encryptedtoken is not None:
            data['encryptedtoken'] = encryptedtoken

        r = self._api_request(url, self.headers, data)
        return r

    @_wall_time
    def get(self, authcode=None):
        endpoint = '/get'
        url = self.base_uri + endpoint
        data = {}
        if authcode is not None:
            data['authcode'] = authcode

        r = self._api_request(url, self.headers, data)
        return r

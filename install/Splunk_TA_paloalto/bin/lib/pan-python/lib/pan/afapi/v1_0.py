#
# Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
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
import sys
import time

from .. import __version__, DEBUG1, DEBUG2, DEBUG3
import pan.rc
import pan.http
from pan.afapi import PanAFapiError

_cloud_server = 'autofocus.paloaltonetworks.com'


class PanAFapiRequest:
    def __init__(self, name=None):
        self.name = name
        self.http_code = None
        self.http_reason = None
        self.http_headers = None
        self.http_encoding = None
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
            if self.json is not None and 'message' in self.json:
                e += ' ' + self.json['message']
            raise PanAFapiError(e)

        return None


class PanAFapi:
    def __init__(self,
                 api_version=None,
                 panrc_tag=None,
                 hostname=None,
                 api_key=None,
                 timeout=None,
                 verify_cert=True,
                 sleeper=None):
        self._log = logging.getLogger(__name__).log
        self.api_version = api_version
        self.panrc_tag = panrc_tag
        self.hostname = hostname
        self.api_key = api_key
        self.timeout = timeout
        self.verify_cert = verify_cert
        self.sleeper = _Sleeper if sleeper is None else sleeper

        self._log(DEBUG3, 'Python version: %s', sys.version)
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
            raise PanAFapiError(e)

        if 'api_key' in panrc.panrc:
            self.api_key = panrc.panrc['api_key']
        if 'hostname' in panrc.panrc:
            self.hostname = panrc.panrc['hostname']
        else:
            self.hostname = _cloud_server

        if self.api_key is None:
            raise PanAFapiError('api_key required')

        self.uri = 'https://' + self.hostname
        self.base_uri = self.uri + '/api/' + str(api_version)
        self.headers = {'content-type': 'application/json'}

        try:
            self.http = pan.http.PanHttp(timeout=self.timeout,
                                         verify_cert=self.verify_cert)
        except pan.http.PanHttpError as e:
            raise PanAFapiError(e)

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
        self._log(DEBUG2, r.http_encoding)
        self._log(DEBUG2, r.http_headers)
        r.http_content = self.http.content
        r.http_text = self.http.text
        if r.http_headers is not None:
            x = r.http_headers.get('content-type')
            if x is not None and x.startswith('application/json'):
                try:
                    r.json = json.loads(r.http_text)
                except ValueError as e:
                    self._log(DEBUG1, 'json.loads: ', e)
        self._log(DEBUG3, r.http_text)

    def _set_apikey(self, data):
        try:
            obj = json.loads(data)
            obj['apiKey'] = self.api_key
            return json.dumps(obj)
        except ValueError as e:
            raise PanAFapiError(str(e))

    def _api_request(self, url, headers, data=None, params=None):
        self._log(DEBUG1, url)
        if params is not None:
            self._log(DEBUG1, params)
        self._log(DEBUG1, data)

        data = '{}' if data is None else data
        data = self._set_apikey(data)

        try:
            self.http.http_request(url=url,
                                   headers=self.headers,
                                   data=data,
                                   params=params)
        except pan.http.PanHttpError as e:
            raise PanAFapiError(str(e))

        r = PanAFapiRequest(inspect.stack()[1][3])
        self._set_attributes(r)
        return r

    def samples_search(self, data=None):
        endpoint = '/samples/search/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r

    def samples_results(self, af_cookie=None):
        endpoint = '/samples/results/'
        url = self.base_uri + endpoint
        if af_cookie is not None:
            url += af_cookie
        r = self._api_request(url, self.headers, '{}')
        return r

    def samples_search_results(self, data=None, terminal=True):
        return self._search_results(data,
                                    self.samples_search,
                                    self.samples_results,
                                    terminal)

    def _search_results(self, data, search, results, terminal):
        r = search(data=data)
        r.raise_for_status()

        if not terminal:
            yield r

        obj = r.json
        if obj is None:
            raise PanAFapiError('Response not JSON')

        af_cookie = obj.get('af_cookie')
        if af_cookie is None:
            raise PanAFapiError('No af_cookie in response')

        sleeper = self.sleeper(obj)

        while True:
            r = results(af_cookie=af_cookie)
            r.raise_for_status()

            if not terminal:
                yield r

            obj = r.json
            if obj is None:
                raise PanAFapiError('Response not JSON')

            msg = obj.get('af_message')
            if msg is not None and msg == 'complete':
                if terminal:
                    yield r
                try:
                    self._log(DEBUG1, 'ZZZ total %.2f', float(sleeper))
                except AttributeError:
                    pass
                break

            x = sleeper.sleep(obj)
            self._log(DEBUG1, 'ZZZ %.2f', x)

    def sessions_search(self, data=None):
        endpoint = '/sessions/search/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r

    def sessions_results(self, af_cookie=None):
        endpoint = '/sessions/results/'
        url = self.base_uri + endpoint
        if af_cookie is not None:
            url += af_cookie
        r = self._api_request(url, self.headers)
        return r

    def sessions_search_results(self, data=None, terminal=True):
        return self._search_results(data,
                                    self.sessions_search,
                                    self.sessions_results,
                                    terminal)

    def sessions_histogram_search(self, data=None):
        endpoint = '/sessions/histogram/search/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r

    def sessions_histogram_results(self, af_cookie=None):
        endpoint = '/sessions/histogram/results/'
        url = self.base_uri + endpoint
        if af_cookie is not None:
            url += af_cookie
        r = self._api_request(url, self.headers)
        return r

    def sessions_histogram_search_results(self, data=None, terminal=True):
        return self._search_results(data,
                                    self.sessions_histogram_search,
                                    self.sessions_histogram_results,
                                    terminal)

    def sessions_aggregate_search(self, data=None):
        endpoint = '/sessions/aggregate/search/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r

    def sessions_aggregate_results(self, af_cookie=None):
        endpoint = '/sessions/aggregate/results/'
        url = self.base_uri + endpoint
        if af_cookie is not None:
            url += af_cookie
        r = self._api_request(url, self.headers)
        return r

    def sessions_aggregate_search_results(self, data=None, terminal=True):
        return self._search_results(data,
                                    self.sessions_aggregate_search,
                                    self.sessions_aggregate_results,
                                    terminal)

    def session(self, sessionid=None):
        endpoint = '/session/'
        url = self.base_uri + endpoint
        if sessionid is not None:
            url += sessionid
        r = self._api_request(url, self.headers)
        return r

    def top_tags_search(self, data=None):
        endpoint = '/top-tags/search/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r

    def top_tags_results(self, af_cookie=None):
        endpoint = '/top-tags/results/'
        url = self.base_uri + endpoint
        if af_cookie is not None:
            url += af_cookie
        r = self._api_request(url, self.headers)
        return r

    def top_tags_search_results(self, data=None, terminal=True):
        return self._search_results(data,
                                    self.top_tags_search,
                                    self.top_tags_results,
                                    terminal)

    def tags(self, data=None):
        endpoint = '/tags/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r

    def tag(self, tagname=None):
        endpoint = '/tag/'
        url = self.base_uri + endpoint
        if tagname is not None:
            url += tagname
        r = self._api_request(url, self.headers)
        return r

    def sample_analysis(self, data=None, sampleid=None):
        endpoint = '/sample/'
        url = self.base_uri + endpoint
        if sampleid is not None:
            url += sampleid + '/'
        url += 'analysis'
        r = self._api_request(url, self.headers, data)
        return r

    def export(self, data=None):
        endpoint = '/export/'
        url = self.base_uri + endpoint
        r = self._api_request(url, self.headers, data)
        return r


class _Sleeper:
    START = 0.5
    STEP = 2
    MAX = 10
    INCREASE = 10  # percent

    def __init__(self, obj):
        self._percent = obj.get('af_complete_percentage', 0)
        self._sleep = _Sleeper.START
        self._total = 0
        time.sleep(self._sleep)
        self._total += self._sleep

    def sleep(self, obj):
        percent = obj.get('af_complete_percentage', 0)
        if percent - self._percent < _Sleeper.INCREASE:
            self._sleep += _Sleeper.STEP
            if self._sleep > _Sleeper.MAX:
                self._sleep = _Sleeper.MAX
        else:
            self._sleep = _Sleeper.START

        self._percent = percent
        time.sleep(self._sleep)
        self._total += self._sleep
        return self._sleep

    def __float__(self):
        return self._total

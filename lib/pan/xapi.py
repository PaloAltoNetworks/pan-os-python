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

"""Interface to the PAN-OS XML API

The pan.xapi module implements the PanXapi class.  It provides an
interface to the XML API on Palo Alto Networks' Next-Generation
Firewalls.
"""

from __future__ import print_function
import sys
import re
import time
import logging
try:
    import ssl
except ImportError:
    raise ValueError('SSL support not available')

try:
    # 3.2
    from urllib.request import Request, urlopen, \
        build_opener, install_opener, HTTPSHandler
    from urllib.error import URLError
    from urllib.parse import urlencode
    _legacy_urllib = False
except ImportError:
    # 2.7
    from urllib2 import Request, urlopen, URLError, \
        build_opener, install_opener
    try:
        from urllib2 import HTTPSHandler
    except:
        pass
    from urllib import urlencode
    _legacy_urllib = True

import xml.etree.ElementTree as etree

from . import __version__, DEBUG1, DEBUG2, DEBUG3
import pan.rc

_encoding = 'utf-8'
_job_query_interval = 0.5


class PanXapiError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg


class PanXapi:
    def __init__(self,
                 tag=None,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 hostname=None,
                 port=None,
                 serial=None,
                 use_http=False,
                 use_get=False,
                 timeout=None,
                 ssl_context=None):
        self._log = logging.getLogger(__name__).log
        self.tag = tag
        self.api_username = None
        self.api_password = None
        self.api_key = None
        self.hostname = None
        self.port = port
        self.serial = serial
        self.use_get = use_get
        self.timeout = timeout
        self.ssl_context = ssl_context

        self._log(DEBUG3, 'Python version: %s', sys.version)
        self._log(DEBUG3, 'xml.etree.ElementTree version: %s', etree.VERSION)
        self._log(DEBUG3, 'pan-python version: %s', __version__)

        if self.port is not None:
            try:
                self.port = int(self.port)
                if self.port < 1 or self.port > 65535:
                    raise ValueError
            except ValueError:
                raise PanXapiError('Invalid port: %s' % self.port)

        if self.timeout is not None:
            try:
                self.timeout = int(self.timeout)
                if not self.timeout > 0:
                    raise ValueError
            except ValueError:
                raise PanXapiError('Invalid timeout: %s' % self.timeout)

        if self.ssl_context is not None:
            try:
                ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            except AttributeError:
                raise PanXapiError('SSL module has no SSLContext()')

        init_panrc = {}  # .panrc args from constructor
        if api_username is not None:
            init_panrc['api_username'] = api_username
        if api_password is not None:
            init_panrc['api_password'] = api_password
        if api_key is not None:
            init_panrc['api_key'] = api_key
        if hostname is not None:
            init_panrc['hostname'] = hostname
        if port is not None:
            init_panrc['port'] = port
        if serial is not None:
            init_panrc['serial'] = serial

        try:
            panrc = pan.rc.PanRc(tag=self.tag,
                                 init_panrc=init_panrc)
        except pan.rc.PanRcError as msg:
            raise PanXapiError(str(msg))

        # If we get a api_username and api_password in the constructor
        # and no api_key, delete api_key inherited from .panrc if any.
        # Prevent confusion when you specify a api_username and
        # api_password but they are not used due to existence of
        # api_key in .panrc.
        if ('api_key' in panrc.panrc and
                api_username is not None and
                api_password is not None and
                api_key is None):
            del panrc.panrc['api_key']
            self._log(DEBUG1, 'ignoring .panrc inherited api_key')

        if 'api_username' in panrc.panrc:
            self.api_username = panrc.panrc['api_username']
        if 'api_password' in panrc.panrc:
            self.api_password = panrc.panrc['api_password']
        if 'api_key' in panrc.panrc:
            self.api_key = panrc.panrc['api_key']
        if 'hostname' in panrc.panrc:
            self.hostname = panrc.panrc['hostname']
        if 'port' in panrc.panrc:
            self.port = panrc.panrc['port']
            try:
                self.port = int(self.port)
                if self.port < 1 or self.port > 65535:
                    raise ValueError
            except ValueError:
                raise PanXapiError('Invalid port from .panrc: %s' % self.port)
        if 'serial' in panrc.panrc:
            self.serial = panrc.panrc['serial']

        if self.hostname is None:
            raise PanXapiError('hostname argument required')
        if self.api_key is None and (self.api_username is None or
                                     self.api_password is None):
            raise PanXapiError('api_key or api_username and ' +
                               'api_password arguments required')

        if use_http:
            scheme = 'http'
        else:
            scheme = 'https'

        self.uri = '%s://%s' % (scheme, self.hostname)
        if self.port is not None:
            self.uri += ':%s' % self.port
        self.uri += '/api/'

        if _legacy_urllib:
            self._log(DEBUG2, 'using legacy urllib')

    def __str__(self):
        return '\n'.join((': '.join((k, str(self.__dict__[k]))))
                         for k in sorted(self.__dict__))

    def __clear_response(self):
        # XXX naming
        self.status = None
        self.status_code = None
        self.status_detail = None
        self.xml_document = None
        self.text_document = None
        self.element_root = None
        self.element_result = None
        self.export_result = None

    def __get_header(self, response, name):
        """use getheader() method depending or urllib in use"""

        s = None
        types = set()

        if hasattr(response, 'getheader'):
            # 3.2, http.client.HTTPResponse
            s = response.getheader(name)
        elif hasattr(response.info(), 'getheader'):
            # 2.7, httplib.HTTPResponse
            s = response.info().getheader(name)
        else:
            raise PanXapiError('no getheader() method found in ' +
                               'urllib response')

        if s is not None:
            types = [type.lower() for type in s.split(';')]
            types = [type.lstrip() for type in types]
            types = [type.rstrip() for type in types]
            types = set(types)

        self._log(DEBUG3, '__get_header(%s): %s', name, s)
        self._log(DEBUG3, '__get_header: %s', types)

        return types

    def __set_response(self, response):
        message_body = response.read()

        content_type = self.__get_header(response, 'content-type')
        if not content_type:
            self.status_detail = 'no content-type response header'
            return False

        if 'application/octet-stream' in content_type:
            return self.__set_stream_response(response, message_body)

        elif ('application/xml' in content_type and
              'charset=utf-8' in content_type):
            return self.__set_xml_response(message_body)

        # XXX no charset
        elif ('application/xml' in content_type):
            return self.__set_xml_response(message_body)

        # XXX bug in 5.0 and 6.0: content-type text/plain for export pcap
        elif ('text/plain' in content_type and
              self.__get_header(response, 'content-disposition')):
            return self.__set_stream_response(response, message_body)

        elif ('text/plain' in content_type and
              'charset=utf-8' in content_type):
            return self.__set_text_response(message_body)

        else:
            msg = 'no handler for content-type: %s' % content_type
            self.status_detail = msg
            return False

    def __set_stream_response(self, response, message_body):
        content_disposition = self.__get_header(response,
                                                'content-disposition')
        if not content_disposition:
            self.status_detail = 'no content-disposition response header'
            return False

        if 'attachment' not in content_disposition:
            msg = 'no handler for content-disposition: %s' % \
                content_disposition
            self.status_detail = msg
            return False

        filename = None
        for type in content_disposition:
            result = re.search(r'^filename=([-\w\d\.]+)$', type)
            if result:
                filename = result.group(1)
                break

        export_result = {}
        export_result['file'] = filename
        export_result['content'] = message_body
        self.export_result = export_result
        self.status = 'success'
        return True

    def __set_xml_response(self, message_body):
        self.xml_document = message_body.decode(_encoding)

        try:
            element = etree.fromstring(message_body)
        except etree.ParseError as msg:
            self.status_detail = 'ElementTree.fromstring ParseError: %s' % msg
            return False
        # we probably won't see MemoryError when it happens but try to catch
        except MemoryError as msg:
            self.status_detail = 'ElementTree.fromstring MemoryError: %s' % msg
            return False
        except Exception as msg:
            self.status_detail = '%s: %s' % (sys.exc_info()[0].__name__, msg)
            return False

        self.element_root = element
        self.element_result = self.element_root.find('result')  # can be None
        if self.element_result is None:
            # type=report
            self.element_result = self.element_root.find('report/result')

        self._log(DEBUG3, 'xml_document: %s', self.xml_document)
        self._log(DEBUG3, 'message_body: %s', type(message_body))
        self._log(DEBUG3, 'message_body.decode(): %s', type(self.xml_document))

        response_attrib = self.element_root.attrib
        if not response_attrib:
            # XXX error?
            self.status_detail = 'no response element status attribute'
            return False

        self._log(DEBUG2, 'response_attrib: %s', response_attrib)

        if 'status' in response_attrib:
            self.status = response_attrib['status']
        else:
            self.status = 'success'
        if 'code' in response_attrib:
            self.status_code = response_attrib['code']

        self.status_detail = self.__get_response_msg()

        if self.status == 'success':
            return True
        else:
            return False

    def __set_text_response(self, message_body):
        self.text_document = message_body.decode(_encoding)

        self._log(DEBUG3, 'text_document: %s', self.text_document)
        self._log(DEBUG3, 'message_body: %s', type(message_body))
        self._log(DEBUG3, 'message_body.decode(): %s',
                  type(self.text_document))

        self.status = 'success'
        return True

    def __get_response_msg(self):
        lines = []

        # XML API response message formats are not documented

        # type=user-id register and unregister
        path = './msg/line/uid-response/payload/*/entry'
        elem = self.element_root.findall(path)
        if len(elem) > 0:
            self._log(DEBUG2, 'path: %s %s', path, elem)
            for line in elem:
                msg = ''
                for key in line.keys():
                    msg += '%s: %s ' % (key, line.get(key))
                if msg:
                    lines.append(msg.rstrip())
            return '\n'.join(lines) if lines else None

        path = './msg/line'
        elem = self.element_root.findall(path)
        if len(elem) > 0:
            self._log(DEBUG2, 'path: %s %s', path, elem)
            for line in elem:
                if line.text is not None:
                    lines.append(line.text)
                else:
                    # <line><line>xxx</line></line>...
                    elem = line.find('line')
                    if elem is not None and elem.text is not None:
                        lines.append(elem.text)
            return '\n'.join(lines) if lines else None

        path = './result/msg/line'
        elem = self.element_root.findall(path)
        if len(elem) > 0:
            self._log(DEBUG2, 'path: %s %s', path, elem)
            for line in elem:
                if line.text is not None:
                    lines.append(line.text)
            return '\n'.join(lines) if lines else None

        path = './result/msg'
        elem = self.element_root.find(path)
        if elem is not None:
            self._log(DEBUG2, 'path: %s %s', path, elem)
            if elem.text is not None:
                lines.append(elem.text)
            return lines[0] if lines else None

        path = './msg'
        elem = self.element_root.find(path)
        if elem is not None:
            self._log(DEBUG2, 'path: %s %s', path, elem)
            if elem.text is not None:
                lines.append(elem.text)
            return lines[0] if lines else None

        # 'show jobs id nn' and 'show jobs all' responses
        path = './result/job/details/line'
        elem = self.element_root.findall(path)
        if len(elem) > 0:
            self._log(DEBUG2, 'path: %s %s', path, elem)
            for line in elem:
                if line.text is not None:
                    lines.append(line.text)
                else:
                    path = './newjob/newmsg'
                    elem2 = line.find(path)
                    if elem2 is not None and elem2.text is not None:
                        lines.append(elem2.text)
            return '\n'.join(lines) if lines else None

        return None

    # XXX store tostring() results?
    # XXX rework this
    def xml_root(self):
        if self.element_root is None:
            # May not be set due to ParseError, so return response
            return self.xml_document

        s = etree.tostring(self.element_root, encoding=_encoding)

        if not s:
            return None

        self._log(DEBUG3, 'xml_root: %s', type(s))
        self._log(DEBUG3, 'xml_root.decode(): %s', type(s.decode(_encoding)))

        return s.decode(_encoding)

    def xml_result(self):
        if self.element_result is None:
            return None

        s = ''.encode()

        if self.element_result.text:
            s += self.element_result.text.encode(_encoding)

        for elem in self.element_result:
            s += etree.tostring(elem, encoding=_encoding)

        if not s:
            return None

        self._log(DEBUG3, 'xml_result: %s', type(s))
        self._log(DEBUG3, 'xml_result.decode(): %s', type(s.decode(_encoding)))

        return s.decode(_encoding)

    def __api_request(self, query):
        # type=keygen request will urlencode key if needed so don't
        # double encode
        if 'key' in query:
            query2 = query.copy()
            key = query2['key']
            del query2['key']
            data = urlencode(query2)
            data += '&' + 'key=' + key
        else:
            data = urlencode(query)

        self._log(DEBUG3, 'query: %s', query)
        self._log(DEBUG3, 'data: %s', type(data))
        self._log(DEBUG3, 'data.encode(): %s', type(data.encode()))

        url = self.uri
        if self.use_get:
            url += '?' + data
            request = Request(url)
        else:
            # data must by type 'bytes' for 3.x
            request = Request(url, data.encode())

        self._log(DEBUG1, 'URL: %s', url)
        self._log(DEBUG1, 'method: %s', request.get_method())
        self._log(DEBUG1, 'data: %s', data)

        kwargs = {
            'url': request,
            }

        if (sys.version_info.major == 2 and sys.hexversion >= 0x02070900 or
                sys.version_info.major == 3 and sys.hexversion >= 0x03040300):
            # see PEP 476; urlopen() has context
            if self.ssl_context is None:
                # don't perform certificate verification
                kwargs['context'] = ssl._create_unverified_context()
            else:
                kwargs['context'] = self.ssl_context
        elif self.ssl_context is not None:
            https_handler = HTTPSHandler(context=self.ssl_context)
            opener = build_opener(https_handler)
            install_opener(opener)

        if self.timeout is not None:
            kwargs['timeout'] = self.timeout

        try:
            response = urlopen(**kwargs)

        # XXX handle httplib.BadStatusLine when http to port 443
        except URLError as error:
            msg = 'URLError:'
            if hasattr(error, 'code'):
                msg += ' code: %s' % error.code
            if hasattr(error, 'reason'):
                msg += ' reason: %s' % error.reason
            if not (hasattr(error, 'code') or hasattr(error, 'reason')):
                msg += ' unknown error (Kevin heart Python)'
            self.status_detail = msg
            return False

        self._log(DEBUG2, 'HTTP response headers:')
        self._log(DEBUG2, '%s', response.info())

        return response

    def __set_api_key(self):
        if self.api_key is None:
            self.keygen()
            self._log(DEBUG1, 'autoset api_key: "%s"', self.api_key)

    def cmd_xml(self, cmd):
        def _cmd_xml(args, obj):
            if not args:
                return
            arg = args.pop(0)
            if args:
                result = re.search(r'^"(.*)"$', args[0])
                if result:
                    obj.append('<%s>' % arg)
                    obj.append(result.group(1))
                    obj.append('</%s>' % arg)
                    args.pop(0)
                    _cmd_xml(args, obj)
                else:
                    obj.append('<%s>' % arg)
                    _cmd_xml(args, obj)
                    obj.append('</%s>' % arg)
            else:
                obj.append('<%s>' % arg)
                _cmd_xml(args, obj)
                obj.append('</%s>' % arg)

        args = cmd.split()
        obj = []
        _cmd_xml(args, obj)
        xml = ''.join(obj)

        self._log(DEBUG2, 'cmd_xml: "%s"', xml)

        return xml

    def keygen(self, extra_qs=None):
        self.__clear_response()

        if (self.api_username is None or
                self.api_password is None):
            raise PanXapiError('api_username and api_password ' +
                               'arguments required')

        query = {
            'type': 'keygen',
            'user': self.api_username,
            'password': self.api_password,
            }
        if self.serial is not None:
            query['target'] = self.serial
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

        if self.element_result is None:
            raise PanXapiError('keygen(): result element not found')
        element = self.element_result.find('key')
        if element is None:
            raise PanXapiError('keygen(): key element not found')

        self.api_key = element.text

        return self.api_key

    @staticmethod
    def __qs_to_dict(qs):
        if isinstance(qs, dict):
            return qs

        d = {}
        try:
            pairs = qs.split('&')
            for pair in pairs:
                key, value = pair.split('=', 1)
                d[key] = value
        except ValueError:
            return None

        return d

    def __merge_extra_qs(self, query, qs):
        if qs is None:
            return query

        if isinstance(qs, str):
            d = self.__qs_to_dict(qs)
            if d is None:
                raise PanXapiError('Invalid extra_qs: %s:' % qs)
        elif not isinstance(qs, dict):
            raise PanXapiError('Invalid extra_qs: not dict or str')
        else:
            d = qs

        x = query.copy()
        x.update(d)

        return x

    def ad_hoc(self, qs=None, xpath=None, modify_qs=False):
        self.__set_api_key()
        self.__clear_response()

        query = {}
        if qs is not None:
            query = self.__qs_to_dict(qs)
            if query is False:
                raise PanXapiError('Invalid ad_hoc query: %s' % qs)

        if modify_qs:
            if xpath is not None:
                query['xpath'] = xpath
            if self.api_key is not None:
                query['key'] = self.api_key
            if self.api_username is not None:
                query['user'] = self.api_username
            if self.api_password is not None:
                query['password'] = self.api_password
            if self.serial is not None:
                query['target'] = self.serial

        self._log(DEBUG1, '%s', query)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

    def show(self, xpath=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        self.__type_config('show', query, extra_qs)

    def get(self, xpath=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        self.__type_config('get', query, extra_qs)

    def delete(self, xpath=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        self.__type_config('delete', query, extra_qs)

    def set(self, xpath=None, element=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        if element is not None:
            query['element'] = element
        self.__type_config('set', query, extra_qs)

    def edit(self, xpath=None, element=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        if element is not None:
            query['element'] = element
        self.__type_config('edit', query, extra_qs)

    def move(self, xpath=None, where=None, dst=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        if where is not None:
            query['where'] = where
        if dst is not None:
            query['dst'] = dst
        self.__type_config('move', query, extra_qs)

    def rename(self, xpath=None, newname=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        if newname is not None:
            query['newname'] = newname
        self.__type_config('rename', query, extra_qs)

    def clone(self, xpath=None, xpath_from=None, newname=None,
              extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        if xpath_from is not None:
            query['from'] = xpath_from
        if newname is not None:
            query['newname'] = newname
        self.__type_config('clone', query, extra_qs)

    def override(self, xpath=None, element=None, extra_qs=None):
        query = {}
        if xpath is not None:
            query['xpath'] = xpath
        if element is not None:
            query['element'] = element
        self.__type_config('override', query, extra_qs)

    def __type_config(self, action, query, extra_qs=None):
        self.__set_api_key()
        self.__clear_response()

        query['type'] = 'config'
        query['action'] = action
        query['key'] = self.api_key
        if self.serial is not None:
            query['target'] = self.serial
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

    def user_id(self, cmd=None, vsys=None, extra_qs=None):
        self.__set_api_key()
        self.__clear_response()

        query = {}
        query['type'] = 'user-id'
        query['key'] = self.api_key
        if cmd is not None:
            query['cmd'] = cmd
        if vsys is not None:
            query['vsys'] = vsys
        if self.serial is not None:
            query['target'] = self.serial
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

    def commit(self, cmd=None, action=None, sync=False,
               interval=None, timeout=None, extra_qs=None):
        self.__set_api_key()
        self.__clear_response()

        if interval is not None:
            try:
                interval = float(interval)
                if interval < 0:
                    raise ValueError
            except ValueError:
                raise PanXapiError('Invalid interval: %s' % interval)
        else:
            interval = _job_query_interval

        if timeout is not None:
            try:
                timeout = int(timeout)
                if timeout < 0:
                    raise ValueError
            except ValueError:
                raise PanXapiError('Invalid timeout: %s' % timeout)

        query = {}
        query['type'] = 'commit'
        query['key'] = self.api_key
        if self.serial is not None:
            query['target'] = self.serial
        if cmd is not None:
            query['cmd'] = cmd
        if action is not None:
            query['action'] = action
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

        if sync is not True:
            return

        job = self.element_root.find('./result/job')
        if job is None:
            return

        self._log(DEBUG2, 'commit job: %s', job.text)

        cmd = 'show jobs id "%s"' % job.text
        start_time = time.time()

        while True:
            try:
                self.op(cmd=cmd, cmd_xml=True)
            except PanXapiError as msg:
                raise PanXapiError('commit %s: %s' % (cmd, msg))

            path = './result/job/status'
            status = self.element_root.find(path)
            if status is None:
                raise PanXapiError('no status element in ' +
                                   "'%s' response" % cmd)
            if status.text == 'FIN':
                # XXX commit vs. commit-all job status
                return

            self._log(DEBUG2, 'job %s status %s', job.text, status.text)

            if (timeout is not None and timeout != 0 and
                    time.time() > start_time + timeout):
                raise PanXapiError('timeout waiting for ' +
                                   'job %s completion' % job.text)

            self._log(DEBUG2, 'sleep %.2f seconds', interval)
            time.sleep(interval)

    def op(self, cmd=None, vsys=None, cmd_xml=False, extra_qs=None):
        if cmd is not None and cmd_xml:
            cmd = self.cmd_xml(cmd)
        self.__type_op(cmd, vsys, extra_qs)

    def __type_op(self, cmd, vsys, extra_qs=None):
        self.__set_api_key()
        self.__clear_response()

        query = {}
        query['type'] = 'op'
        if cmd is not None:
            query['cmd'] = cmd
        if vsys is not None:
            query['vsys'] = vsys
        query['key'] = self.api_key
        if self.serial is not None:
            query['target'] = self.serial
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

    @staticmethod
    def pcapid_time(pcapid):
        # bit 25-56 is epoch time of threat
        mask = 0x01fffffffe000000
        pcapid &= mask
        pcapid >>= 25

        return pcapid

    @staticmethod
    def panos_time(seconds):
        format = '%Y/%m/%d %H:%M:%S'
        s = time.strftime(format, time.localtime(seconds))

        return s

    def export(self, category=None, from_name=None, to_name=None,
               pcapid=None, search_time=None, serialno=None,
               extra_qs=None):
        self.__set_api_key()
        self.__clear_response()

        query = {}
        query['type'] = 'export'
        query['key'] = self.api_key
        if category is not None:
            query['category'] = category
        if from_name is not None:
            query['from'] = from_name
        if to_name is not None:
            query['to'] = to_name
        if pcapid is not None:
            query['pcapid'] = pcapid
        if search_time is not None:
            query['search-time'] = search_time
        elif pcapid is not None:
            if isinstance(pcapid, str):
                try:
                    n = int(pcapid)
                except ValueError:
                    raise PanXapiError('Invalid pcapid: %s' % pcapid)
            pcap_time = self.pcapid_time(n)
            panos_time = self.panos_time(pcap_time)
            query['search-time'] = panos_time
            self._log(DEBUG1, 'pcapid time: %s %s', pcap_time,
                      panos_time)
        if serialno is not None:
            query['serialno'] = serialno
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

        if self.export_result:
            self.export_result['category'] = category

    def log(self, log_type=None, nlogs=None, skip=None, filter=None,
            interval=None, timeout=None, extra_qs=None):
        self.__set_api_key()
        self.__clear_response()

        if interval is None:
            interval = _job_query_interval

        try:
            interval = float(interval)
            if interval < 0:
                raise ValueError
        except ValueError:
            raise PanXapiError('Invalid interval: %s' % interval)

        if timeout is not None:
            try:
                timeout = int(timeout)
                if timeout < 0:
                    raise ValueError
            except ValueError:
                raise PanXapiError('Invalid timeout: %s' % timeout)

        query = {}
        query['type'] = 'log'
        query['key'] = self.api_key
        if log_type is not None:
            query['log-type'] = log_type
        if nlogs is not None:
            query['nlogs'] = nlogs
        if skip is not None:
            query['skip'] = skip
        if filter is not None:
            query['query'] = filter
        if extra_qs is not None:
            query = self.__merge_extra_qs(query, extra_qs)

        response = self.__api_request(query)
        if not response:
            raise PanXapiError(self.status_detail)

        if not self.__set_response(response):
            raise PanXapiError(self.status_detail)

        job = self.element_root.find('./result/job')
        if job is None:
            raise PanXapiError('no job element in type=log response')

        query = {}
        query['type'] = 'log'
        query['action'] = 'get'
        query['key'] = self.api_key
        query['job-id'] = job.text
        self._log(DEBUG2, 'log job: %s', job.text)

        start_time = time.time()

        while True:
            response = self.__api_request(query)
            if not response:
                raise PanXapiError(self.status_detail)

            if not self.__set_response(response):
                raise PanXapiError(self.status_detail)

            status = self.element_root.find('./result/job/status')
            if status is None:
                raise PanXapiError('no status element in ' +
                                   'type=log&action=get response')
            if status.text == 'FIN':
                return

            self._log(DEBUG2, 'job %s status %s', job.text, status.text)

            if (timeout is not None and timeout != 0 and
                    time.time() > start_time + timeout):
                raise PanXapiError('timeout waiting for ' +
                                   'job %s completion' % job.text)

            self._log(DEBUG2, 'sleep %.2f seconds', interval)
            time.sleep(interval)

if __name__ == '__main__':
    # python -m pan.xapi [tag] [xpath]
    import pan.xapi

    tag = None
    xpath = '/config/mgt-config'
    if len(sys.argv) > 1 and sys.argv[1]:
        tag = sys.argv[1]
    if len(sys.argv) > 2:
        xpath = sys.argv[2]

    try:
        xapi = pan.xapi.PanXapi(timeout=5,
                                tag=tag)
        xapi.show(xpath=xpath)
    except pan.xapi.PanXapiError as msg:
        print('pan.xapi.PanXapi:', msg, file=sys.stderr)
        sys.exit(1)
    print('show:', xapi.status, file=sys.stderr)
    print(xapi.xml_document)

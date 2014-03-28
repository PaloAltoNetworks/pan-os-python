#
# Copyright (c) 2012, 2013 Kevin Steves <kevin.steves@pobox.com>
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

from __future__ import print_function
import sys
import xml.etree.ElementTree as etree
#import lxml.etree as etree
from . import __version__

_encoding = 'utf-8'
_tags_forcelist = set(['entry', 'member'])


class PanConfigError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class PanConfig:
    def __init__(self,
                 debug=0,
                 config=None,
                 tags_forcelist=_tags_forcelist):
        self.debug = debug
        self.debug1, self.debug2, self.debug3 = False, False, False
        if self.debug > 0:
            self.debug1 = True
        if self.debug > 1:
            self.debug2 = True
        if self.debug > 2:
            self.debug3 = True
        self._config_version = 0  # 0 indicates not yet set
        self._config_panorama = None
        self._config_multi_vsys = None

        if self.debug > 3:
            raise PanConfigError('Maximum debug level is 3')

        if self.debug3:
            print('Python version:', sys.version, file=sys.stderr)
            print('xml.etree.ElementTree version:', etree.VERSION,
                  file=sys.stderr)
            print('pan-python version:', __version__, file=sys.stderr)

        if config is None:
            raise PanConfigError('no config')
        if self.debug2:
            print(type(config), file=sys.stderr)

        if hasattr(config, 'tag'):
            self.config_root = config
        else:
            try:
                self.config_root = etree.fromstring(config)
            except etree.ParseError as msg:
                raise PanConfigError('ElementTree.fromstring ParseError: %s'
                                     % msg)
        if self.debug1:
            print('config_root:', self.config_root, file=sys.stderr)

    def __find_xpath(self, xpath=None):
# Not a true Xpath
# http://docs.python.org/dev/library/xml.etree.elementtree.html#xpath-support
        if self.debug1:
            print('xpath:', xpath, file=sys.stderr)
        if xpath:
            try:
                nodes = self.config_root.findall(xpath)
            except SyntaxError as msg:
                raise PanConfigError('ElementTree.find SyntaxError: %s' % msg)
        else:
            nodes = [self.config_root]

        if self.debug1:
            print('xpath nodes:', nodes, file=sys.stderr)

        return nodes

    def config_version(self):
        if self._config_version != 0:
            return self._config_version

        self._config_version = None
        if self.config_root.tag == 'config':
            self._config_version = \
                self.config_root.get('version', default=None)

        return self._config_version

    def config_panorama(self):
        if self._config_panorama is not None:
            return self._config_panorama

        xpaths = [
            "./panorama",
            "./devices/entry[@name='localhost.localdomain']/device-group",
        ]
        if self.config_root.tag == 'config':
            for xpath in xpaths:
                elem = self.config_root.find(xpath)
                if elem is not None:
                    self._config_panorama = True
                    break
            else:
                self._config_panorama = False

        return self._config_panorama

    def config_multi_vsys(self):
        if self._config_multi_vsys is not None:
            return self._config_multi_vsys

        path = "./devices/entry[@name='localhost.localdomain']/vsys/entry"
        if self.config_root.tag == 'config':
            nodes = self.config_root.findall(path)
            if len(nodes) > 1:
                self._config_multi_vsys = True
            else:
                self._config_multi_vsys = False

        return self._config_multi_vsys

    def xml(self, xpath=None):
        nodes = self.__find_xpath(xpath)
        if not nodes:
            return None

        s = ''.encode()
        for elem in nodes:
            s += etree.tostring(elem, encoding=_encoding)

        if not s:
            return None

        if self.debug3:
            print('xml:', type(s), file=sys.stderr)
            print('xml.decode():', type(s.decode(_encoding)),
                  file=sys.stderr)
        return s.decode(_encoding)

    def python(self, xpath=None):
        nodes = self.__find_xpath(xpath)
        if not nodes:
            return None

        d = {}
        if len(nodes) > 1:
            for elem in nodes:
                d[elem.tag] = {}
                self.__serialize_py(elem, d[elem.tag])
        else:
            self.__serialize_py(nodes[0], d)

        return d

    def __serialize_py(self, elem, obj, forcelist=False):
        tag = elem.tag
        text = elem.text
        tail = elem.tail  # unused
        text_strip = None
        if text:
            text_strip = text.strip()
        attrs = elem.items()

        if self.debug3:
            print('TAG(forcelist=%s): "%s"' % (forcelist, tag),
                  file=sys.stderr)

        if forcelist:
            if tag not in obj:
                obj[tag] = []
            if not len(elem) and not text_strip and not attrs:
                obj[tag].append(None)
                return
            if not len(elem) and text_strip and not attrs:
                obj[tag].append(text)
                return

            obj[tag].append({})
            o = obj[tag][-1]

        else:
            if not len(elem) and not text_strip and not attrs:
                obj[tag] = None
                return
            if not len(elem) and text_strip and not attrs:
                if text_strip == 'yes':
                    obj[tag] = True
                elif text_strip == 'no':
                    obj[tag] = False
                else:
                    obj[tag] = text
                return

            obj[tag] = {}
            o = obj[tag]

        for k, v in attrs:
#            o['@' + k] = v
            o[k] = v

        if text_strip:
            o[tag] = text

        if len(elem):
            tags = {}
            for e in elem:
                if e.tag in tags:
                    tags[e.tag] += 1
                else:
                    tags[e.tag] = 1
            for e in elem:
                forcelist = False
                if e.tag in _tags_forcelist or tags[e.tag] > 1:
                    forcelist = True
                self.__serialize_py(e, o, forcelist)

    def flat(self, path, xpath=None):
        nodes = self.__find_xpath(xpath)
        if not nodes:
            return None

        obj = []
        for elem in nodes:
            self.__serialize_flat(elem, path + elem.tag, obj)

        return obj

    def __serialize_flat(self, elem, path, obj):
        tag = elem.tag
        text = elem.text
        tail = elem.tail  # unused
        text_strip = None
        if text:
            text_strip = text.strip()
        attrs = elem.items()

        if self.debug3:
            print('TAG(elem=%d): "%s"' % (len(elem), tag), file=sys.stderr)
            print('text_strip: "%s"' % text_strip, file=sys.stderr)
            print('attrs: %s' % attrs, file=sys.stderr)
            print('path: "%s"' % path, file=sys.stderr)
            print('obj: %s' % obj, file=sys.stderr)
            print(file=sys.stderr)

        if not text_strip:
            obj.append(path)
        elif text_strip:
            lines = text.splitlines()
            if len(lines) > 1:
                n = 1
                for line in lines:
                    s = path + '[%d]="%s"' % (n, line)
                    obj.append(s)
                    n += 1
            else:
                s = path + '="%s"' % text
                obj.append(s)

        for k, v in attrs:
            path += "[@%s='%s']" % (k, v)
            obj.append(path)

        for e in elem:
            self.__serialize_flat(e, path + '/' + e.tag, obj)

    def __quote_space(self, s):
        # XXX string with " etc.
        if ' ' in s:
            return '"%s"' % s
        return s

    def set_cli(self, path, xpath=None, member_list=False):
        nodes = self.__find_xpath(xpath)
        if not nodes:
            return None

        obj = []
        for elem in nodes:
            self.__serialize_set_cli(elem, path + elem.tag, obj,
                                     member_list)

        return obj

    def __serialize_set_cli(self, elem, path, obj, member_list=False):
        tag = elem.tag
        text = elem.text
        tail = elem.tail  # unused
        text_strip = None
        if text:
            text_strip = text.strip()
        attrs = elem.items()

        if self.debug3:
            print('TAG(elem=%d member_list=%s): "%s"' %
                  (len(elem), member_list, tag),
                  file=sys.stderr)
            print('text_strip: "%s"' % text_strip, file=sys.stderr)
            print('attrs: %s' % attrs, file=sys.stderr)
            print('path: "%s"' % path, file=sys.stderr)
            print('obj: %s' % obj, file=sys.stderr)
            print(file=sys.stderr)

        for k, v in attrs:
            if k == 'name':
                path += ' ' + self.__quote_space(v)

        if member_list:
            nodes = elem.findall('./member')
            if self.debug3:
                print('TAG(members=%d): "%s"' % (len(nodes), tag), file=sys.stderr)
            if len(nodes) > 1:
                members = []
                for e in nodes:
                    members.append(self.__quote_space(e.text))
                path += ' [ ' + ' '.join(members) + ' ]'
                obj.append(path)
                return

        if not len(elem):
            if text_strip:
                path += ' ' + self.__quote_space(text)
            obj.append(path)

        for e in elem:
            tpath = path
            if e.tag not in ['entry', 'member']:
                tpath += ' ' + e.tag
            self.__serialize_set_cli(e, tpath, obj, member_list)

    def config_xpaths(self):
        xpaths_panos_4_1 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/network
./shared
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-admin-override
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/captive-portal
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/group-mapping
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-agent
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ts-agent
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-content-types
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/region
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-filter
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/threats
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/schedule
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/email-scheduler
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/pdf-summary-report
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/report-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/reports
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profile-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/setting
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/display-name
./mgt-config
'''

        xpaths_panos_5_0 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/network
./shared
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/region
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-filter
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/threats
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/schedule
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/email-scheduler
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/pdf-summary-report
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/report-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/reports
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profile-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ocsp-responder
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-admin-override
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-collector
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/captive-portal
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/group-mapping
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-agent-sequence
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-agent
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ts-agent
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-content-types
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/setting
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/display-name
./mgt-config
'''

        # add: tag, vm-info-source, import
        xpaths_panos_6_0 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/network
./shared
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/region
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-filter
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/threats
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/schedule
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/email-scheduler
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/pdf-summary-report
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/report-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/reports
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profile-group
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ocsp-responder
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-admin-override
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-collector
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/captive-portal
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/group-mapping
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-agent-sequence
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/vm-info-source
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-agent
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ts-agent
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/url-content-types
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/import
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/setting
./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/display-name
./mgt-config
'''

        xpaths_panos_multi_vsys_4_1 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/network
./shared
./devices/entry[@name='localhost.localdomain']/vsys
./mgt-config
'''
        xpaths_panorama_4_1 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/device-group
./panorama
./shared
./mgt-config
'''

        xpaths_panorama_5_0 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/device-group
./devices/entry[@name='localhost.localdomain']/template
./devices/entry[@name='localhost.localdomain']/log-collector
./devices/entry[@name='localhost.localdomain']/log-collector-group
./panorama
./shared
./mgt-config
'''

        # add: vmware-service-manager, predefined
        xpaths_panorama_6_0 = '''
./devices/entry[@name='localhost.localdomain']/deviceconfig
./devices/entry[@name='localhost.localdomain']/device-group
./devices/entry[@name='localhost.localdomain']/template
./devices/entry[@name='localhost.localdomain']/log-collector
./devices/entry[@name='localhost.localdomain']/log-collector-group
./devices/entry[@name='localhost.localdomain']/vmware-service-manager
./predefined
./panorama
./shared
./mgt-config
'''

        xpaths_panos = xpaths_panos_4_1
        xpaths_panos_multi_vsys = xpaths_panos_multi_vsys_4_1
        xpaths_panorama = xpaths_panorama_4_1

        if self.config_version() is not None:
            if self.config_version() in ['5.0.0', '5.1.0']:
                xpaths_panos = xpaths_panos_5_0
                xpaths_panorama = xpaths_panorama_5_0
            elif self.config_version() in ['6.0.0']:
                xpaths_panos = xpaths_panos_6_0
                xpaths_panorama = xpaths_panorama_6_0

        if self.config_multi_vsys():
            xpaths = xpaths_panos_multi_vsys
        elif self.config_panorama():
            xpaths = xpaths_panorama
        else:
            xpaths = xpaths_panos
        xpaths = xpaths.split('\n')
        xpaths = [s for s in xpaths if s]

        return xpaths

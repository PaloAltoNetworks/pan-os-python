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

from collections import namedtuple
import logging
import re
import sys

from .. import __version__, DEBUG1, DEBUG2, DEBUG3

_default_api_version = (1, 0)
DEFAULT_API_VERSION = 'v%d.%d' % _default_api_version


class _ApiVersion(namedtuple('api_version',
                             ['major', 'minor'],
                             verbose=False)):
    def __str__(self):
        return 'v%d.%d' % (self.major, self.minor)

    def __int__(self):
        # reserve lower 8 bits for 'future' use
        return self.major << 16 | self.minor << 8


class PanAFapiError(Exception):
    pass


def PanAFapi(api_version=None, *args, **kwargs):
    _log = logging.getLogger(__name__).log

    if api_version is None:
        x = _default_api_version
    else:
        r = re.search(r'^v?(\d+)\.(\d+)$', api_version)
        if r is None:
            raise PanAFapiError('Invalid api_version: %s' % api_version)
        x = int(r.group(1)), int(r.group(2))
    _api_version = _ApiVersion(*x)
    _log(DEBUG1, 'api_version: %s, 0x%06x',
         _api_version, _api_version)

    _package = 'pan.afapi'
    _module = 'v%d_%d' % (_api_version.major, _api_version.minor)
    _class = 'PanAFapi'
    _module_name = _package + '.' + _module

    try:
        __import__(_module_name)
    except ImportError as e:
        raise PanAFapiError('Module import error: %s: %s' %
                            (_module_name, e))

    try:
        klass = getattr(sys.modules[_module_name], _class)
    except AttributeError:
        raise PanAFapiError('Class not found: %s' % _class)

    return klass(api_version=_api_version, *args, **kwargs)

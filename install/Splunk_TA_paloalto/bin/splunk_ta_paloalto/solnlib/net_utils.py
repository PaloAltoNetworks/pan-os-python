# Copyright 2016 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License'): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
Net utilities.
'''

import socket

from solnlib import ip_math

__all__ = ['resolve_hostname']


def resolve_hostname(addr):
    '''Try to resolve an IP to a host name and returns None
    on common failures.

    :param addr: IP address to resolve.
    :type addr: ``string``
    :returns: Host name if success else None.
    :rtype: ``string``

    :raises ValueError: If `addr` is not a valid address
    '''

    if ip_math.is_valid_ip(addr):
        try:
            name, _, _ = socket.gethostbyaddr(addr)
            return name
        except socket.gaierror:
            # [Errno 8] nodename nor servname provided, or not known
            pass
        except socket.herror:
            # [Errno 1] Unknown host
            pass
        except socket.timeout:
            # Timeout.
            pass

        return None
    else:
        raise ValueError('Invalid ip address.')

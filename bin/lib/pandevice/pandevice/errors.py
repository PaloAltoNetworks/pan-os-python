#!/usr/bin/env python

# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
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

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>

"""Exception classes used by pandevice package"""

from pan.xapi import PanXapiError


# Exceptions used by PanDevice Class
class PanDeviceError(PanXapiError):
    """Exception for errors in the PanDevice class

    The PanDevice class may raise errors when problems occur such as
    response parsing problems.  This exception class is raised on those
    errors. This class is not for errors connecting to the API, as
    pan.xapi.PanXapiError is responsible for those.

    Attributes:
        message: The error message for the exception
        pan_device: A reference to the PanDevice that generated the exception
    """
    def __init__(self, *args, **kwargs):
        self.pan_device = kwargs.pop('pan_device', None)
        super(PanDeviceError, self).__init__(*args, **kwargs)

class PanDeviceXapiError(PanDeviceError):
    """General error returned by an API call"""
    pass

class PanInvalidCredentials(PanDeviceXapiError):
    pass

class PanURLError(PanDeviceXapiError):
    pass

class PanConnectionTimeout(PanDeviceXapiError):
    pass

class PanJobTimeout(PanDeviceError):
    pass

class PanLockError(PanDeviceError):
    pass

class PanPendingChanges(PanDeviceError):
    pass

class PanCommitInProgress(PanDeviceXapiError):
    pass

class PanInstallInProgress(PanDeviceXapiError):
    pass

class PanCommitFailed(PanDeviceXapiError):
    def __init__(self, *args, **kwargs):
        self.result = kwargs.pop('result', None)
        super(PanCommitFailed, self).__init__("Commit failed", *args, **kwargs)

class PanCommitNotNeeded(PanDeviceXapiError):
    pass

class PanSessionTimedOut(PanDeviceXapiError):
    pass

class PanDeviceNotSet(PanDeviceError):
    pass

class PanNoSuchNode(PanDeviceXapiError):
    pass

class PanObjectMissing(PanDeviceXapiError):
    pass

class PanHAConfigSyncFailed(PanDeviceXapiError):
    pass

class PanHASyncInProgress(PanDeviceXapiError):
    pass

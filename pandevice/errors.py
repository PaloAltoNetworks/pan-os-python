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

# Exceptions used by PanDevice Class
class PanDeviceError(Exception):
    """Exception for errors in the PanDevice class

    The PanDevice class may raise errors when problems occur such as
    response parsing problems.  This exception class is raised on those
    errors. This class is not for errors connecting to the API, as
    pan.xapi.PanXapiError is responsible for those.

    Attributes:
        message: The error message for the exception
    """
    def __init__(self, *args, **kwargs):
        self.pan_device = kwargs.pop('pan_device', None)
        super(PanDeviceError, self).__init__(*args, **kwargs)

class PanDeviceXapiError(PanDeviceError):
    pass

class PanInvalidCredentials(PanDeviceXapiError):
    pass

class PanURLError(PanDeviceXapiError):
    pass

class PanConnectionTimeout(PanDeviceXapiError):
    pass

class PanJobTimeout(PanDeviceXapiError):
    pass

class PanLockError(PanDeviceError):
    pass

class PanPendingChanges(PanDeviceError):
    pass

class PanCommitInProgress(PanDeviceXapiError):
    pass

class PanInstallInProgress(PanDeviceXapiError):
    pass

class PanCommitFailed(PanDeviceError):
    def __init__(self, *args, **kwargs):
        self.result = kwargs.pop('result', None)
        super(PanCommitFailed, self).__init__("Commit failed", *args, **kwargs)

class PanCommitNotNeeded(PanDeviceError):
    pass

class PanSessionTimedOut(PanDeviceXapiError):
    pass

class PanDeviceNotSet(PanDeviceError):
    pass

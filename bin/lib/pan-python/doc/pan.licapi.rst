..
 Copyright (c) 2017 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

==========
pan.licapi
==========

--------------------------------------------
Python interface to the PAN-OS Licensing API
--------------------------------------------

NAME
====

 pan.licapi - Python interface to the PAN-OS Licensing API

SYNOPSIS
========
::

 import pan.licapi

 try:
     licapi = pan.licapi.PanLicapi(panrc_tag='license')
 except pan.licapi.PanLicapiError as e:
     print('pan.licapi.PanLicapi:', e, file=sys.stderr)
     sys.exit(1)

 try:
     r = licapi.get(authcode='I3546330')
 except pan.licapi.PanLicapiError as e:
     print('get:', e, file=sys.stderr)
     sys.exit(1)

 try:
     r.raise_for_status()
 except pan.licapi.PanLicapiError as e:
     print('get:', e, file=sys.stderr)
     sys.exit(1)

 print(r.json)

DESCRIPTION
===========

 The pan.licapi module defines the PanLicapi class, which provides an
 interface to the PAN-OS Licensing API.

 PanLicapi provides an interface to all Licensing API requests:

 ==============================  ==============================   ================
 Request                         PanLicapi Method                 API Resource URI
 ==============================  ==============================   ================
 activate VM license             activate()                       /api/license/activate
 deactivate VM license           deactivate()                     /api/license/deactivate
 get quantity of VM provisioned  get()                            /api/license/get
 ==============================  ==============================   ================

pan.licapi Constants
--------------------

 **__version__**
  pan package version string.

 **DEBUG1**, **DEBUG2**, **DEBUG3**
  Python ``logging`` module debug levels (see **Debugging and
  Logging** below).

 **DEFAULT_API_VERSION**
  Default API version.

pan.licapi Constructor, Response object and Exception Class
-----------------------------------------------------------

class pan.licapi.PanLicapi()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::

  class pan.licapi.PanLicapi(api_version=None,
                             panrc_tag=None,
                             hostname=None,
                             api_key=None,
                             timeout=None,
                             verify_cert=True)

 **api_version**
  API version as a string in the form v\ **version** or
  **version** (e.g., *v1*).  The API version is used to determine
  the PanLicapi class implementation to use.

  The default API version is **DEFAULT_API_VERSION**.

  **api_version** is verified and the class attribute is set to an
  instance of the _ApiVersion class (defined below).

 **panrc_tag**
  .panrc tagname.

 **hostname**
  URI hostname used in API requests.    This can also be
  specified in a .panrc file using the ``hostname`` *varname*.

  The default is ``api.paloaltonetworks.com``.

 **api_key**
  ``apikey`` HTTP request header argument used in API requests.  This
  can also be specified in a .panrc file using the ``api_key``
  *varname*.

 **timeout**
  The HTTP connect ``timeout`` in seconds.

 **verify_cert**
  Specify if SSL server certificate verification is performed.

  The default is to verify the server certificate.

exception pan.licapi.PanLicapiError
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the PanLicapi class when an error occurs.  The
 string representation of an instance of this exception will contain a
 user-friendly error message.

class pan.licapi.PanLicapiRequest()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The results of a request are returned in a PanLicapiRequest object.

pan.licapi.PanLicapiRequest Class Attributes and Methods
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 =================      ===========
 Attribute              Description
 =================      ===========
 name                   Method name for the request
 wall_time              Wall time of API request in seconds (floating point number)
 http_code              HTTP response status code
 http_reason            HTTP response status reason
 http_headers           HTTP headers.  This is an **email.message.Message** object.
 http_encoding          Charset (set using ``email.message.Message.get_content_charset()``)
 http_content_type      Content type (set using ``email.message.Message.get_content_type()``)
 http_content           HTTP response body (bytes)
 http_text              HTTP response body (Unicode)
 json                   HTTP response body (JSON)
 =================      ===========

raise_for_status()
~~~~~~~~~~~~~~~~~~

 The ``raise_for_status()`` method will raise PanLicapiError when the
 http_code attribute is not a 2XX success class status code.

 A non-2XX status code will not by default cause an exception to
 be raised.

pan.licapi.PanLicapi Methods
----------------------------

activate(authcode=None, uuid=None, cpuid=None, serialnumber=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``activate()`` method performs the ``/api/license/activate`` API
 request to activate a VM license.

 **authcode**
  License Auth Code.

 **uuid**
  VM-Series vm-uuid.

 **cpuid**
  VM-Series vm-cpuid.

 **serialnumber**
  Previously activated device serial number.

 There are 3 calling sequences depending upon the arguments passed:

 =====================  ===========
 Arguments              Description
 =====================  ===========
 authcode, uuid, cpuid  Activate new license and return licenses
 uuid, cpuid            Get previously activated licenses
 serialnumber           Get previously activated licenses
 =====================  ===========

deactivate(encryptedtoken=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``deactivate()`` method performs the ``/api/license/deactivate`` API
 request to deactivate a VM license.

 **encryptedtoken**
  The contents of the license-token-file from PAN-OS which is obtained
  using the operational command ``request license deactivate
  VM-Capacity mode manual``.

  The token file is exported from the device using ``scp export
  license-token-file`` or ``tftp export license-token-file``.

  Starting with PAN-OS 8.0 you can display the token file using ``show
  license-token-files name``.  This can be used to export the token
  file using the PAN-OS XML API.

get(authcode=None)
~~~~~~~~~~~~~~~~~~

 The ``get()`` method performs the ``/api/license/get`` API request to
 get the quantity of VM provisioned for an Auth Code.

 **authcode**
  License Auth Code.

pan.licapi._ApiVersion class Attributes and Methods
---------------------------------------------------

 The _ApiVersion class provides an interface to the API version of the
 PanLicapi class instance.

 =================      ===========
 Attribute              Description
 =================      ===========
 version                version as an integer
 =================      ===========

__str__()
~~~~~~~~~

 version as a string in the format v\ **version**.  (e.g., *v1*).

__int__()
~~~~~~~~~

 version as an integer with the following layout:

 ==================  ===========
 Bits (MSB 0 order)  Description
 ==================  ===========
 0-15                unused
 16-23               version
 24-31               reserved for future use
 ==================  ===========

Sample Usage
~~~~~~~~~~~~

::

 import pan.licapi

 try:
     licapi = pan.licapi.PanLicapi(panrc_tag='license')
 except pan.licapi.PanLicapiError as e:
     print('pan.licapi.PanLicapi:', e, file=sys.stderr)
     sys.exit(1)

 print('api_version: %s, 0x%04x' %
       (licapi.api_version, licapi.api_version))

Debugging and Logging
---------------------

 The Python standard library ``logging`` module is used to log debug
 output; by default no debug output is logged.

 In order to obtain debug output the ``logging`` module must be
 configured: the logging level must be set to one of **DEBUG1**,
 **DEBUG2**, or **DEBUG3** and a handler must be configured.
 **DEBUG1** enables basic debugging output and **DEBUG2** and
 **DEBUG3** specify increasing levels of debug output.

 For example, to configure debug output to **stderr**:
 ::

  import logging

  if options['debug']:
      logger = logging.getLogger()
      if options['debug'] == 3:
          logger.setLevel(pan.licapi.DEBUG3)
      elif options['debug'] == 2:
          logger.setLevel(pan.licapi.DEBUG2)
      elif options['debug'] == 1:
          logger.setLevel(pan.licapi.DEBUG1)

      handler = logging.StreamHandler()
      logger.addHandler(handler)

FILES
=====

 ``.panrc``
  .panrc file

EXAMPLES
========

 The **panlicapi.py** command line program calls each available
 PanLicapi method and can be reviewed for sample usage.

SEE ALSO
========

 panlicapi.py

 Licensing API Documentation
  https://www.paloaltonetworks.com/documentation/80/virtualization/virtualization/license-the-vm-series-firewall/licensing-api

AUTHORS
=======

 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>

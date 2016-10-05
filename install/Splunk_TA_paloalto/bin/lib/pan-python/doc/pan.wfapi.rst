..
 Copyright (c) 2014-2016 Kevin Steves <kevin.steves@pobox.com>

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

=========
pan.wfapi
=========

------------------------------------
Python interface to the WildFire API
------------------------------------

NAME
====

 pan.wfapi - Python interface to the WildFire API

SYNOPSIS
========
::

 import pan.wfapi

 try:
     wfapi = pan.wfapi.PanWFapi(tag='wildfire')

 except pan.wfapi.PanWFapiError as msg:
     print('pan.wfapi.PanWFapi:', msg, file=sys.stderr)
     sys.exit(1)

 sample = '/var/wildfire/samples/sample1.exe'

 try:
     wfapi.submit(file=sample)

 except pan.wfapi.PanWFapiError as msg:
     print('submit:', msg, file=sys.stderr)
     sys.exit(1)

 print('sample %s submitted' % sample)
 print(wfapi.response_body)

DESCRIPTION
===========

 The pan.wfapi module defines the PanWFapi class, which provides an
 interface to the WildFire API.

 PanWFapi provides an interface to all WildFire API requests:

 ==============================   ========
 Request                          URI path
 ==============================   ========
 submit file                      /publicapi/submit/file
 submit URL                       /publicapi/submit/url
 submit link                      /publicapi/submit/link
 submit links                     /publicapi/submit/links
 submit verdict change request    /publicapi/submit/change-request
 get previously uploaded sample   /publicapi/get/sample
 get sample PCAP                  /publicapi/get/pcap
 get sample analysis report       /publicapi/get/report
 get sample verdict               /publicapi/get/verdict
 get sample verdicts              /publicapi/get/verdicts
 get verdicts changed             /publicapi/get/verdicts/changed
 get sample malware test file     /publicapi/test/pe
 ==============================   ========

pan.wfapi Constants
-------------------

 **__version__**
  pan package version string.

 **DEBUG1**, **DEBUG2**, **DEBUG3**
  Python ``logging`` module debug levels (see **Debugging and
  Logging** below).

 **BENIGN**, **MALWARE**, **GRAYWARE**, **PENDING**, **ERROR**, **UNKNOWN**, **INVALID**
  Constants for the integer verdict values.

 **VERDICTS**
  A dictionary which maps the integer verdict values to a tuple
  of (name, description).


pan.wfapi Constructor and Exception Class
-----------------------------------------

class pan.wfapi.PanWFapi()
~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::

  class pan.wfapi.PanWFapi(tag=None,
                           hostname=None,
                           api_key=None,
                           timeout=None,
                           http=False,
                           ssl_context=None)

 **tag**
  .panrc tagname.

 **hostname**
  URI hostname used in API requests.    This can also be
  specified in a .panrc file using the ``hostname`` *varname*.

  This is used to specify an alternate cloud (e.g.,
  ``beta.wildfire.paloaltonetworks.com``) or a WildFire appliance.

  The default is ``wildfire.paloaltonetworks.com``.

 **api_key**
  ``api_key`` argument used in API requests.  This can also be
  specified in a .panrc file using the ``api_key`` *varname*.

 **timeout**
  The ``timeout`` value for urlopen() in seconds.

 **http**
  Use *http* URL scheme for API requests.  This can be used with the
  ``testfile()`` method to get a malware test file over HTTP.

 **ssl_context**
  An ssl.SSLContext() to use for HTTPS requests.  An SSL context holds
  data such as SSL configuration options and certificates.

  This can be used to specify the ``cafile``, ``capath`` and other SSL
  configuration options.

  When ``ssl_context`` is *None*, if the **certifi** package is
  installed its Certificate Authority (CA) bundle is used for SSL
  server certificate verification, otherwise no changes are made to
  the default **ssl** module settings.

  The default is *None*.

  SSL contexts are supported starting in Python versions 2.7.9
  and 3.2.

exception pan.wfapi.PanWFapiError
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the PanWFapi class when an error occurs.  The
 string representation of an instance of this exception will contain a
 user-friendly error message.

pan.wfapi.PanWFapi Methods
--------------------------

submit(file=None, url=None, links=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``submit()`` method submits a file, URL or web page links to
 WildFire for analysis.

 **file**
  Path to a file to submit for analysis.

 **url**
  URL to a file to submit for analysis.

 **links**
  List of links (URLs to web pages) to submit for analysis.
  A maximum of 1,000 links can be submitted in a request.

 You must submit one of **file**, **url** or **links**.

change_request(hash=None, verdict=None, email=None, comment=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``change_request()`` method is used to request a manual review
 of a sample's verdict by the Threat Research Team.

 **hash**
  The SHA256 hash for the sample.

 **verdict**
  The suggested integer verdict.

 **email**
  Notification e-mail address.

 **comment**
  Explanation for the change request.  Can be up to 2048 bytes.

sample(hash=None)
~~~~~~~~~~~~~~~~~

 The ``sample()`` method gets a previously uploaded sample file.  The
 sample can be specified by its MD5 or SHA256 hash.

report(hash=None, format=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``report()`` method gets an analysis report for a previously uploaded
 sample.  The sample can be specified by its MD5 or SHA256 hash.
 The report format can be ``xml`` or ``pdf``.  The default is ``xml``.

verdict(hash=None)
~~~~~~~~~~~~~~~~~~

verdicts(hashes=None)
~~~~~~~~~~~~~~~~~~~~~

 The ``verdict()`` and ``verdicts()`` methods get the verdict(s) for
 previously uploaded samples.  The sample can be specified by its MD5
 or SHA256 hash.  The ``verdict()`` **hash** argument is a single hash
 and the ``verdicts()`` **hashes** argument is a list of up to 500
 hashes.

 The result is an XML document with verdict represented as an integer:

 =====  ========  ===========
 Value  Verdict   Description
 =====  ========  ===========
 0      benign
 1      malware
 2      grayware
 -100   pending   sample exists and verdict not known
 -101   error     sample is in error state
 -102   unknown   sample does not exist
 -103   invalid   hash is invalid (verdicts() method only)
 =====  ========  ===========

verdicts_changed(date=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``verdicts_changed()`` method gets the hashes of samples whose
 verdicts have changed within the last 30 days starting at the date
 specified.  The format for the **date** argument is *YYYY-MM-DD*.

pcap(hash=None, platform=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``pcap()`` method gets a PCAP (packet capture) file of network
 activity for a previously uploaded sample.  The sample can be
 specified by its MD5 or SHA256 hash.  The sandbox environment for the
 PCAP can optionally be specified using the platform ID.  If no
 platform is specified a PCAP from an environment that resulted in a
 *Malware* verdict is returned.

 Valid platform IDs are:

 ===========  ===================
 Platform ID  Sandbox Environment
 ===========  ===================
 1            Windows XP, Adobe Reader 9.3.3, Office 2003
 2            Windows XP, Adobe Reader 9.4.0, Flash 10, Office 2007
 3            Windows XP, Adobe Reader 11, Flash 11, Office 2010
 4            Windows 7, Adobe Reader 11, Flash 11, Office 2010
 5            Windows 7 x64 SP1, Adobe Reader 11, Flash 11, Office 2010
 201          Android 2.3, API 10, avd2.3.1
 ===========  ===================

testfile()
~~~~~~~~~~

 The ``testfile()`` method gets a sample malware test file.  Each request
 returns a similar PE (Portable Executable) file named
 ``wildfire-test-pe-file.exe`` with a different hash and with verdict
 *Malware*.

 This currently requires an ``api_key`` even though it is not
 needed for the API request.

attachment
~~~~~~~~~~

 The ``attachment`` data attribute is a dictionary used to access a
 downloaded file's filename and content; it will contain two keys:

 ========  =====
 Key       Value
 ========  =====
 filename  filename field in content-disposition header
 content   file content from HTTP message body
 ========  =====

http_code
~~~~~~~~~

 The ``http_code`` data attribute contains the HTTP response status
 code.

 Status codes that can be returned include:

 ===============================  ===========
 HTTP status-code, reason-phrase  Description
 ===============================  ===========
 401 Unauthorized                 API key invalid
 403 Forbidden                    Permission denied
 404 Not Found                    Report/sample/pcap not found
 405 Method Not Allowed           Must use method POST
 413 Request Entity Too Large     Sample size exceeds maximum
 418                              Invalid file type
 419 Quota Exceeded               Maximum daily uploads exceeded
 419 Quota Exceeded               Maximum daily queries exceeded
 420 Insufficient Arguments       Missing required request parameter
 421 Invalid Argument             Invalid request parameter
 422 URL Download Error           URL download error
 456                              Invalid request
 513                              File upload failed
 ===============================  ===========

http_reason
~~~~~~~~~~~

 The ``http_reason`` data attribute contains the HTTP response reason
 phrase.

response_body
~~~~~~~~~~~~~

 The ``response_body`` data attribute contains the HTTP response
 message body.

response_type
~~~~~~~~~~~~~

 The ``response_type`` data attribute is set to ``xml`` when the message
 body is an XML document.

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
          logger.setLevel(pan.wfapi.DEBUG3)
      elif options['debug'] == 2:
          logger.setLevel(pan.wfapi.DEBUG2)
      elif options['debug'] == 1:
          logger.setLevel(pan.wfapi.DEBUG1)

      handler = logging.StreamHandler()
      logger.addHandler(handler)

FILES
=====

 ``.panrc``
  .panrc file

EXAMPLES
========

 The **panwfapi.py** command line program calls each available
 PanWFapi method and can be reviewed for sample usage.

SEE ALSO
========

 panwfapi.py

 WildFire Administrator's Guide
  https://www.paloaltonetworks.com/documentation/71/wildfire/wf_admin

 WildFire API
  https://www.paloaltonetworks.com/documentation/71/wildfire/wf_api

AUTHORS
=======

 Kevin Steves <kevin.steves@pobox.com>

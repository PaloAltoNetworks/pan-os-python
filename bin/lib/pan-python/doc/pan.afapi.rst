..
 Copyright (c) 2014-2015 Kevin Steves <kevin.steves@pobox.com>
 Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>

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
pan.afapi
=========

-------------------------------------
Python interface to the AutoFocus API
-------------------------------------

NAME
====

 pan.afapi - Python interface to the AutoFocus API

SYNOPSIS
========
::

 import pan.afapi

 try:
     afapi = pan.afapi.PanAFapi(panrc_tag='autofocus')
 except pan.afapi.PanAFapiError as e:
     print('pan.afapi.PanAFapi:', e, file=sys.stderr)
     sys.exit(1)

 data = '{"scope":"unit42","pageSize":200}'
 try:
     r = afapi.tags(data)
 except pan.afapi.PanAFapiError as e:
     print('tags:', e, file=sys.stderr)
     sys.exit(1)

 try:
     r.raise_for_status()
 except pan.afapi.PanAFapiError as e:
     print('tags:', e, file=sys.stderr)
     sys.exit(1)

 for tag in r.json['tags']:
     print(tag['public_tag_name'], tag['count'])

DESCRIPTION
===========

 The pan.afapi module defines the PanAFapi class, which provides an
 interface to the AutoFocus API.

 PanAFapi provides an interface to all AutoFocus API requests:

 =========================   ==============================   ================
 Request                     PanAFapi Method                  API Resource URI
 =========================   ==============================   ================
 Search samples              samples_search()                 /samples/search/
 Get samples results         samples_search_results()         /samples/results/
 Search sessions             sessions_search()                /sessions/search/
 Get sessions results        sessions_search_results()        /sessions/results/
 Get histogram of sessions   sessions_histogram_search()      /sessions/histogram/search/
 Get histogram results       sessions_histogram_results()     /sessions/histogram/results/
 Get aggregate of sessions   sessions_aggregate_search()      /sessions/aggregate/search/
 Get aggregate results       sessions_aggregate_results()     /sessions/aggregate/results/
 Search top tags             top_tags_search()                /top-tags/search/
 Get top tags results        top_tags_results()               /top-tags/results/
 Search tags                 tags()                           /tags/
 Get tag                     tag()                            /tag/
 Get session                 session()                        /session/
 Get sample analysis         sample_analysis()                /sample/{id}/analysis
 Export list                 export()                         /export/
 =========================   ==============================   ================

 In addition, convenience methods are provided for the search/results
 requests to perform the search and provide the results when the
 search is completed:

 ====================================   =================
 PanAFapi Method                        API Resource URIs
 ====================================   =================
 samples_search_results()               | /samples/search/
                                        | /samples/results/
 sessions_search_results()              | /sessions/search/
                                        | /sessions/results/
 sessions_histogram_search_results()    | /sessions/histogram/search/
                                        | /sessions/histogram/results/
 sessions_aggregate_search_results()    | /sessions/aggregate/search/
                                        | /sessions/aggregate/results/
 top_tags_search_results()              | /top-tags/search/
                                        | /top-tags/results/
 ====================================   =================

pan.afapi Constants
-------------------

 **__version__**
  pan package version string.

 **DEBUG1**, **DEBUG2**, **DEBUG3**
  Python ``logging`` module debug levels (see **Debugging and
  Logging** below).

 **DEFAULT_API_VERSION**
  Default API version.

pan.afapi Constructor, Response object and Exception Class
----------------------------------------------------------

class pan.afapi.PanAFapi()
~~~~~~~~~~~~~~~~~~~~~~~~~~
 ::

  class pan.afapi.PanAFapi(api_version=None,
                           panrc_tag=None,
                           hostname=None,
                           api_key=None,
                           timeout=None,
                           verify_cert=True,
                           sleeper=None)

 **api_version**
  API version as a string in the form v\ **major**.\ **minor** or
  **major**.\ **minor** (e.g., *v1.0*).  The API version is used to determine
  the PanAFapi class implementation to use.

  The default API version is **DEFAULT_API_VERSION**.

  **api_version** is verified and the class attribute is set to an
  instance of the _ApiVersion class (defined below).

 **panrc_tag**
  .panrc tagname.

 **hostname**
  URI hostname used in API requests.    This can also be
  specified in a .panrc file using the ``hostname`` *varname*.

  The default is ``autofocus.paloaltonetworks.com``.

 **api_key**
  ``apiKey`` argument used in API requests.  This can also be
  specified in a .panrc file using the ``api_key`` *varname*.

 **timeout**
  The HTTP connect ``timeout`` in seconds.

 **verify_cert**
  Specify if SSL server certificate verification is performed.

  The default is to verify the server certificate.

 **sleeper**
  A class definition used to sleep between the search
  request, and each results request in the search/results convenience
  methods.

  The default is PanAFapi._Sleeper.

exception pan.afapi.PanAFapiError
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the PanAFapi class when an error occurs.  The
 string representation of an instance of this exception will contain a
 user-friendly error message.

class pan.afapi.PanAFapiRequest()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The results of a request are returned in a PanAFapiRequest object.

pan.afapi.PanAFapiRequest Class Attributes and Methods
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 =================      ===========
 Attribute              Description
 =================      ===========
 name                   Method name for the request
 http_code              HTTP response status code
 http_reason            HTTP response status reason
 http_headers           HTTP headers.  This is an **email.message.Message** object.
 http_encoding          Charset from the content-type header if set
 http_content           HTTP response body (bytes)
 http_text              HTTP response body (Unicode)
 json                   HTTP response body (JSON)
 =================      ===========

raise_for_status()
~~~~~~~~~~~~~~~~~~

 The ``raise_for_status()`` method will raise PanAFapiError when the
 http_code attribute is not a 2XX success class status code.

 A non-2XX status code will not by default cause an exception to
 be raised.

pan.afapi.PanAFapi Methods
--------------------------

samples_search(data=None)
~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``samples_search()`` method performs the ``/samples/search/`` API
 request to search WildFire samples.


 **data**
  JSON object for HTTP request body.

samples_results(af_cookie=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``samples_results()`` method performs the ``/samples/results/``
 API request to get samples search results.

 **af_cookie**
  The af_cookie to get the search results.

samples_search_results(self, data=None, terminal=True)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``samples_search_results()`` method calls the
 ``samples_search()`` method, and then calls the ``samples_results()``
 method until the response body contains a *complete* ``af_message``.

 This method is implemented as a generator function.

 **data**
  JSON object for ``samples_search()`` HTTP request body.

 **terminal**
  Specify if only the terminal (complete) search result should be
  returned or if the intermediate (incomplete) search results should
  also be returned.

  By default only the terminal search result is returned.

sessions_search(data=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_search()`` method performs the ``/sessions/search/``
 API request to search sessions.

 **data**
  JSON object for HTTP request body.

sessions_results(af_cookie=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_results()`` method performs the ``/sessions/results/``
 API request to get sessions search results.


 **af_cookie**
  The af_cookie to get the search results.

sessions_search_results(self, data=None, terminal=True)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_search_results()`` method calls the
 ``sessions_search()`` method, and then calls the
 ``sessions_results()`` method until the response body contains a
 *complete* ``af_message``.

 This method is implemented as a generator function.

 **data**
  JSON object for ``sessions_search()`` HTTP request body.

 **terminal**
  Specify if only the terminal (complete) search result should be
  returned or if the intermediate (incomplete) search results should
  also be returned.

  By default only the terminal search result is returned.

sessions_histogram_search(data=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_histogram_search()`` method performs the
 ``/sessions/histogram/search/`` API request to search sessions
 histogram data.  This data corresponds to the *Malware Download
 Sessions* data when you view search statistics in the AutoFocus
 portal.

 **data**
  JSON object for HTTP request body.

sessions_histogram_results(af_cookie=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_histogram_results()`` method performs the
 ``/sessions/histogram/results/`` API request to get sessions
 histogram search results.


 **af_cookie**
  The af_cookie to get the search results.

sessions_histogram_search_results(self, data=None, terminal=True)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_histogram_search_results()`` method calls the
 ``sessions_histogram_search()`` method, and then calls the
 ``sessions_histogram_results()`` method until the response body
 contains a *complete* ``af_message``.

 This method is implemented as a generator function.

 **data**
  JSON object for ``sessions_histogram_search()`` HTTP request body.

 **terminal**
  Specify if only the terminal (complete) search result should be
  returned or if the intermediate (incomplete) search results should
  also be returned.

  By default only the terminal search result is returned.

sessions_aggregate_search(data=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_aggregate_search()`` method performs the
 ``/sessions/aggregate/search/`` API request to search sessions
 aggregate data.  This data corresponds to the *Top*
 data such as *Top Applications* and *Top Malware* in the AutoFocus
 portal dashboard.

 **data**
  JSON object for HTTP request body.

sessions_aggregate_results(af_cookie=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_aggregate_results()`` method performs the
 ``/sessions/aggregate/results/`` API request to get sessions
 aggregate search results.


 **af_cookie**
  The af_cookie to get the search results.

sessions_aggregate_search_results(self, data=None, terminal=True)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sessions_aggregate_search_results()`` method calls the
 ``sessions_aggregate_search()`` method, and then calls the
 ``sessions_aggregate_results()`` method until the response body contains
 a *complete* ``af_message``.

 This method is implemented as a generator function.

 **data**
  JSON object for ``sessions_aggregate_search()`` HTTP request body.

 **terminal**
  Specify if only the terminal (complete) search result should be
  returned or if the intermediate (incomplete) search results should
  also be returned.

  By default only the terminal search result is returned.

top_tags_search(data=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``top_tags_search()`` method performs the ``/top-tags/search/``
 API request to search top tags data.  This data corresponds to
 the *Top Tags* data in the AutoFocus portal dashboard and search
 statistics.

 **data**
  JSON object for HTTP request body.

top_tags_results(af_cookie=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``top_tags_results()`` method performs the ``/top-tags/results/``
 API request to get top tags search results.


 **af_cookie**
  The af_cookie to get the search results.

top_tags_search_results(self, data=None, terminal=True)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``top_tags_search_results()`` method calls the
 ``top_tags_search()`` method, and then calls the
 ``top_tags_results()`` method until the response body contains
 a *complete* ``af_message``.

 This method is implemented as a generator function.

 **data**
  JSON object for ``top_tags_search()`` HTTP request body.

 **terminal**
  Specify if only the terminal (complete) search result should be
  returned or if the intermediate (incomplete) search results should
  also be returned.

  By default only the terminal search result is returned.

tags(data=None)
~~~~~~~~~~~~~~~

 The ``tags()`` method performs the ``/tags/`` API request to
 search AutoFocus tags.

 **data**
  JSON object for HTTP request body.

tag(tagname=None)
~~~~~~~~~~~~~~~~~

 The ``tag()`` method performs the ``/tag/`` API request to
 get details for an AutoFocus tag.

 **tagname**
  Public tag name.  The public tag name is preceded by
  a prefix which uniquely identifies the tag (e.g., 1234.abc).

session(sessionid=None)
~~~~~~~~~~~~~~~~~~~~~~~

 The ``session()`` method performs the ``/session/`` API
 request to get details for a session.

 **sessionid**
  The AutoFocus session ID.

sample_analysis(data=None, sampleid=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ``sample_analysis()`` method performs the
 ``/sample/{id}/analysis`` API request to get details for a
 sample's WildFire analysis.

 **sampleid**
  The AutoFocus sample ID.

export(data=None)
~~~~~~~~~~~~~~~~~

 The ``export()`` method performs the ``/export/`` API
 request to export a list of saved AutoFocus artifacts.

 **data**
  JSON object for HTTP request body.

pan.afapi._ApiVersion class Attributes and Methods
--------------------------------------------------

 The _ApiVersion class provides an interface to the API version of the
 PanAFapi class instance.

 =================      ===========
 Attribute              Description
 =================      ===========
 major                  major version as an integer
 minor                  minor version as an integer
 =================      ===========

__str__()
~~~~~~~~~

 Major and minor version as a string in the format v\ **major**.\
 **minor** (e.g., *v1.0*).

__int__()
~~~~~~~~~

 Major and minor version as an integer with the following layout:

 ==================  ===========
 Bits (MSB 0 order)  Description
 ==================  ===========
 0-7                 unused
 8-15                major version
 16-23               minor version
 24-31               reserved for future use
 ==================  ===========

Sample Usage
~~~~~~~~~~~~

::

 import pan.afapi

 try:
     afapi = pan.afapi.PanAFapi(panrc_tag='autofocus')
 except pan.afapi.PanAFapiError as e:
     print('pan.afapi.PanAFapi:', e, file=sys.stderr)
     sys.exit(1)

 print('api_version: %s, 0x%06x' %
       (afapi.api_version, afapi.api_version))

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
          logger.setLevel(pan.afapi.DEBUG3)
      elif options['debug'] == 2:
          logger.setLevel(pan.afapi.DEBUG2)
      elif options['debug'] == 1:
          logger.setLevel(pan.afapi.DEBUG1)

      handler = logging.StreamHandler()
      logger.addHandler(handler)

FILES
=====

 ``.panrc``
  .panrc file

EXAMPLES
========

 The **panafapi.py** command line program calls each available
 PanAFapi method and can be reviewed for sample usage.

SEE ALSO
========

 panafapi.py

 AutoFocus API Reference
  https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_api.html

AUTHORS
=======

 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>

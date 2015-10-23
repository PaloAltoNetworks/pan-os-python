..
 NOTE: derived from documentation in PAN-perl

 Copyright (c) 2011 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 Copyright (c) 2013-2015 Kevin Steves <kevin.steves@pobox.com>

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

========
pan.xapi
========

--------------------------------------
Python interface to the PAN-OS XML API
--------------------------------------

NAME
====

 pan.xapi - Python interface to the PAN-OS XML API

SYNOPSIS
========
::

 import pan.xapi

 try:
     xapi = pan.xapi.PanXapi(tag='pa-200')
 except pan.xapi.PanXapiError as msg:
     print('pan.xapi.PanXapi:', msg, file=sys.stderr)
     sys.exit(1)

 xpath = "/config/devices/entry/vsys/entry/rulebase/security/rules/"
 xpath += "entry[@name='rule7']/disabled"
 element = "<disabled>yes</disabled>"

 try:
     xapi.edit(xpath=xpath,
               element=element)
 except pan.xapi.PanXapiError as msg:
     print('edit:', msg, file=sys.stderr)
     sys.exit(1)

 print('policy disabled')

DESCRIPTION
===========

 The pan.xapi module defines the PanXapi class, which provides an
 interface to the PAN-OS XML API.

 PanXapi provides an interface to the following API request types:

 - key generation: ``type=keygen``
 - device configuration: ``type=config``
 - commit configuration: ``type=commit``
 - operational command: ``type=op``
 - export file: ``type=export``
 - dynamic object update: ``type=user-id``
 - log retrieval: ``type=log``

pan.xapi Constants
------------------

 **__version__**
  pan package version string.

 **DEBUG1**, **DEBUG2**, **DEBUG3**
  Python ``logging`` module debug levels (see **Debugging and
  Logging** below).

pan.xapi Constructor and Exception Class
----------------------------------------

class pan.xapi.PanXapi()
~~~~~~~~~~~~~~~~~~~~~~~~
 ::

  class pan.xapi.PanXapi(tag=None,
                         api_username=None,
                         api_password=None,
                         api_key=None,
                         hostname=None,
                         port=None,
                         serial=None,
                         use_http=False,
                         use_get=False,
                         timeout=None,
                         ssl_context=None)

 **tag**
  .panrc tagname.

 **api_username**
  **user** argument for ``type=keygen`` request.

 **api_password**
  **password** argument for ``type=keygen`` request.

 **api_key**
  **key** argument for API requests.

 **hostname**
  PAN-OS hostname or IP address. Used to construct request URI.

 **port**
  Port number used in the URL.  This can be used to
  perform port forwarding using for example ssh(1).

 **api_username**, **api_password**, **hostname**, **port** and
 **api_key** can be passed as function arguments, or specified using a
 .panrc file.  Either **api_username** and
 **api_password** or **api_key** must be provided.  When
 **api_username** and **api_password** are provided the **api_key**
 will be generated automatically using the API ``type=keygen`` request
 and used as the key for API requests

 **serial**
  Serial number used for Panorama to device redirection.
  This sets the **target** argument to the serial number specified in
  device configuration, commit configuration, key generation, dynamic
  object update and operational command API requests.

  When an API request is made on Panorama and the serial number is
  specified, Panorama will redirect the request to the managed device
  with the serial number.

 **use_http**
  Use the *http* URL scheme for API requests.  The default is to use
  the *https* URL scheme.

 **use_get**
  Use the HTTP *GET* method for API requests.  The default is to use
  the HTTP *POST* method with Content-Type
  application/x-www-form-urlencoded.

 **timeout**
  The ``timeout`` value for urlopen().

 **ssl_context**
  An ssl.SSLContext() to use for HTTPS requests.  An SSL context holds
  data such as SSL configuration options and certificates.

  This can be used to specify the ``cafile``, ``capath`` and other SSL
  configuration options.

  SSL contexts are supported starting in Python versions 2.7.9
  and 3.2.

  Starting with Python versions 2.7.9 and 3.4.3 SSL server certificate
  verification is performed by default as described in PEP 476.
  Because many PAN-OS systems use a self-signed certificate, pan.xapi
  will disable the default starting with these versions.
  **ssl_context** can be used to enable verification.

exception pan.xapi.PanXapiError
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 Exception raised by the PanXapi class when an error occurs.  The
 string representation of an instance of this exception will contain a
 user-friendly error message.

pan.xapi.PanXapi Methods
------------------------

keygen()
~~~~~~~~

 The keygen() method performs the ``type=keygen`` key generation API
 request with the **api_username** and **api_password** arguments, and
 returns the *key* element in the response and sets the **api_key**
 data attribute (instance variable).

ad_hoc(qs=None, xpath=None, modify_qs=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The ad_hoc() method performs an ad hoc (custom) API request using
 the request parameters in **qs**.

 **qs** is either a query string with field=value pairs separated by
 ampersand (**&**) or a dictionary of field, value pairs.  The
 parameters will be URL-encoded before performing the API request.
 **modify_qs** can be set to *True* to insert known fields into the
 query string; the known fields that can be inserted are:

 - xpath
 - key (api_key)
 - user (api_username)
 - password (api_password)
 - target (serial)

 ad_hoc() can be used to construct API requests that are not
 directly supported by PanXapi.

show(xpath=None)
~~~~~~~~~~~~~~~~

 The show() method performs the ``action=show`` device configuration
 API request with the optional **xpath** argument.  show() is used to
 retrieve the *active* configuration on the firewall.

get(xpath=None)
~~~~~~~~~~~~~~~

 The get() method performs the ``action=get`` device configuration
 API request with the optional **xpath** argument.  get() is used to
 retrieve the *candidate* configuration on the firewall.

delete(xpath=None)
~~~~~~~~~~~~~~~~~~

 The delete() method performs the ``action=delete`` device
 configuration API request with the **xpath** argument. delete() is
 used to remove an existing object at the node specified by **xpath**.

set(xpath=None, element=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The set() method performs the ``action=set`` device configuration API
 request with the **xpath** and **element** arguments. set() is
 used to create a new object at the node specified by **xpath**.

edit(xpath=None, element=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The edit() method performs the ``action=edit`` device configuration
 API request with the **xpath** and **element** arguments.  edit()
 is used to replace an existing object at the node specified by
 **xpath**.

move(xpath=None, where=None, dst=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The move() method performs the ``action=move`` device configuration
 API request with the **xpath**, **where** and **dst** arguments.

 This moves the location of an existing node in the configuration
 specified by **xpath**.  **where** is used to specify the location of
 the node and can be *after*, *before*, *bottom* or *top*.  **dst** is
 used to specify the relative destination node name when **where** is
 *after* or *before*.

 move() is most frequently used to reorder rules (security, nat, qos,
 etc.) within the rulebase, however can be used to move other nodes in
 the configuration.

rename(xpath=None, newname=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The rename() method performs the ``action=rename`` device
 configuration API request with the **xpath** and **newname**
 arguments.

 This renames an existing node in the configuration specified by
 **xpath**.  **newname** is used to specify the new name for the node.

clone(xpath=None, xpath_from=None, newname=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The clone() method performs the ``action=clone`` device configuration
 API request with the **xpath**, **from** (*xpath_from* function
 argument) and **newname** arguments.

 This clones (copies) an existing node in the configuration specified
 by **xpath**.  **xpath_from** is used to specify the source XPath and
 **newname** is used to specify the new name for the cloned node.

override(xpath=None, element=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The override() method performs the ``action=override`` device
 configuration API request with the **xpath** and **element**
 arguments. override() is used to create a new object at a node
 that is part of a template from Panorama specified by **xpath**.
 Only certain nodes in the Network and Device categories can
 be overridden.

user_id(cmd=None, vsys=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The user_id() method performs the ``type=user-id`` dynamic object
 update API request with the **cmd** argument and optional **vsys**
 argument.  This is used to update dynamic objects including ip-user
 mappings and address objects.  **vsys** can be used to target the
 dynamic update to a specific Virtual System.

commit(cmd=None, action=None, sync=False, interval=None, timeout=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The commit() method performs the ``type=commit`` commit configuration
 API request with the **cmd** argument and optional **action**
 argument.  This schedules a job to execute a configuration mode
 **commit** command to commit the candidate configuration.

 **cmd** is an XML document used to specify commit arguments.

 **action** can be set to "all" to perform a ``commit-all`` on
 Panorama.

 Additional arguments include:

 - **sync**

   Perform a synchronous commit when set to *True*.

   The XML API schedules a job to perform the commit operation; the
   commit() method will then periodically perform an API request to
   determine if the job ID returned in the initial request is complete
   and return with the job status.  Additional arguments to control
   the polling include:

   - **interval**

    A floating point number specifying the query interval in seconds
    between each non-finished job status response.

    The default is 0.5 seconds.

   - **timeout**

    The maximum number of seconds to wait for the job to finish.

    The default is to try forever (**timeout** is set to *None* or 0).

op(cmd=None, vsys=None, cmd_xml=False)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The op() method performs the ``type=op`` operational command API
 request with the **cmd** argument and optional **vsys** argument.
 **cmd** is an XML document which represents the command to be executed.
 Commands and command options are XML elements, and command arguments
 are XML data.  **vsys** can be to to target the command to a specific
 Virtual System.

 When **cmd_xml** is *True* a CLI-style **cmd** argument is converted to
 XML.  This works by converting all unquoted arguments in **cmd** to
 start and end elements and treating double quoted arguments as text
 after removing the quotes.  For example:

 - show system info

   * <show><system><info></info></system></show>

 - show interface "ethernet1/1"

   * <show><interface>ethernet1/1</interface></show>

export(category=None, from_name=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export(category=None, pcapid=None, search_time=None, serialno=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The export() method performs the ``type=export`` export file API
 request with the **category** argument and optional **from** argument
 (*from_name* function argument).  If the request is successful, the
 **export_result** data attribute is a dictionary containing the
 following keys:

 - file: content-disposition response header filename
 - content: file contents
 - category: export category string

 The **category** argument specifies the type of file to export.  The
 **from_name** argument is used to specify the source for a file list
 or file export.

Threat PCAP export
##################

 In PAN-OS 6.0 the extended packet capture feature was added and is
 used for threat PCAPs.  As a result the **from** argument is no
 longer used to specify the source file, and it is not possible to
 obtain a file list.

 The PCAP is specified using the **pcapid**, **search_time** and
 **serialno** arguments.

 **pcapid** is a unique numeric identifier for the extended PCAP
 and is obtained from the **pcap_id** field in the THREAT log.

 **search_time** is used to narrow the search for the PCAP ID and is
 used to set a time window in the range *-5 minutes* to *+2 hours* of
 the time specified.  The search time is typically set to the
 **receive_time** field in the THREAT log.  The PAN-OS log time string
 format is used, for example: 2015/01/20 10:51:09.

 **search_time** is required in the API request; if not specified in
 the export() method it will be set to the threat epoch time which is
 part of the **pcapid**.

 **serialno** is required when exporting from Panorama and is used to
 specify the device of the PCAP.  It is also currently required when
 exporting from firewall devices, however this requirement will be
 removed in a future version of PAN-OS.

log(self, log_type=None, nlogs=None, skip=None, filter=None, interval=None, timeout=None)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 The log() method performs the ``type=log`` retrieve log API request
 with the **log-type** argument.

 **log-type** specifies the type of log to retrieve and can be:

 - config
 - hipmatch
 - system
 - threat
 - traffic
 - url
 - wildfire

 Additional API request arguments include:

 - **nlogs**

  Specify the number of logs to retrieve.

  The default is 20 and the maximum is 5000.

  **pan.xapi** currently loads the entire XML document into memory
  using the **ElementTree** module.  A large number of log entries can
  cause a memory exception which may not be possible to catch.  If you
  see exceptions when using a large **nlog** value try reducing it.

 - **skip**

  Specify the number of logs to skip. This can be used to retrieve log
  entries in batches by skipping previously retrieved logs.

  The default is 0.

 - **filter**

  Specify the log query selection filter.  This is a set of log
  filter expressions as can be specified in the Monitor tab in the
  Web UI.

  This is the **query** argument in the API request.

 The XML API schedules a job to create the log data; the log() method
 will then periodically perform an API request to determine if the
 job ID returned in the initial request is complete and receive the log
 data.  Additional arguments to control the polling include:

 - **interval**

  A floating point number specifying the query interval in seconds
  between each non-finished job status response.

  The default is 0.5 seconds.

 - **timeout**

  The maximum number of seconds to wait for the job to finish.

  The default is to try forever (**timeout** is set to *None* or 0).

extra_qs=None
~~~~~~~~~~~~~

 All API methods have an additional argument that can be used to
 modify (replace) and augment (add to) the standard parameters in the
 request.

 **extra_qs** is either a query string with field=value pairs
 separated by ampersand (**&**) or a dictionary of field, value pairs.
 The parameters will be URL-encoded before performing the API request.

xml_root()
~~~~~~~~~~

 The xml_root() method returns the XML document from the previous
 request as a string starting at the root node.

xml_result()
~~~~~~~~~~~~

 The xml_root() method returns the XML document from the previous
 request as a string starting at the child of the result element.

status
~~~~~~

 The status data attribute contains the XML response element status
 attribute received from the previous API request.  Possible values
 are:

 - success
 - error
 - unauth

status_code
~~~~~~~~~~~

 The status_code data attribute contains the XML response element
 code attribute from the previous API request if one is available.

status_detail
~~~~~~~~~~~~~

 The status_detail data attribute contains the XML status message
 received from the previous API request if one is available.  This is
 the value within a msg or line element.

text_document
~~~~~~~~~~~~~

 The text_document data attribute contains the message body from the
 previous API request when the response content-type is text/plain.

export_result
~~~~~~~~~~~~~

 The export_result data attribute is a dictionary containing the
 result of the previous export() method request when the response
 content-disposition is attachment.  The dictionary contains the
 following keys:

 - file: content-disposition response header filename
 - content: file contents
 - category: export category string

element_root
~~~~~~~~~~~~

 The element_root data attribute is set to the root element of the
 parsed response document XML tree; it is an **Element** object and is
 set using etree.ElementTree.fromstring().

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
          logger.setLevel(pan.xapi.DEBUG3)
      elif options['debug'] == 2:
          logger.setLevel(pan.xapi.DEBUG2)
      elif options['debug'] == 1:
          logger.setLevel(pan.xapi.DEBUG1)

      handler = logging.StreamHandler()
      logger.addHandler(handler)

set and edit
------------

 set and edit are similar, and have subtle differences.

 set can be described as a merge operation at the XPath node:

 - set will create new objects
 - set will update existing objects
 - set will not delete existing objects

 edit can be described as a replace operation at the Xpath node:

 - edit will create new objects
 - edit will update existing objects
 - edit will delete existing objects

get and show
------------

 get is used to retrieve the *candidate* configuration and show
 is used to retrieve the *active* configuration.

 XPath matching for get and show has differences.

 get:

 - return values even if the XPath matches multiple nodes
 - return values only if the resulting nodes are not text nodes and
   are actual elements in the XML

 show:

 - return values only if the XPath results in exactly one node
 - return the result even if the matched node is a text node

FILES
=====

 ``.panrc``
  .panrc file

EXAMPLES
========

 The **panxapi.py** command line program calls each available
 PanXapi method and can be reviewed for sample usage.

SEE ALSO
========

 panxapi.py

 PAN-OS 7.0 XML API Reference
  https://www.paloaltonetworks.com/documentation/70/pan-os.html

AUTHORS
=======

 Kevin Steves <kevin.steves@pobox.com>

CAVEATS
=======

 The XML API provides no version mechanism.  PanXapi does not obtain
 the PAN-OS version in order to determine API features and relies on
 the API to return errors for requests not supported on a PAN-OS
 version.

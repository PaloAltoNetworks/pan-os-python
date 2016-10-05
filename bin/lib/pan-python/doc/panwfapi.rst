..
 Copyright (c) 2013-2016 Kevin Steves <kevin.steves@pobox.com>

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

===========
panwfapi.py
===========

---------------------------------------------------
command line program for accessing the WildFire API
---------------------------------------------------

NAME
====

 panwfapi.py - command line program for accessing the WildFire API

SYNOPSIS
========
::

 panwfapi.py [options]
    --submit path|url     submit file or URL to WildFire for analysis
    --submit-link link    submit links to WildFire for analysis
    --change-request      request review of sample's verdict
    --report              get WildFire report
    --verdict             get WildFire sample verdict
    --sample              get WildFire sample file
    --pcap                get WildFire PCAP files
    --changed             get changed verdicts
    --hash hash           query MD5 or SHA256 hash
    --platform id         platform ID for sandbox environment
    --new-verdict verdict benign|malware|grayware
    --email address       notification e-mail address
    --comment comment     change request explanation
    --testfile            get sample malware test file
    --format format       report output format
    --date date           start date for changed verdicts
                          (YYYY-MM-DD or -days)
    --dst dst             save file to directory or path
    -K api_key            WildFire API key
    -h hostname           WildFire hostname
    -x                    print XML response to stdout
    -p                    print XML response in Python to stdout
    -j                    print XML response in JSON to stdout
    -D                    enable debug (multiple up to -DDD)
    -t tag                .panrc tagname
    -T seconds            urlopen() timeout
    --http                use http URL scheme (default https)
    --ssl opt             SSL verify option: default|noverify
    --cafile path         file containing CA certificates
    --capath path         directory of hashed certificate files
    --version             display version
    --help                display usage

DESCRIPTION
===========

 **panwfapi.py** is used to perform API requests on the WildFire
 cloud.  It uses the PanWFapi class from the **pan.wfapi** module to
 execute API requests.

 The options are:

 ``--submit`` *path|url*
  Submit a file or URL to WildFire for analysis.  Valid URL
  schemes for *url* are: **file**, **http**, **https** and **ftp**.
  A **file** *url* is the same as specifying *path*.

 ``--submit-link`` *link*
  Submit links to WildFire for analysis.  A link is a URL to a
  web page.

  *link* can be a single link or a path to a file containing multiple
  newline delimited links or **-** to specify that links be read from
  *stdin*.

  A maximum of 1,000 links can be submitted in a request.

 ``--change-request``
  Request  a manual review
  of a sample's verdict by the Threat Research Team.  Requires
  **--hash**, **--new-verdict**, **--email** and **--comment** arguments.

 ``--report``
  Get analysis report for a previously uploaded sample.  The
  sample can be specified by its MD5 or SHA256 hash (**--hash**).

 ``--verdict``
  Get the verdict(s) for previously uploaded samples.  The samples can
  be specified by their MD5 or SHA256 hash (**--hash**).  Up to 500
  hashes can be specified.

 ``--sample``
  Get a previously uploaded sample file.  The sample can be specified
  by its MD5 or SHA256 hash (**--hash**).

 ``--pcap``
  Get PCAP (packet capture) file of network activity for a previously
  uploaded sample.  The sample can be specified by its MD5 or SHA256
  hash (**--hash**).  The sandbox environment for the PCAP can optionally
  be specified using the platform ID (**--platform**).  If no platform
  is specified a PCAP from an environment that resulted in a *Malware*
  verdict is returned.

 ``--changed``
  Get the hashes of samples whose verdicts have changed within the
  last 30 days starting at the date specified with **--date**.

 ``--hash`` *hash*
  MD5 or SHA256 hash for a WildFire sample.  **--hash** can be
  specified multiple times for queries which allow multiple hashes.
  It can also be a path to a file containing the hashes or **'-'** to
  specify that hashes be read from *stdin*.

 ``--platform`` *id*
  Platform ID for sandbox environment.  Valid platform IDs are:

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

 ``--testfile``
  Get sample malware test file.  Each request returns a similar PE
  (Portable Executable) file named ``wildfire-test-pe-file.exe`` with
  a different hash and with verdict *Malware*.

  This currently requires an ``api_key`` even though it is not
  needed for the API request.

 ``--format`` *format*
  WildFire report output format string.  This can be **xml** or **pdf**.

  The default is **xml**.

 ``--date`` *date*
  Start date for **--changed** query.  The format for the
  *date* argument is *YYYY-MM-DD* or *-days* to specify a date
  relative to the current day.  *0* can be also be used to specify
  the current date.

 ``--dst`` *dst*
  Save file to the directory or path specified in *dst*.  By default
  files are saved with the filename specified in the HTTP response
  attachment.  Files saved are:

  - WildFire samples (**--sample**)

    sha256-hash-of-sample

  - PDF files (**--format=pdf**)

    sha256-hash-of-sample.pdf

  - PCAP files (**--pcap**)

    sha256-hash-of-sample.platform.unknown.pcap

  - Malware test file (**--testfile**)

    wildfire-test-pe-file.exe

 ``--new-verdict`` *verdict*
  The suggested verdict.  Can be specified as a string (*benign*,
  *malware* or *grayware*) or an integer.

 ``--email`` *address*
  Notification e-mail address.

 ``--comment`` *comment*
  Explanation for the change request.  Can be up to 2048 bytes.
  *comment* can be a string, a path to a file containing the comment or
  **'-'** to specify the comment be read from *stdin*.

 ``-K`` *api_key*
  Specify the **api_key** used in API requests.  This can also be
  specified in a .panrc file using the ``api_key`` *varname*.

 ``-h`` *hostname*
  Specify the **hostname** used in API requests.  This can also be
  specified in a .panrc file using the ``hostname`` *varname*.

  This is used to specify an alternate cloud (e.g.,
  ``beta.wildfire.paloaltonetworks.com``) or a WildFire appliance.

  The default is ``wildfire.paloaltonetworks.com``.

 ``-x``
  Print XML response to *stdout*.

 ``-p``
  Print XML response in Python to *stdout*.

 ``-j``
  Print XML response in JSON to *stdout*.

 ``-D``
  Enable debugging.  May be specified multiple times up to 3
  to increase debugging output.

 ``-t`` *tag*
  Specify tagname for .panrc.

 ``-T`` *seconds*
  Specify the ``timeout`` value for urlopen().

 ``--http``
  Use *http* URL scheme for API requests.  This can be used with the
  ``--testfile`` option to get a malware test file over HTTP.

 ``--ssl`` *opt*
  Specify the type of SSL server certificate verification to be
  performed.

  ``noverify``
   Disable SSL server certificate verification.

  ``default``
   If the **certifi** package is installed its Certificate Authority
   (CA) bundle is used for SSL server certificate verification,
   otherwise no changes are made to the default **ssl** module
   settings.

   This is the default.

  SSL server certificate verification is only performed in Python
  version 2.7.9 and 3.4.3 and greater.

  ``--ssl`` is ignored if ``--cafile`` or ``--capath`` are specified.

 ``--cafile`` *path*
  A file containing CA certificates to be used for SSL
  server certificate verification.

 ``--capath`` *path*
  A directory of hashed certificate files to be used for
  SSL server certificate verification.

 ``--version``
  Display version.

 ``--help``
  Display command options.

FILES
=====

 ``.panrc``
  .panrc file.

EXIT STATUS
===========

 **panwfapi.py** exits with 0 on success and 1 if an error occurs.

EXAMPLES
========

 Add WildFire API key to .panrc file.
 ::

  $ echo 'api_key%wildfire=d3b07384d113edec49eaa6238ad5ff00' >>.panrc

 Submit file to WildFire for analysis and print XML response.
 ::

  $ panwfapi.py -t wildfire -x --submit /tmp/sample.exe
  submit: 200 OK [response_body=True response_type=xml]

  <?xml version="1.0" encoding="UTF-8" ?><wildfire><upload-file-info><url></url><filename>sample.exe</filename><sha256>5a036546422c5235283254234fc5a67a36e3221a2324a3087db0081f08cc38e6</sha256><md5>ada8501b1e2abae90a83cc4cf20196d8</md5><size>466356</size><filetype>PE32 executable</filetype></upload-file-info></wildfire>

 Query WildFire sample report by MD5 hash and print XML response.
 ::

  $ panwfapi.py -t wildfire -x --report --hash 6de476723a12ad277a84f031868aace3 | head
  report: 200 OK [response_body=True response_type=xml]
  <?xml version="1.0" encoding="UTF-8" ?>
  <wildfire> 
  <version>2.0</version>
  <file_info>
      <sha256>74e330f15ac544a7e5201b9bed97d4425058a47bd10a6763932181f78b99116e</sha256>
      <md5>6de476723a12ad277a84f031868aace3</md5>
      <filetype>PE</filetype>
      <size>313856</size>
      <malware>yes</malware>
  </file_info>

 Get previously uploaded sample.
 ::

  $ panwfapi.py -t wildfire --sample --hash 6de476723a12ad277a84f031868aace3 --dst /tmp
  sample: 200 OK [attachment="74e330f15ac544a7e5201b9bed97d4425058a47bd10a6763932181f78b99116e"]
  saved /tmp/74e330f15ac544a7e5201b9bed97d4425058a47bd10a6763932181f78b99116e

 Get PCAP file of sample network activity.
 ::

  $ panwfapi.py -t wildfire --pcap --hash 11727b1d9ed03799a756d1bbb84e6319 --platform 4
  pcap: 200 OK [attachment="033e2d2ea39ffd9285d75edff1171c4b9f28fb407a314010f87f5d7ed98517d6.4.1.pcap"]
  saved 033e2d2ea39ffd9285d75edff1171c4b9f28fb407a314010f87f5d7ed98517d6.4.1.pcap

 Submit URL to WildFire for analysis and print XML response in JSON.
 ::

  $ panwfapi.py -t wildfire -j --submit \
  > https://www.paloaltonetworks.com/content/dam/paloaltonetworks-com/en_US/assets/pdf/datasheets/wildfire/wildfire.pdf
  submit: 200 OK [response_body=True response_type=xml]
  {
    "wildfire": {
      "upload-file-info": {
        "filename": null, 
        "filetype": "Adobe PDF document", 
        "md5": "b81a9805d672bc6d574bd76ffd09ad54", 
        "sha256": "716bc87686b4242c4e446fdb4599cf112fdd6fd85600a30a1856a67cc61b9c25", 
        "size": "1236454", 
        "url": "https://www.paloaltonetworks.com/content/dam/paloaltonetworks-com/en_US/assets/pdf/datasheets/wildfire/wildfire.pdf"
      }
    }
  }

 Get malware test file over HTTP.
 ::

  $ panwfapi.py --testfile --http -K 0
  testfile: 200 OK [attachment="wildfire-test-pe-file.exe"]
  saved wildfire-test-pe-file.exe

SEE ALSO
========

 pan.wfapi

 WildFire Administrator's Guide
  https://www.paloaltonetworks.com/documentation/71/wildfire/wf_admin

 WildFire API
  https://www.paloaltonetworks.com/documentation/71/wildfire/wf_api

AUTHORS
=======

 Kevin Steves <kevin.steves@pobox.com>

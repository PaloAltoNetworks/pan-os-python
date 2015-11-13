Release History
===============

0.7.0 (2015-05-25)
------------------

- pan.xapi: Allow xml_result() to match result in report output.

- pan.config: Fix typo causing Panorama 6.1 xpaths to not be used.

- panrc.rst:  Add section on .panrc file permissions.

- panxapi.py: Use lstrip('\r\n').rstrip() on response XML and message
  before printing.

- Fix a bug where we only processed the first node for -pjr when there
  was more than one node.

- Move .panrc documentation to a separate document.

- Documentation: /publicapi/get/verdicts allows up to 500 hashes.

0.6.0 (2015-03-20)
------------------

- Don't name the internal log function log as this steps on the log()
  method in pan.xapi; change in all modules for consistency.

- panwfapi.rst: Typo in WildFire .panrc example.

- pan.xapi: type=report&reporttype=predefined response does not return
  charset in content-type. Fix to be more liberal in what we accept.

- pan.wfapi.rst: Fix wrong variable in Debugging and Logging example.

- pan.xapi: Document element_root data attribute.

- panxapi.py: Missed a use of pan.xapi.xml_python() when it was
  removed.

- panxapi.py: Fix --ls (formatted PCAP listing), which has been broken
  since 5.0 due to XML response format changes.

- pan.xapi: Workaround bug in 5.0 and 6.0: export PCAP response
  incorrectly uses content-type text/plain instead of
  application/octet-stream.

- panxapi.py, pan.xapi: Add support for the extended packet capture
  feature added in PAN-OS 6.0 which is used for threat PCAPs.

- panxapi.py: Files besides PCAP can be exported that are returned as
  attachments (e.g., device-state), so rename save_pcap() to
  save_attachment().

- pan.xapi: Add text_document data attribute which contains the
  message body from the previous API request when the response
  content-type is text/plain.

- panxapi.py: Add --text option to print text to stdout.

- panxapi.py, pan.xapi: Allow --ad-hoc to be used to modify (replace)
  and augment (add to) the standard parameters in the request.

- Add reference to PAN-OS and WildFire documentation to SEE ALSO
  sections of the documentation.

- panxapi.py: Can export more than PCAP files; update documentation
  and usage.

- Add Python 3.4 to supported list.

- pan.xapi: When an XML response does not contain a status attribute
  (e.g., export configuration), set to 'success'.

- pan.xapi: If ElementTree has text use for start of xml_result()
  string.

- pan.xapi.op(): Handle multiple double quoted arguments for
  cmd_xml=True.

- panxapi.py: When -r is specified without any of -xjp, -x is now
  implied.

- pan.config: Add PAN-OS 6.1 for set CLI.

- pan.wfapi: Don't override self._msg in __set_response() if already
  set.  Handle case on non 2XX HTTP code and no content-type in
  response.

- panxapi.py: Print warning if extra arguments after xpath.

- pan.xapi: Address changes to Python 2.7.9 and 3.4.3 which now
  perform SSL server certificate verification by default (see PEP
  476).  Maintains past behaviour of no verification by default.

  NOTE: this removes the cafile and capath arguments from PanXapi()
  and adds ssl_context.

- pan.wfapi, panwfapi.py: Add support for:
    get sample verdict               /publicapi/get/verdict
    get sample verdicts              /publicapi/get/verdicts
    get verdicts changed             /publicapi/get/verdicts/changed

- pan.wfapi.rst: Add table with HTTP status codes that can be
  returned.

- pan.wfapi: Add constants for verdict integer values.

- pan.wfapi: Remove HTTP status code reason phrases that are returned
  by default now.

- Set SIGPIPE to SIG_DFL in panxapi.py for consistency with panconf.py
  and panwfapi.py.  This is needed on some systems when piping to
  programs like head so we don't see BrokenPipeError.  Also handle
  AttributeError for Windows which doesn't have SIGPIPE.

0.5.0 (2014-10-22)
------------------

- Change debug messages in modules from print to stderr to log using
  the logging module.  See the section 'Debugging and Logging' in
  pan.wfapi.rst and pan.xapi.rst for an example of configuring the
  logging module to enable debug output.

  IMPORTANT NOTE: the debug argument has been removed from the
  constructors, so programs using them must be modified.

- Add platform ID for Windows 7 64-bit sandbox to WildFire
  documentaton.

- Fix bug in panconf.py: positional arguments not initialized to none
  in conf_set()

- Remove undocumented xml_python() method from pan.xapi and pan.wfapi.
  Use pan.config if you need this.

- Add 'serial' varname to .panrc.  Allows you to have tags which
  reference a Panorama managed device via redirection.  Suggested by
  Jonathan Kaplan.

- Add example to panxapi.rst: Print operational command variable using
  shell pipeline.

- Document --sync, --interval, --timeout for panxapi.py

- Add --validate to panxapy.py which runs commit with a cmd argument
  of <commit><validate></validate></commit> to validate the
  configuration.  This is a new feature in PAN-OS 6.0.

- Fix keygen() to return api_key as documented.

- Add support for type=config&action=override.  From btorres-gil

0.4.0 (2014-09-14)
------------------

- WildFire API support.

0.3.0 (2014-06-21)
------------------

- PEP8 cleanup.

- fix unintended _valid_part to valid_part variable name change in
  pan.config.

- handle type=user-id register and unregister response messages.
  suggested and initial diff by btorresgil.

- fix serial number (target API argument) not set in type=commit;
  from btorresgil.

- fix debug print to stdout vs. stderr in pan.xapi.

- changes for PyPI upload in setup.py.

0.2.0 (2014-03-22)
------------------

- various PEP8 cleanup.

- use HISTORY.rst for changes/release history vs. CHANGES.txt.

- add panconf.py, a command line program for managing PAN-OS XML
  configurations.

- add Panorama 5.1 (same as 5.0) for set CLI.

- add PAN-OS 6.0 XPaths for set CLI.

- pan.xapi: use pan.config for XML to Python conversion and remove
  duplicated code.

- I am developing with Python 3.3 by default now so add as supported.

- Rewrite XML response message parser to use xml.etree.ElementTree
  path/xpath to match each known format.  This will make it easier to
  support additional message formats.

  Multi-line messages (multiple line elements) are now newline
  delimited.

- operational command 'show jobs id nn' can have response with path
  './result/job/details/line'; if so set status_detail to text (can be
  multi-line).

- pan.xapi: if an XML response message is an empty string set it to
  None vs. ''.

- panxapi: print status line the same for exception/non-exception. We
  now quote message in non-exception case.

- handle ./newjob/newmsg within ./result/job/details/line of 'show
  jobs xxx' response.  the response message parser makes this easy
  now, but I'm still unsure if we really want to try to handle these
  things because the response formats are not documented.

- panxapi: add path value to --capath and --cafile argument usage.

- panxapi: don't print exception message if it's a null string.

- add --timeout and --interval options for use with --log to panxapi.

- rename pan.xapi log() sleep argument to interval and rework query
  interval processing slightly.

- add synchronous commit capability.

  TODO: more complete show job message parsing, especially for commit-all.

0.1.0 (2013-09-21)
------------------

- missing newline in debug.

- handle response with <msg><line><line>xxx</line></line>...

- in print_status() give priority to exception message over
  status_detail.

- use both code and reason from URLError exception for error message.

- Add support for log retrieval (type=log) to pan.xapi (see the log()
  method) and panxapi.py (see the --log option).

- reStructuredText cleanup.

- add example to retrieve report using the --ad-hoc option.

- Change name of distribution from PAN-python to pan-python.

- Add __version__ attribute and --version option.

- Add GitHub references to README and setup.py.

(2013-03-06)
------------

- initial release (on DevCenter)

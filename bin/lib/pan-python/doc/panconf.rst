..
 Copyright (c) 2012, 2013 Kevin Steves <kevin.steves@pobox.com>

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
panconf.py
==========

-----------------------------------------------------------
command line program for managing PAN-OS XML configurations
-----------------------------------------------------------

NAME
====

 panconf.py - command line program for managing PAN-OS XML configurations

SYNOPSIS
========
::

 panconf.py [options] [pseudo-xpath]
    --config path         path to XML config or '-' for stdin
    --xml                 print XML
    --py                  print XML in Python
    --json                print XML in JSON
    --flat                print XML flatly
    --set                 print XML as set CLI
    --mlist               print set CLI members as a list
    --compact             print compactly
    --debug level         enable debug level up to 3
    --version             display version
    --help                display usage

DESCRIPTION
===========

 **panconf.py** is used to manage PAN-OS XML configurations.  It can be
 used to query nodes in an XML configuration by XPath (currently a
 pseudo-xpath, see below) and convert the configuration to Python, JSON
 and other formats for reporting and further manipulation.

 It uses the **pan.config** module which is currently a private
 interface (it is subject to change and not documented).

 The options are:

 ``--config`` *path*
  Specify path to PAN-OS XML configuration or '-' to read from
  **stdin**.  This can be a complete (e.g., ``running-config.xml``)
  or partial (``rulebase security rules``) XML configuration.

 ``--xml``
  Print configuration in XML.

 ``--py``
  Print configuration as a Python object.

 ``--json``
  Print configuration as a JSON object.

 ``--flat``
  Print configuration flatly in an XPath-like format.  This is useful
  for search with document node context and to identify a node's XPath.

  When ``pseudo-xpath`` is not specified a default set of XPath
  expressions is used to match nodes in the XML configuration.

 ``--set``
  Print configuration in set CLI format.  This is intended to be the
  same format as seen when using ``set cli config-output-format set``.

  When ``pseudo-xpath`` is not specified a default set of XPath
  expressions is used to match nodes in the XML configuration.

  When ``pseudo-xpath`` is specified, it should specify a top-level
  node (what ``# set ?`` allows) or results are unspecified.

 ``--mlist``
  Print set CLI members as a list by enclosing multiple *member*
  element text in square brackets.  By default each member terminates
  a single set statement.  Member list format is used by default when
  a PAN-OS version of 5.0 or greater is obtained from the config file
  via the *config* element *version* attribute.

  Member list format:
  ::

   set network virtual-router stx_1234 interface [ ethernet1/5.100 ethernet1/6.100 ]

  Default format:
  ::

   set network virtual-router stx_1234 interface ethernet1/5.100
   set network virtual-router stx_1234 interface ethernet1/6.100

 ``--compact``
  Print output compactly.  This currently applies to JSON
  output only, and can be used to eliminate spaces in the JSON
  object.

 ``--debug`` *level*
  Enable debugging in **panconf.py** and the **pan.config** module.
  *level* is an integer in the range 0-3; 0 specifies no
  debugging and 3 specifies maximum debugging.

 ``--version``
  Display version.

 ``--help``
  Display **panconf.py** command options.

 ``pseudo-xpath``
  ``pseudo-xpath`` is currently the XPath as supported by the
  **xml.etree.ElementTree** module, which provides limited support for
  XPath expressions for locating elements in a tree.  For more information
  see the examples below and the documentation at:
  http://docs.python.org/dev/library/xml.etree.elementtree.html#elementtree-xpath.

FILES
=====

 None.

EXIT STATUS
===========

 **panconf.py** exits with 0 on success and 1 if an error occurs.

EXAMPLES
========

 ``config.xml`` in the examples below is a ``running-config.xml``
 exported from a PAN-OS device.

 Print XML node for ``adminr`` user.
 ::

  $ panconf.py --config config.xml --xml "./mgt-config/users/entry[@name='adminr']"
  <entry name="adminr">
        <permissions>
          <role-based>
            <superreader>yes</superreader>
          </role-based>
        </permissions>
        <phash>$1$panetwrx$xQpDOQuAP3v8bFzJz.l7j0</phash>
      </entry>
 
 Print JSON object for ``adminr`` user.
 ::

  $ panconf.py --config config.xml --json "./mgt-config/users/entry[@name='adminr']"
  {
    "entry": {
      "name": "adminr", 
      "permissions": {
        "role-based": {
          "superreader": true
        }
      }, 
      "phash": "$1$panetwrx$xQpDOQuAP3v8bFzJz.l7j0"
    }
  }

 Print flatly for admin users.
 ::

  $ panconf.py --config config.xml --flat "./mgt-config"
  ./mgt-config
  ./mgt-config/users
  ./mgt-config/users/entry
  ./mgt-config/users/entry[@name='admin']
  ./mgt-config/users/entry[@name='admin']/phash="$1$dgfkmfpe$/OGLAdsxd/zzjq51vLoeR0"
  ./mgt-config/users/entry[@name='admin']/permissions
  ./mgt-config/users/entry[@name='admin']/permissions/role-based
  ./mgt-config/users/entry[@name='admin']/permissions/role-based/superuser="yes"
  ./mgt-config/users/entry
  ./mgt-config/users/entry[@name='adminr']
  ./mgt-config/users/entry[@name='adminr']/permissions
  ./mgt-config/users/entry[@name='adminr']/permissions/role-based
  ./mgt-config/users/entry[@name='adminr']/permissions/role-based/superreader="yes"
  ./mgt-config/users/entry[@name='adminr']/phash="$1$panetwrx$xQpDOQuAP3v8bFzJz.l7j0"

 Print set CLI for admin users.
 ::

  $ panconf.py --config config.xml --set "./mgt-config"
  set mgt-config users admin phash $1$dgfkmfpe$/OGLAdsxd/zzjq51vLoeR0
  set mgt-config users admin permissions role-based superuser yes
  set mgt-config users adminr permissions role-based superreader yes
  set mgt-config users adminr phash $1$panetwrx$xQpDOQuAP3v8bFzJz.l7j0

SEE ALSO
========

 panxapi.py

AUTHORS
=======

 Kevin Steves <kevin.steves@pobox.com>

MISCELLANY
==========

 Configurations with ``multi-vsys: on`` are identified when multiple
 nodes match the xpath
 ``"/config/devices/entry[@name='localhost.localdomain']/vsys/entry"``,
 which is not perfect.

 Configurations for Panorama are identified by matching the xpath
 ``"/config/panorama"`` or
 ``"/config/devices/entry[@name='localhost.localdomain']/device-group"``,
 which is also not perfect.

 ``--debug 1`` can be used to display configuration version and types
 identified:
 ::

  $ panconf.py --config panorama.xml --debug 1
  config_root: <Element 'config' at 0x207e1af90>
  config_version: 4.1.0
  config_panorama: True
  config_multi_vsys: False

 When performing a top level configuration mode ``# show`` command
 with no arguments a default set of XPath expressions is used by
 PAN-OS to match the configuration to be displayed.  These paths are
 stored internally in the **pan.config** module for different PAN-OS
 versions (4.1, 5.0, 5.1 (Panorama), 6.0 and 6.1) in order to duplicate
 the order and set of configuration nodes displayed.

 PAN-OS may place a trailing space on some set statements;
 **panconf.py** never ends a statement with a space.

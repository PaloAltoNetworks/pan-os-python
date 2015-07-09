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

======
.panrc
======

-------------------------
Format of the .panrc file
-------------------------

NAME
====

 .panrc - Format of the .panrc file

DESCRIPTION
===========

 .panrc files can contain hostname, port, serial number, username,
 password and API key variables for the PAN-OS XML API; and hostname
 and API key variables for the WildFire API.  .panrc is used by
 the PanXapi and PanWFapi classes.

 A .panrc file consists of lines with the format:
 ::

  varname[%tagname]=value

 Empty lines and lines starting with pound (**#**) are ignored.  For
 example:
 ::

  api_username=api
  api_password=admin
  hostname=192.168.1.1

  # admin API key
  api_key=C2M1P2h1tDEz8zF3SwhF2dWC1gzzhnE1qU39EmHtGZM=
  hostname=192.168.1.1

 *tagname* is optional and can be appended to *varname* with percent
 (**%**).  This form is used to allow a single .panrc file to contain
 variables for multiple systems.  The PanXapi and PanWFapi
 constructors have an optional **tag** argument to specify that only a
 *varname* with the given *tagname* be used.  For example:
 ::

  # no tag
  hostname=172.29.9.122
  api_username=admin
  api_password=goodpw

  # fw-test
  hostname%fw-test=172.29.9.123
  api_username%fw-test=admin
  api_password%fw-test=admin

  # eng-fw
  hostname%eng-fw=172.29.9.124
  api_key%eng-fw=C2M1P2h1tDEz8zF3SwhF2dWC1gzzhnE1qU39EmHtGZM=

 *tagname* must match the regular expression **/^[\w-]+$/** (1 or more
 alphanumeric characters plus "-" and "_").

Recognized varname Values
~~~~~~~~~~~~~~~~~~~~~~~~~

 The following *varname* values are recognized:

 ================   ======  ========
 *varname*          PAN-OS  WildFire
 ================   ======  ========
 **hostname**       X       X
 **port**           X
 **serial**         X
 **api_username**   X
 **api_password**   X
 **api_key**        X       X
 ================   ======  ========

.panrc File Permissions
~~~~~~~~~~~~~~~~~~~~~~~

 Because .panrc contains authentication material it should have strict
 file permissions (read/write for the owner and not accessable by
 group or other).  For example:
 ::

  $ chmod 600 ~/.panrc

.panrc Locations and Variable Merging
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 A .panrc file can reside in the current working directory
 ($PWD/.panrc) and in the user's home directory ($HOME/.panrc).
 .panrc variables can also be specified in the PanXapi and PanWFapi
 constructors.  When a variable exists from multiple sources, the
 priority for merging variables is: __init__(), $PWD/.panrc,
 $HOME/.panrc.

SEE ALSO
========

 panxapi.py, pan.xapi, panwfapi.py, pan.wfapi

AUTHORS
=======

 Kevin Steves <kevin.steves@pobox.com>

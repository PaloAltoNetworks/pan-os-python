.. _commands:

Searchbar Commands
==================

There are several custom commands in the app that can communicate to the
Palo Alto Networks next-generation firewall to make changes.  These
commands take the events from the search as input, and add context the
firewall so it can better enforce its security policy.

.. _panuserupdate:

panuserupdate
-------------

The ``panuserupdate`` command synchronizes user login events with
Palo Alto Networks User-ID. More information: :ref:`userid`

Added in App version 5.0. For previous versions, refer to the
:ref:`panupdate` command.

**Syntax**::

    panuserupdate device=<hostname>|panorama=<hostname>
    [serial=<serial-of-device-in-panorama>] [vsys=<vsys#>]
    [action=<login|logout>] [ip_field=<field-containing-IPs>]
    user_field=<field-containing-usernames>

===========  ==========  ========================================================
Parameter    Default     Usage
===========  ==========  ========================================================
device                   IP or hostname of firewall
panorama                 IP or hostname of Panorama
serial                   Serial of firewall (required if using panorama parameter
vsys         vsys1       VSYS ID (eg. vsys2)
action       login       Tell the firewall user logged in or logged out
ip_field     src_ip      Log field containing IP address
user_field   user        Log field containing the username
===========  ==========  ========================================================

Example 1:
  When a radius authentication log is received by Splunk, tell the firewall
  that the user logged. This command would cause the firewall with management
  IP 192.168.4.211 to receive the user-to-IP mapping::

    index=main sourcetype=radius | panuserupdate device="192.168.4.211"

Example 2:
  The previous example assumes the user and ip are in fields named `user` and
  `src_ip`. If this is not the case, rename the fields or tell the command what
  fields to use.

  Rename the fields::

    index=main sourcetype=radius | rename addr AS ip | rename authuser AS user | panuserupdate panorama="10.5.5.8" serial="0001A13800105"

  Call out the fields::

    index=main sourcetype=radius | panuserupdate panorama="10.5.5.8" serial="0001A13800105" vsys="vsys4" ip_field="addr" user_field="authuser"

  The first search renames the fields before passing them to the panuserupdate
  command. It also uses Panorama to connect to a firewall with the serial
  number 0001A13800105. This is the User-ID firewall connected to Panorama.

  The second search tells the panuserupdate command which fields contain the
  ip and user. It also passes this information via Panorama to a firewall, but
  this example specifies the update is for vsys4 on the firewall.

Example 3:
  Notifies the firewall of a radius user logout via Panorama. The default
  fields src_ip and user are used to gather the IP and Username::

    sourcetype=radius logout | panuserupdate panorama="10.4.4.4" serial="0004001028200" action="logout"

See also:
  * :ref:`userid`
  * :ref:`syncuserid`


.. _pantag:

pantag
------

The ``pantag`` command shares context with the firewall by tagging IP
addresses found in Splunk into `Dynamic Address Groups`_.

Command added in App version 4.1. New parameters added in App version 5.0.

**Syntax**::

    pantag device=<hostname>|panorama=<hostname>
    [serial=<serial-of-device-in-panorama>] [vsys=<vsys#>]
    [action=<add|remove>] [ip_field=<field-containing-IPs>]
    tag=<tag>|tag_field=<field-containing-tags>

===========  ==========  ========  ============================================================
Parameter    Default     Added in  Usage
===========  ==========  ========  ============================================================
device                   4.1       IP or hostname of firewall
panorama                 5.0       IP or hostname of Panorama
serial                   5.0       Serial of firewall (required if using panorama parameter
vsys         vsys1       5.0       VSYS ID (eg. vsys2)
action       add         4.1       Add or remove the tag
field        src_ip      4.1       Same as ip_field parameter (deprecated in 5.0, use ip_field)
ip_field     src_ip      5.0       Log field containing IP address to tag
tag                      4.1       Tag for the IP, referenced in the Dynamic Address Group
tag_field                5.0       Log field containing the tag for IP address in the same log
===========  ==========  ========  ============================================================

.. note:: Prior to App version 5.0, the ``ip_field`` parameter is just ``field``

Example 1:
  Any IP on the network that generated a spyware
  (command-and-control traffic) alert is tagged as an infected host on the
  firewall at 10.1.1.1::

    `pan_threat` log_subtype="spyware" | stats dc(src_ip) by src_ip | pantag device="10.1.1.1" action="add" tag="infected-host"

  In this example, any device that is sending command and control traffic will
  be tagged with `infected-host`.  Your security policy could limit the reach
  of IP addresses with this tag until the incident is remediated. Or it could
  present a captive portal to the user indicating the problem and steps to
  contact IT.

Example 2:
  Tag any IP that is generating linux syslogs as a linux host on the
  firewall. Tag is applied to the firewall with serial 0005001028200 via
  the Panorama at 10.4.4.4::

    sourcetype="linux_messages_syslog" | pantag panorama="10.4.4.4" serial="0005001028200" ip_field="host" tag="linux-host"

Example 3:
  Tag every IP address on the firewall with their Splunk classification (from
  the IP classification lookup table)::

    `pan_traffic` | pantag device="10.1.1.1" ip_field="src_ip" tag_field="src_class"

Example 4:
  If anyone tries to connect to www.splunk.com, remove the tag
  'suspicious-ip-address' from the IP of the website. Tag is removed on vsys3
  of firewall with hostname main-fw.company.com::

    `pan_url` dest_hostname="www.splunk.com" | pantag device="main-fw.company.com" vsys="vsys3" action="remove" ip_field="dest_ip" tag="suspicious-ip-addresses"


.. note:: The IP is tagged on the firewall immediately, however, it can take
   up to 60 seconds for the tagged IP addresses to show up in the corresponding
   Dynamic Address Group in the security policy.  This delay is intentional to
   prevent accidental DoS scenarios.

.. _pancontentpack:

pancontentpack
--------------

Update the app and threat lookup tables from the latest firewall content pack.

Added in App version 5.0

For usage instructions, see :ref:`contentpack`.

Legacy commands
---------------

.. _panblock:

panblock
~~~~~~~~

Deprecated in App version 4.1. Use :ref:`pantag` instead.

Removed in App version 5.2.

Modify the configuration of the firewall address groups to include IP
addresses from events in Splunk.  This is similar to tagging IP addresses
and works the same way, but is much less dynamic than tagging because it is
modifying the firewall configuration and requires a configuration commit. ::

    `index=pan_logs sourcetype=pan_threat log_subtype=vulnerability | stats dc (src_ip) by (src_ip) | panblock device="1.0.0.1" action="add" group="attackers"`


.. _panupdate:

panupdate
~~~~~~~~~

Deprecated in App version 5.0. Use :ref:`panuserupdate` instead.

Removed in App version 5.2.

The Palo Alto Networks firewall will inform Splunk of the user generating
each connection via the syslogs it sends to Splunk.  This assumes that the
firewall is getting the login information from AD or some other
authentication system, to know what user is logged into the device
generating the traffic.

If authentication logs are being indexed by Splunk, then Splunk can share
knowledge of where users are logged in to the firewall.  For example, if
Splunk is receiving a radius authentication log where 'user' is the field
containing the user who authenticated, and 'ip' is the field containing the
IP address where the user logged in, then you can map the user to the ip on
the firewall using the ``panupdate`` command like so::

    `index=main sourcetype=radius | rename user AS addruser | rename ip AS addrip | panupdate device="192.168.4.211"`

This would cause the firewall with management IP 192.168.4.211 to receive
the user-to-IP mapping.  The mapping times out after 30 minutes.

.. _Dynamic Address Groups: https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os/policy/use-dynamic-address-groups-in-policy.html
.. _WildFire: https://www.paloaltonetworks.com/products/technologies/wildfire.html

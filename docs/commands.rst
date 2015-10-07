Searchbar Commands
==================

There are several custom commands in the app that can communicate to the
Palo Alto Networks next-generation firewall to make changes.  These
commands take the events from the search as input, and add context the
firewall so it can better enforce its security policy.

.. _panuserupdate:

Sync user login events
----------------------

**Command: `panuserupdate`**

Added in App version 5.0.  If using a previous version, refer to the
:ref:`panupdate` command.

The Palo Alto Networks firewall will inform Splunk of the user generating
each connection or event via the syslogs it sends to Splunk.  This assumes
that the firewall is getting the login information from AD or some other
authentication system, to know what user is logged into the device
generating the traffic.

If authentication logs are being indexed by Splunk, then Splunk can synchronize
knowledge of where users are logged in with the firewall. For example, if
Splunk is receiving a radius authentication log where 'user' is the field
containing the user who authenticated, and 'ip' is the field containing the
IP address where the user logged in, then you can map the user to the ip on
the firewall.

In this situation, it is often preferred to use Splunk syslog forwarding to
a User-ID agent or firewall because it is more efficient.  But there are
some cases where the user and IP are not in the same log.  For example, if
an authentication log contains the user and MAC address, and the DHCP log
contains the MAC address and IP.  A correlation must be done on the MAC
address to know which IP the user logged in from. In this situation, the
panuserupdate command is the preferred solution.

**Example 1**::

    index=main sourcetype=radius | panuserupdate device="192.168.4.211"

This would cause the firewall with management IP 192.168.4.211 to receive
the user-to-IP mapping.

**Example 2**:

The previous example assumes the user and ip are in fields named `user` and
`ip`. If this is not the case, rename the fields or tell the command what
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

Share context
-------------

**Command: `pantag`**

Added in App version 4.1

Tagging an IP address means setting metadata or context on the firewall for
that IP, which causes it to be added to corresponding Dynamic Address
Groups in the firewall security policy.  For example, you could create a
rule in the security policy that blocks and IP address with the tag
'bad-actor'. Initially, no IP addresses would be blocked, but you can
create a search in Splunk for criteria that represents a problem device,
and trigger a tagging of that IP address with the 'bad-actor' tag.  The
firewall would add the IP address to the Dynamic Address Group in the
policy automatically and begin blocking the IP.

Blocking a bad actor is just the beginning, and you aren't limited to allow
or deny as your options.  You could tag an IP address for additional
scrutiny by the Threat Prevention engine, or as a known trusted server to
be given additional permissions.  The behaviors are defined by your
security policy, and how you treat IP addresses with specific tags.

You can tag an IP address using the `pantag` command like so::

    `index=pan_logs sourcetype=pan_wildfire category=malicious | pantag device="1.0.0.1" action="add" field="dst_ip" tag="malware-infected"`

In this example, any device that downloads a malicious file as determined
by WildFire_ will be tagged with `malware-downloaded`.  Your security policy
could limit the reach of IP addresses with this tag until the incident is
remediated.

Note:  IP is tagged on the firewall immediately, however, it can take up to
60 seconds for the tagged IP addresses to show up in the corresponding
Dynamic Address Group in the security policy.  This delay is intentional to
prevent accidental DoS scenarios.

This webinar explains the concept of automated remediation and demonstrates
a case study of a real customer using this technique with Splunk and Palo
Alto Networks today:

Webinar: `Defeat APT with Automated Remediation in Splunk`_

This video from Ignite 2015 explains Dynamic Address Groups in more detail
with several use cases including asset management:

Video: `Applying Order to Computing Chaos`_

Legacy commands
---------------

panblock
~~~~~~~~~

**Command: `panblock`**

Deprecated in App version 4.1. Use **pantag** instead.

Modify the configuration of the firewall address groups to include IP
addresses from events in Splunk.  This is similar to tagging IP addresses
and works the same way, but is much less dynamic than tagging because it is
modifying the firewall configuration and requires a configuration commit. ::

    `index=pan_logs sourcetype=pan_threat log_subtype=vulnerability | stats dc (src_ip) by (src_ip) | panblock device="1.0.0.1" action="add" group="attackers"`


.. _panupdate:

panupdate
~~~~~~~~~
**Command: `panupdate`**

Deprecated in App version 5.0. Use **panuserupdate** instead.

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
the firewall using the `panupdate` command like so::

    `index=main sourcetype=radius | rename user AS addruser | rename ip AS addrip | panupdate device="192.168.4.211"`

This would cause the firewall with management IP 192.168.4.211 to receive
the user-to-IP mapping.  The mapping times out after 30 minutes.

.. _WildFire: https://www.paloaltonetworks.com/products/technologies/wildfire.html
.. _Defeat APT with Automated Remediation in Splunk:
    https://www.paloaltonetworks.com/resources/webcasts/defeat-apts-improve-security-posture-real-time.html
.. _Applying Order to Computing Chaos: https://www.youtube.com/watch?v=Kv0SR9KLDj4

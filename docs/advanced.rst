.. _advancedfeatures:

Advanced Features
=================

.. _syncuserid:

Sync user login events with User-ID
-----------------------------------

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

See also:
  * :ref:`userid`
  * Searchbar Command: :ref:`panuserupdate`

.. _dag:

Share context with Dynamic Address Groups
-----------------------------------------

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

**See also:**

  Command reference: :ref:`pantag`

Webinar that explains the concept of automated remediation and demonstrates
a case study of a real customer using this technique with Splunk and Palo
Alto Networks today:

  Webinar: `Defeat APT with Automated Remediation in Splunk`_

Video from a session at Ignite 2015 explains Dynamic Address Groups in more
detail with several use cases including asset management:

  Video: `Applying Order to Computing Chaos`_

.. _Applying Order to Computing Chaos:
    https://www.youtube.com/watch?v=Kv0SR9KLDj4

IP Classification
-----------------

Classify IP addresses in Splunk by any criteria relevant to your environment.
IP ranges can be designated as `DMZ`, `datacenter`, `VMware`, `serverfarm`,
`webtier`, or any other relevant keyword to help distinguish and classify a
group of IP addresses during a search.

Classifications will show up in the ``src_class`` and ``dest_class`` [#f1]_ fields.

Classifications are set in the lookup file ``ip_classifictions.csv`` [#f2]_.
Add subnets and their classification to the ``ip_classifications.csv`` file, one
per line.

For example::

    cidr,classification
    10.0.0.0/8,private
    172.16.0.0/12,private
    192.168.0.0/16,private
    10.5.5.0/24,dmz
    10.240.0.0/16,datacenter1
    192.168.5.0/24,partner-mpls

More specific entries take precedence.

Now look for the classifications in the ``src_class`` and ``dest_class``
fields during a search that includes these IP address ranges.

Un/Sanctioned SaaS Detection
----------------------------

*Added in App version 5.0*

Classify SaaS applications as sanctioned or unsanctioned for your
organization. This designation is used in searches using the Splunk searchbar
and to separate information in the App's SaaS Dashboard.

SaaS applications are designated as sanctioned in the lookup file
``sanctioned_saas.csv`` in the Splunk_TA_paloalto Add-on.

Add each sanctioned SaaS app in the lookup file, one per line.  For example::

    app,sanctioned_saas
    paloalto-wildfire-cloud,yes
    boxnet,yes
    dropbox,yes
    gmail-enterprise,yes
    skype,yes
    facebook-base,yes
    gmail-chat,yes

Sanctioned designation is found in the field ``app:is_sanctioned_saas``.

For a list of all SaaS applications, visit `Applipedia`_ and under the
`Characteristics` header, click `SaaS`.

.. _Applipedia: https://applipedia.paloaltonetworks.com/

.. _wildfire:

WildFire
--------

.. todo:: Wildfire directions

.. _remediation:

Automated Remediation
---------------------

Use the :ref:`pantag` command to share context from Splunk to the firewall
for automated remediation.

This webinar explains the concept of automated remediation and demonstrates
a case study of a real customer using this technique with Splunk and Palo
Alto Networks today:

Webinar: `Defeat APT with Automated Remediation in Splunk`_

.. _Defeat APT with Automated Remediation in Splunk:
    https://www.paloaltonetworks.com/resources/webcasts/defeat-apts-improve-security-posture-real-time.html

.. _contentpack:

Update metadata from content packs
----------------------------------

*Added in App version 5.0*

The Palo Alto Networks Add-on (TA) comes with two lookup files with metadata
about applications and threat signatures called ``app_list.csv`` and
``threat_list.csv``, respectively. These lookup tables are responsible for
populating the app:**** and threat:*** fields used in the dashboards and
displayed during a search.

The lookup table files are updated with each TA release, but can get out of
date between releases. To keep the files up to date, they can be updated
dynamically from the content pack metadata in your firewall or Panorama.
This is done by creating a saved search inside the TA to periodically pull
the metadata from the firewall or Panorama and update the lookup tables.

Create the following saved searches in the TA, by creating the file:
``$SPLUNK_HOME/etc/apps/Splunk_TA_paloalto/local/savedsearches.conf``
::

    [Palo Alto Networks - Retrieve ContentPack Apps]
    cron_schedule = 5 0 * * 6
    dispatch.earliest_time = -1m@m
    displayview = flashtimeline
    enableSched = 1
    realtime_schedule = 0
    request.ui_dispatch_view = flashtimeline
    search = | pancontentpack <IP-or-hostname> apps | outputlookup createinapp=true app_lookup
    disabled = 0

    [Palo Alto Networks - Retrieve ContentPack Threats]
    cron_schedule = 10 0 * * 6
    dispatch.earliest_time = -1m@m
    displayview = flashtimeline
    enableSched = 1
    realtime_schedule = 0
    request.ui_dispatch_view = flashtimeline
    search = | pancontentpack <IP-or-hostname> threats | outputlookup createinapp=true threat_lookup
    disabled = 0

Set ``<IP-or-hostname>`` to the IP or hostname of your Firewall or Panorama.
Ensure you set the credentials for this device in the
:ref:`App configuration <initialsetup>`. This example updates the lookup
tables every Saturday at 12:05 AM for apps and 12:10 AM for threats.
Change the cron_schedule to your desired update schedule.

.. note:: The Palo Alto Networks App version 5.0 must be installed for the
   lookup table update to work. But the saved searches must be created in
   the TA, not the App.

.. rubric:: Footnotes

.. [#f1] The field is called ``dst_class`` in App versions before 5.0
.. [#f2] Starting in App version 5.0, the ``ip_classifications.csv`` file is located in the Splunk_TA_paloalto Add-on.  Before 5.0, it is in the SplunkforPaloAltoNetworks App.

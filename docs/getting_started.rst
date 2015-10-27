Getting Started
===============

Step 1: Create the Splunk input
-------------------------------

Syslogs can be sent to Splunk using the following protocols:

* Next generation Firewall: UDP, TCP, or SSL
* Traps Endpoint Security: UDP

Configure the input using the direction for your version of the App:

App Version 5.x
~~~~~~~~~~~~~~~

todo: Install directions

App Version 3.x and 4.x
~~~~~~~~~~~~~~~~~~~~~~~

* Edit `$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/local/inputs.conf`

Note: The ``local`` directory does not exist after installation, so you may
need to create it.

Add the following lines to the ``inputs.conf`` file.  This examples uses the
default syslog port 514/udp.  Change the port as needed. ::

    [udp://514]
    index = pan_logs
    sourcetype = pan_log
    no_appending_timestamp = true
    connection_host = ip

The ``index``, ``sourcetype``, and ``no_appending_timestamp`` setting must be set
exactly as in the example.

Firewall, Panorama, and Traps ESM can all send logs to the same input port.

Step 2: Configure the Firewall or Endpoint Security Manager
-----------------------------------------------------------

There are two ways to send logs from a Next generation Firewall to Splunk:

1. All firewalls syslog directly to Splunk
2. All firewalls log to Panorama, then Panorama syslogs to Splunk

The Palo Alto Networks syslog documentation describes each option in detail
and how to configure it.

**Firewall and Panorama syslog to Splunk:**
https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os/monitoring/use-external-services-for-monitoring.html

Send Traps Endpoint logs to Splunk by configuring the Endpoint Security
Manager (ESM).

**Traps ESM syslog to Splunk:**
https://www.paloaltonetworks.com/documentation/32/endpoint/endpoint-admin-guide/reports-and-logging/enable-external-reporting-using-the-esm-console.html

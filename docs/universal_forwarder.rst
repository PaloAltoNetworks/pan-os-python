.. _universalforwarder:

Syslog-ng and Universal Forwarder
=================================

This document assumes you already have syslog-ng, Splunk Universal Forwarder and Splunk installed and will not cover installation.

You should also have the Palo Alto Networks for Splunk app and add-on installed as described in `Getting Started <http://pansplunk.readthedocs.io/en/latest/getting_started.html>`_

.. note:: The App and Add-on do not need to be installed on the Universal Forwarder.

Step 1: Setup Syslog-ng
-----------------------

Add the following lines to the ``/etc/syslog-ng/syslog-ng.conf`` file. This example uses the default install location of syslog-ng on an ubuntu server. Change the directory as need.

Under "Sources" add a source in syslog-ng to listen for logs on a port. This example uses port UDP 514::

    source s_udp514 { 
        network(
            transport("udp")
            port(514)
            flags(no-parse)
        );
    };

Under "Destinations" specify a .log file destination::

    destination d_udp514 { file("/YOURPATH/udp514.log" template("${MSG}\n")); };

Under "Log paths" specify the path of the log::

    log { source(s_udp514); destination(d_udp514); };

Save ``syslog-ng.conf`` and restart syslog-ng::

    $ /etc/init.d/syslog-ng restart

Step 2: Configure Splunk Universal Forwarder
--------------------------------------------

Configure the Universal Forwarder to monitor the ``/YOURPATH/udp514.log`` file created in step 1.

Create or modify``/opt/splunkforwader/etc/system/local/inputs.conf`` and add a monitoring stanza::

    [monitor:///YOURPATH/udp514.log]
    sourcetype = pan:log


Create or modify``/opt/splunkforwader/etc/system/local/outputs.conf`` and add a tcpout stanza::

    [tcpout]
    defaultGroup = default-autolb-group
    
    [tcpout:default-autolb-group]
    server = 192.168.0.3:9997

    [tcpout-server://192.168.0.3:9997]

.. note:: Replace the IP address 192.168.0.3 with the IP of Splunk indexer.



To forward to multiple Splunk servers use this tcpout stanza instead::

    [tcpout]
    defaultGroup = default-autolb-group
    
    [tcpout:default-autolb-group]
    server = 192.168.0.1:9997,192.168.0.2:9997,192.168.0.3:9997
    [tcpout-server://192.168.0.1:9997]
    [tcpout-server://192.168.0.2:9997]
    [tcpout-server://192.168.0.3:9997]

Restart Splunk Universal Forwarder::

    $ /opt/splunkforwarder/bin/splunk restart

Step 3: Configure Splunk Indexer
--------------------------------

If it doesn't exist, add a listening port on Splunk Indexer:

1. From the Web Interface navigate to **Settings->Forwarding and receiving**
2. Under **Recieve Data**, click on **Configure receiving**
3. If port 9997 is already listed then you are done
4. Otherwise, click on **New**
5. Add port 9997 to **Listen on this port**
6. Click Save

Step 4: Verify 
--------------

Verify logs are being forwarded correctly by searching for the following: ::

    source="/YOURPATH/udp514.log"

Change the source to the directory and file you are monitoring.

Verify that ``sourcetype`` is being transformed. You should see ``pan:traffic`` , ``pan:system`` , ``pan:threat`` , ``pan:config`` as the sourcetype.

If log ``sourcetype`` is ``pan:log`` then syslog-ng is changing the logs and they are not being transformed. Go back to step 1 and verify you made the correct changes.

.. note:: If the Indexer has not been running and receiving for a lengthy period of time. It may take awhile for logs to show up.

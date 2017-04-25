
Palo Alto Networks Add-on for Splunk
====================================

Copyright (C) 2014-2016 Palo Alto Networks Inc. All Rights Reserved.

* **Add-on Homepage:** https://splunkbase.splunk.com/app/2757
* **Authors:** Brian Torres-Gil and Paul Nguyen - Palo Alto Networks
* **Add-on Version:** 3.8.0

### Description ###
 
The Palo Alto Networks Add-on for Splunk allows a Splunk® Enterprise
or Splunk Cloud administrator to collect data from Palo Alto Networks
Next-Generation Firewall devices and Advanced Endpoint Protection. The
add-on collects traffic, threat, system, configuration, and endpoint logs
from Palo Alto Networks physical or virtual firewall devices over syslog.
After Splunk indexes the events, you can consume the data using the
pre-built dashboard panels included with the add-on, with Splunk Enterprise
Security, or with the Palo Alto Networks App for Splunk. This add-on
provides the inputs and CIM-compatible knowledge to use with other Splunk
Enterprise apps, such as the Splunk App for Enterprise Security and the
Splunk App for PCI Compliance, and integrates with Splunk Adaptive Response.

Documentation for this add-on is located at: http://pansplunk.readthedocs.io/

### Documentation ###

**Installation and Getting Started:** http://pansplunk.readthedocs.io/en/latest/getting_started.html  
**Release Notes:** http://pansplunk.readthedocs.io/en/latest/release_notes.html  
**Support:** http://pansplunk.readthedocs.io/en/latest/support.html

### Install from Git ###

This app is available on [Splunkbase](http://splunkbase.splunk.com/app/2757)
and [Github](https://github.com/PaloAltoNetworks/Splunk_TA_paloalto).
Optionally, you can clone the github repository to install the app.

From the directory `$SPLUNK_HOME/etc/apps/`, type the following command:

    git clone https://github.com/PaloAltoNetworks/Splunk_TA_paloalto.git Splunk_TA_paloalto
    
### Libraries Included ###

**Pan-Python:** [Github] (https://github.com/kevinsteves/pan-python)
**PanDevice:** [Github] (https://github.com/PaloAltoNetworks/pandevice)
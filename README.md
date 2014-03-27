
Splunk for Palo Alto Networks App
=================================

## Description ##

Field extractions and sample reports,
and dashboards for the Palo Alto
Networks Firewall

#### Version ####

* Splunk Version: 6.x
* App Version: 4.0.2
* Last Modified: Mar 2013
* Authors:
    * Monzy Merza - Splunk, Inc.
    * Brian Torres-Gil - Palo Alto Networks

#### Credits ####

Many Thanks to Contributors, Advisors, Testers:

* Joel 'JayKul' Bennett, David Dorsey
* David Hazekamp, Mike Munn, Adam Sealey
* David Markquardt, Gerald Kannapathy
* Will Hayes, Marc Benoit, Jeff Hillon
* Genti Zaimi, Scott Brenner, Steve Brown

#### Support ####

For fastest response to support, setup, help or feedback,
please click the __Ask a Question__ button at http://apps.splunk.com/app/491

For bugs or feature requests, you can also open an issue on github at 
https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks/issues

## IMPORTANT ##

This app ONLY works on Splunk 6.x

For Splunk 5.x, use version 3.x of this app.

## Dependencies ##

No dependencies

## Installing ##

- Unpack the tar ball into `$SPLUNK_HOME/etc/apps`
- Restart Splunk

Note: After restart, it can take up to 5 minutes for new data to show up in the dashboards.

## Configuring ##

### Setup Screen and Custom Commands ###

The first time you run the app from the web ui, you will be presented with a setup screen. The credentials are only needed if you wish to use the `panblock` and `panupdate` custom commands. The WildFire API is only needed if you are a WildFire subscriber and want Splunk to index WildFire analysis reports from the cloud when a malware sample is analyzed.  These credentials will be stored in Splunk using encryption the same way other Splunk credentials are stored.

If you do not wish to use these extra features, you can enter garbage values.

### To get the firewall data into Splunk ###

IMPORTANT: When you configure the input port, you must set the sourcetype of the firewall data to pan_log and the index to pan_logs.  This can be done from the Web UI or the CLI.  Then, configure the firewall to set traffic to Splunk.

#### From the Splunk Web UI ####

- Navigate to Manager -> Data Inputs -> UDP -> New
- Set the UDP port (Palo Alto Networks firewalls default to port 514)
- Set sourcetype: From list
- Select source type From list: pan_log
- Click on More settings
- Index: pan_logs

For details: http://www.splunk.com/base/Documentation/latest/admin/MonitorNetworkPorts

#### From the CLI via inputs.conf ####

- Edit `$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/local/inputs.conf` 

Example:  (Palo Alto Networks firewalls default to udp port 514)

    [udp://514]
    index= pan_logs
    connection_host = ip
    sourcetype = pan_log
    no_appending_timestamp = true

#### Configure the Firewall ####

Next, on the Palo Alto Networks firewall or Panorama management center, create a Log Forwarding object to send desired syslogs to the Splunk Server. Refer to the Palo Alto Networks documentation for details on log forwarding.  https://live.paloaltonetworks.com/community/documentation

Note: Palo Alto Networks devices have a variety of different logs including traffic, threat, url filtering, malware, etc. This app works with the all the default log types. Customized log types may not work, if they are not defined in the Palo Alto Networks syslog configuration documentation (PANOS-Syslog-Integration-TN-RevM).

## Hints and Tips ##

### Source types ###

As Splunk indexes your Palo Alto Networks firewall data, the app will rename the sourcetypes to pan_threat, pan_traffic, pan_config, and pan_system depending on the logging facility. 

Log can be further filtered by type during search by using predefined macros.  The following macros are available in the search bar to filter on logs of a specific type.

- pan_traffic
- pan_threat
- pan_url
- pan_file
- pan_data
- pan_wildfire
- pan_wildfire_report
- pan_config
- pan_system

Use these macros in the search bar by surrounding them with back-ticks.

### WildFire Cloud Integration ###

WildFire analysis reports can be retrieved dynamically from the WildFire cloud after each analysis.  This retrieval requires a WildFire API Key from https://wildfire.paloaltonetworks.com

Malware analysis reports from the WildFire Cloud are dynamically downloaded and indexed when a WildFire log is received from a firewall.

### NetFlow ###

NetFlow graphs and charts are based on NetFlow data produced by Palo Alto Networks devices and converted to syslog messages by 3rd party software - NetFlow Integrator. Download a 30-day free trial of NetFlow Integrator at https://www.netflowlogic.com/downloads

Steps to configure:

- Install NetFlow Integrator on a separate server or together with Splunk Forwarder
- Point Palo Alto Networks device NetFlow settings to NetFlow Integrator server, default port 9995 with PAN-OS Field Types enabled (see [Administrator's Guide](https://live.paloaltonetworks.com/community/documentation/content?filterID=contentstatus[published]~category[administrators-guide]&filterID=contentstatus[published]~objecttype~objecttype[document]&itemView=detail))
- Enable NetFlow in the Splunk for Palo Alto Networks app setup page
- Restart Splunk for the previous change to take effect
- Add NetFlow Integrator output pointing to Splunk UDP port 10514
- Create Splunk UDP data input `sourcetype=flowintegrator`, which receives syslog messages on UDP port 10514, and `index=flowintegrator`.
- Enable NetFlow Integrator Palo Alto Networks Rules (10030 through 10035) and Converter (20093)

If you have any questions, or require any assistance with configuration please contact NetFlow Logic at https://netflowlogic.zendesk.com/home

### High Performance Value Store (HPVS) ###

The app uses the HPVS feature introduced in Splunk 5.0 and 6.0. This feature provides a tremendous performance improvement for dashboards and views. The views and dashboards make use of saved searches that store data on your search head. This means that disk storage on your search head will be consumed as a result of these searches. If you turn off these saved searches, your dashboards will not render. Or dashboard rendering will be really, really slow. Please post a question to answers.splunk.com if you'd like to explore alternatives. 

### Lookups ###

Lookups are provided for the threat_id and app field to provide additional information about threats and applications on the network.

### Using the form fields on the dashboards ###

All the dashboards work without any filtering values for the form fields. If you want to filter based on a field you should use asterisks before and after the search terms unless you are absolutely sure of the filter value.

Keep in mind that searches that have longer time ranges may take a little longer to return the results. 

### Modifying dashboards ###

Dashboards are built with SimpleXML, so they can be modified using the Splunk GUI.  To do this, click the __Edit__ menu in the top right of the dashboard and select __Edit Panels__.  You can drag panels to new positions, change the visualization (pie, column, area, etc), and modify the searches.  If you modify a dashboard and want to recover the original dashboard, delete the modified dashboard file in `$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/local/data/ui/views` and restart Splunk.

## What's new in this version ##

Version 4.0.2

- Fix: Overview dashboard optimizations
- Fix: Top Applications panel would sometimes show error 
- Fix: Traffic dashboard form filter works

Version 4.0.1

- Fix: Config dashboard shows all events
- Fix: Better handling of navbar changes

Version 4.0

- Splunk 6 support
- Dashboards converted to Splunk 6 SimpleXML, meaning dashboards can now:
    - Print
    - Export as pdf
    - Produce scheduled reports
    - Use pre-populated dropdowns in filters
    - Change using SplunkWeb by editing the panels
- Maps converted to Splunk 6 built-in maps (removes dependencies on other apps)
- Updated navbar including icons and colors

## Installing from Git ##

This app is available on [Splunk Apps](http://apps.splunk.com/app/491) and [Github](https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks).  Optionally, you can clone the github repository to install the app.
From the directory `$SPLUNK_HOME/etc/apps/`, type the following command:

    git clone https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks.git SplunkforPaloAltoNetworks


Splunk for Palo Alto Networks App
=================================

## Description ##

Field extractions and sample reports,
and dashboards for the Palo Alto
Networks Firewall

#### Version ####

* Splunk Version: 5.x
* App Version: 3.3.1
* Last Modified: June 2013
* Authors:
    * Monzy Merza - Splunk, Inc.
    * Brian Torres-Gil - Palo Alto Networks

#### Credits ####

Many Thanks to Contributors, Advisors, Testers:

* Joel 'JayKul' Bennett, David Dorsey
* David Hazekamp, Mike Munn, Adam Sealey
* David Markquardt, Gerald Kannapathy
* Will Hayes, Marc Benoit, Jeff Hillon
* Genti Zaimi

#### Support ####

For fastest response to support, setup, help or feedback, please post to
http://answers.splunk.com and tag your questions with `paloalto`.

For bugs or feature requests, you can also open an issue on github at 
https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks/issues

## IMPORTANT ##

This app ONLY works on Splunk 5.x

## Dependencies ##

This app depends on the following Splunk Apps available from Splunk Base http://splunk-base.splunk.com/apps/ :

- [Splunk for use with AMMAP Flash maps] (http://splunk-base.splunk.com/apps/22372/splunk-for-use-with-ammap-flash-maps)
- [Google Maps] (http://splunk-base.splunk.com/apps/22365/google-maps)
- [Geo Location Lookup Script] (http://splunk-base.splunk.com/apps/22282/geo-location-lookup-script-powered-by-maxmind)

You do not need to install these apps if you do not wish to use the mapping and geo location features. The main dashboard will not render properly without the above apps.

## Installing ##

- Ensure that the apps listed in the Dependencies section are installed.
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
- pan_data
- pan_wildfire
- pan_wildfire_report
- pan_config
- pan_system

Use these macros in the search bar by surrounding them with back-ticks.

### High Performance Value Store (HPVS) ###

The app uses the HPVS feature introduced in Splunk 5.0. This feature provides a tremendous performance improvement for dashboards and views. The views and dashboards make use of saved searches that store data on your search head. This means that disk storage on your search head will be consumed as a result of these searches. If you turn off these saved searches, your dashboards will not render. Or dashboard rendering will be really, really slow. Please post a question to answers.splunk.com if you'd like to explore alternatives. 

### Lookups ###

Lookups are provided for the threat_id and app field to provide additional information about threats and applications on the network.

### Using the form fields on the dashboards ###

All the dashboards work without any filtering values for the form fields. If you want to filter based on a field you should use asterisks before and after the search terms unless you are absolutely sure of the filter value.

Keep in mind that searches that have longer time ranges may take a little longer to return the results. 

## What's new in this version ##

Version 3.3.1  
- Fix: App setup screen allows blank values
- Fix: Several GUI fixes and enhancements

Version 3.3  
- Malware analysis reports from the WildFire Cloud are dynamically downloaded and indexed when a WildFire log is received from a firewall.
- WildFire dashboard
    - Recent WildFire events
    - Graphs of WildFire statistical data
    - Detect compromised hosts using malware behavior to traffic log correlation

Note: Malware analysis report retrieval requires a WildFire API Key from https://wildfire.paloaltonetworks.com

## Installing from Git ##

This app is available on [Splunkbase](http://splunk-base.splunk.com/apps/22327/splunk-for-palo-alto-networks) and [Github](https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks).  Optionally, you can clone the github repository to install the app.
From the directory `$SPLUNK_HOME/etc/apps/`, type the following command:

    git clone https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks.git

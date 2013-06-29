
Splunk for Palo Alto Networks App
=================================

## Description ##

Field extractions and sample reports,
and dashboards for the Palo Alto
Networks Firewall

#### Version ####

* Splunk Version: 5.x
* App Version: 3.3
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

For fastest response to support, setup, help
or feedback, please post to
answers.splunk.com and tag your questions
with 'palo' or paloalto'

Alternatively, contact: bd-sec@splunk.com 

## IMPORTANT ##

This app ONLY works on Splunk 5.x

## Dependencies ##

The app requires the following Splunk Apps available from Splunk Base [http://splunk-base.splunk.com/apps/] (http://splunk-base.splunk.com/apps/) :

- [Splunk for use with AMMAP Flash maps] (http://splunk-base.splunk.com/apps/22372/splunk-for-use-with-ammap-flash-maps)
- [Google Maps] (http://splunk-base.splunk.com/apps/22365/google-maps)
- [Geo Location Lookup Script] (http://splunk-base.splunk.com/apps/22282/geo-location-lookup-script-powered-by-maxmind)

You do not need to install these apps if you do not wish to use the Apps mapping and geo location features. The main dashboard will not render properly without the above apps.

## Installing ##

Ensure that the apps listed in the Dependencies section are installed.

To install this app:

- Unpack the tar ball into `$SPLUNK_HOME/etc/apps`
- Restart Splunk

Note 

- After restart, it can take up to 5 minutes for new data to show up. 
- For older data, you can use the backfill feature of splunk to backfill the summary index:

[http://www.splunk.com/base/Documentation/latest/Knowledge/Managesummaryindexgapsandoverlaps#Use_the_backfill_script_to_add_other_data_or_fill_summary_index_gaps](http://www.splunk.com/base/Documentation/latest/Knowledge/Managesummaryindexgapsandoverlaps#Use_the_backfill_script)

## Configuring ##

Setup Screen and Custom Commands:
The first time you run the app from the web ui, you will be presented with a setup screen. The credentials are only needed if you wish to use the panblock and panupdate custom commands. These passwords will be stored in Splunk. The same way as other splunk credentials are stored. If you do not wish to use the custom commands, you can leave this page blank or enter garbage values.

To get the firewall data into Splunk:
IMPORTANT: When you configure the input port, you must set the sourcetype of the firewall data to pan_log and the index to pan_logs.

From the web ui:

Manager -> Data Inputs -> UDP -> New -> UDP port:

    Palo Alto Networks firewalls default to UDP.
    Source type: Set Sourcetype From list:
    Select Sourcetype: pan_log -> More -> Index: pan_logs  

For details, [http://www.splunk.com/base/Documentation/latest/admin/MonitorNetworkPorts](http://www.splunk.com/base/Documentation/latest/admin/MonitorNetworkPorts
)

### Input configuration via inputs.conf ###

- Edit `$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/local/inputs.conf` 

Example:  (Palo Alto Networks firewalls default to udp port 514)

    [udp://514]
    index= pan_logs
    connection_host = ip
    sourcetype = pan_log
    no_appending_timestamp = true

- Next, configure the firewall device to direct log traffic to the Splunk server on the network port that you specified.

- Refer to the Palo Alto documentation for details on PAN log forwarding. The Palo Alto devices have a variety of different logs. This app works with the default log configuration. If you use any customized log types that are not defined in the Palo Alto syslog configuration documentation (PANOS-Syslog-Integration-TN-RevM), some of the apps features may not work. 

### Source types ###

As Splunk indexes your Palo Alto Networks firewall data, the app will rename the sourcetypes to pan_threat, pan_traffic, pan_config, and pan_system depending on the logging facility. 

### High Performance Value Store (HPVS) ###

The app uses the HPVS feature introduced in Splunk 5.0. This feature provides a tremendous performance improvement for dashboards and views. The views and dashboards make use of saved searches that store data on your search head. This means that disk storage on your search head will be consumed as a result of these searches. If you turn off these saved searches, your dashboards will not render. Or dashboard rendering will be really, really slow. Please post a question to answers.splunk.com if you'd like to explore alternatives. 

### Lookups ###

Lookups are provided for the threat_id and app field to provide additional information about threats and applications on the network. 

### Using the form fields on the dashboards ###

All the dashboards work without any filtering values for the form fields. If you want to filter based on a field you should use asterisks before and after the search terms unless you are absolutely sure of the filter value. e.g. In the Content Filtering View, if you want to filter results by the virtual system called 'vsys1', a good practice would be to enter `#vsys1#` in the Virtual System field.

Keep in mind that searches that have longer time ranges may take a little longer to return the results. 

## What's new in this version ##

- Malware analysis reports from the WildFire Cloud are dynamically downloaded and indexed when a WildFire log is recieved from a firewall.
- WildFire dashboard
    - Recent WildFire events
    - Graphs of WildFire statistical data
    - Detect compromised hosts using malware behavior to traffic log correlation

Note: Malware analysis report retrieval requires a WildFire API Key from [https://wildfire.paloaltonetworks.com](https://wildfire.paloaltonetworks.com).


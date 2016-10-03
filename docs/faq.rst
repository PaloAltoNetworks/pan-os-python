Frequently Asked Questions
==========================

Why use Splunk with my Palo Alto Networks products?
---------------------------------------------------
Palo Alto Networks products provide exceptional levels of visibility into
network traffic and malicious activity, both in the network and on the
endpoint. Combining this visibility with Splunk allows a customer to make
correlations and perform analytics around different kinds of data. These
correlations can be between different kinds of Palo Alto Networks data, for
example, correlating WildFire reports against traffic logs to detect
infected hosts, or correlating firewall logs with endpoint logs. But the
real power of Splunk is correlations and analytics across multiple sources
of data and multiple vendors, for example, correlating firewall logs with
webserver logs, or advanced endpoint security logs with Windows event logs.

Why use Palo Alto Networks with my Splunk?
------------------------------------------
Splunk has unmatched ability to consume and analyze data, but for Splunk to
present usable and actionable insights, it must have the highest level of
visibility and knowledge possible. Palo Alto Networks provides that level
of visibility into the network and the endpoint to detect and even predict
malicious activity. When an indicator of compromise is detected, Palo Alto
Networks and Splunk work together to take action and remediate problems
automatically to keep the network secure.

What can the Palo Alto Networks Splunk App do?
----------------------------------------------
The Splunk for Palo Alto Networks app is one of the most downloaded
apps for Splunk and is completely free. Splunk apps tell Splunk how to
handle data and come with dashboards that display visualizations and
analysis of the data. The Splunk for Palo Alto Networks app brings in
syslogs from firewalls, Panorama, and Traps Endpoint Security Manager
and makes the data easily searchable, analyzes the data with correlations,
and displays the data including any anomalies visually. When actionable
alerts are produced, Splunk can take action by leveraging the firewall and
Panorama APIs to add context that the firewall uses to prevent targeted
threats.

Learn more:
  * :ref:`features`
  * :ref:`advancedfeatures`

What kinds of data does the app take in?
----------------------------------------
The Splunk for Palo Alto Networks app accepts syslogs from Firewalls,
Panorama, and Endpoint Security Manager. Also, WildFire malware reports
are pulled from the WildFire portal as XML.  These reports represent a
behavioral fingerprint of any malware detected by WildFire which you can
correlate against other logs to detect indicators of compromise.

Does the app have a Data Model?
-------------------------------
Yes! In Splunk 6.x, the data model feature allows Splunk
users to quickly visualize and analyze data with a point-and-click
interface (instead of the Splunk searchbar language). This capability
requires that the data be modeled into a Splunk Data Model which is a
highly accelerated summary index of the data. Not only is there a data model
for all Palo Alto Networks logs, all the app's dashboards are based on this
accelerated data model for extremely fast data retrieval and visualization.
So the app itself is using the same Data Model that Splunk administrators
would use to generate visualizations.

Does the app conform to the Common Information Model?
-----------------------------------------------------
Yes! The `Common Information Model`_ (CIM) is a set of standards and an app
that help other apps conform to a common naming and tagging scheme. This
allows Splunk users to search for data across multiple kinds of logs from
multiple vendors using the same field names to access the data, which eases
correlations across different kinds of data. For example, a Splunk user
could correlate between firewall logs and webserver logs. The Splunk for
Palo Alto Networks app conforms strictly to the Common Information Model.

.. _Common Information Model: http://docs.splunk.com/Documentation/CIM/latest/User/Overview

Does the app work with the Splunk Enterprise Security app?
----------------------------------------------------------
Yes! The `Splunk Enterprise Security app`_ (or "ES"), is a set of security
log parsers and security related dashboards that conform to the Common
Information Model. The Enterprise Security app contains a TA (parsers) for
Palo Alto Networks firewall logs. The Splunk for Palo Alto Networks app and
Enterprise Security app can be used individually, or together. The Palo
Alto Networks Add-on 3.7 supports the new Adaptive Response capabilities
of Splunk Enterprise Security.

.. _Splunk Enterprise Security app: http://www.splunk.com/en_us/products/premium-solutions/splunk-enterprise-security.html

I use Splunk ES with the Palo Alto Add-on (TA), why use the App?
----------------------------------------------------------------

The Palo Alto Networks App offers significant additional benefits including:

* Take immediate action to stop threats with :ref:`automated remediation <remediation>`
* Index the :ref:`behavioral footprint <wildfire>` of malware seen by Wildfire
* :ref:`Sync user logins <syncuserid>` from authentication logs to User-ID
* :ref:`Update content pack <contentpack>` metadata for apps and threats
* Datamodel with Pivots for easy access to data and visualizations
* Macros for easy access to logs
* Dashboards to track SaaS application usage, user activity, system health,
  configuration changes for audits, Wildfire malware, and other Palo Alto
  Networks specific features.

My question isn't answered here, how do I get answers?
------------------------------------------------------
Here are a few ways to get your questions answered. Search for answers in this order:

* Check the App Documentation at http://pansplunk.readthedocs.io
* Search on `Splunk Answers`_
* If you can't find an answer or need support, ask a question using the
  instructions on the :ref:`getsupport` page.

.. _Splunk Answers: http://answers.splunk.com/app/questions/491.html

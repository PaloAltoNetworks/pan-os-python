Overview
========

About the App
-------------

.. image:: _static/overview.png

Palo Alto Networks and Splunk have partnered to deliver an advanced security
reporting and analysis tool. The collaboration delivers operational reporting
as well as simplified and configurable dashboard views across Palo Alto
Networks family of next-generation firewalls.

Splunk for Palo Alto Networks leverages the data visibility provided by
Palo Alto Networks's firewalls and endpoint protection with Splunk's extensive
investigation and visualization capabilities to deliver an advanced
security reporting and analysis tool. This app enables security analysts,
administrators, and architects to correlate application and user activities
across all network and security infrastructures from a real-time and
historical perspective.

Complicated incident analysis that previously consumed days of manual and
error-prone data mining can now be completed in a fraction of the time,
saving not only manpower but also enabling key enterprise security
resources to focus on critical, time-sensitive investigations.

**App Author**: Brian Torres-Gil -- `email <mailto:btorres-gil@paloaltonetworks.com>`_ -
`splunkbase <https://answers.splunk.com/users/183886/btorresgil.html>`_ -
`github <https://github.com/btorresgil>`_

Splunk Version Compatibility
----------------------------

==============   ===========
Splunk Version   App Version
==============   ===========
Splunk 6         Palo Alto Networks App 4.x or 5.x
Splunk 5         Palo Alto Networks App 3.x
==============   ===========

.. _features:

Features
--------

The **Palo Alto Networks App** and **Add-on** have different features that are
designed to work together, and with Splunk Enterprise Security when available.

**Palo Alto Networks App**

* Dashboards to track SaaS application usage, user activity, system health,
  configuration changes for audits, Wildfire malware, and other Palo Alto
  Networks specific features.
* Advanced correlations in each dashboard
* Datamodels with pivots for easy access to data and visualizations
* Index the :ref:`behavioral footprint <wildfire>` of malware seen by Wildfire
* :ref:`syncuserid`
* :ref:`dag`
* :ref:`contentpack`
* :ref:`Special searchbar commands <commands>`
* Macros for easy access to logs

**Palo Alto Networks Add-on**

* Fully CIM_ compliant and designed for use with `Splunk Enterprise Security`_
* Field extraction for Palo Alto Networks logs from Firewalls_, Panorama_, and
  `Traps Endpoint Security`_
* :ref:`ipclassification` tailored to your network environment
* :ref:`Designate SaaS applications <sanctioned_saas>` as sanctioned or
  unsanctioned for your organization
* App and Threat metadata from the Palo Alto Networks content and signature
  packs

.. _CIM: http://docs.splunk.com/Documentation/CIM/latest/User/Overview
.. _Splunk Enterprise Security:
   http://www.splunk.com/en_us/products/premium-solutions/splunk-enterprise-security.html
.. _Firewalls:
   https://www.paloaltonetworks.com/products/platforms/firewalls.html
.. _Panorama:
   https://www.paloaltonetworks.com/products/platforms/centralized-management/panorama/overview.html
.. _Traps Endpoint Security:
   https://www.paloaltonetworks.com/products/endpoint-security.html

Install from Github
-------------------

This app is available on `SplunkBase <http://splunkbase.splunk.com/app/491>`_
and `Github <https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks>`_.
Optionally, you can clone the github repository to install the app. Please
feel free to submit contributions to the app using pull requests on github.

From the directory ``$SPLUNK_HOME/etc/apps/``, type the following command::

    git clone https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks.git SplunkforPaloAltoNetworks


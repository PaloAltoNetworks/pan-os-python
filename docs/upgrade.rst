.. _upgrade:

Upgrade
=======

Most upgrades don't require any special action. Just upgrade like any other
Splunk app. For the versions below, there are some considerations or
actions needed to migrate to the new version.

Upgrade to App Version 5.0
--------------------------

This applies if upgrading from a pre-5.0 version of this app to 5.0.0 or higher.


Add-on (TA)
~~~~~~~~~~~

Starting with App v5.0.0, the App now requires the `Palo Alto Networks Add-on
for Splunk`_. The required version of the TA is always listed in the
`README.md`_ file in the Palo Alto Networks App, and in the :ref:`releasenotes`,
and this Add-on is always included in the App.

You do not need to install the Add-on (TA) separately. It is installed or
upgraded automatically when the Palo Alto Networks App v5.0.0 or higher is
installed.

**ACTION REQUIRED**: You must remove the deprecated TA, called `TA_paloalto`.
This usually applies if you use Splunk Enterprise Security version 3.x because
it comes with `TA_paloalto`. Recreate any inputs from the old TA in the new TA
using the instructions in the :ref:`gettingstarted` guide. Check the **apps**
directory in Splunk and take the necessary action according to the table:

==================  ========================================================
Existing TA         Action Needed
==================  ========================================================
TA_paloalto         Delete this TA directory, recreate data inputs in new TA
Splunk_TA_paloalto  No action required, TA is upgraded automatically by App
No TA installed     No action required, TA is installed automatically by App
==================  ========================================================

.. _Palo Alto Networks Add-on for Splunk:
   https://splunkbase.splunk.com/app/2757
.. _README.md:
   https://github.com/PaloAltoNetworks-BD/SplunkforPaloAltoNetworks/blob/master/README.md

Index
~~~~~

The new App 5.0 and Add-on 3.5 do not use the ``pan_logs`` index that previous
versions used. Now, logs can be stored in any index. Since the App no longer
specifies the pan_logs index, if you are upgrading, you will need to specify
the index yourself.

**ACTION REQUIRED**: Create a new index called ``pan_logs`` using the
Splunk GUI or on the command line. Also, in your Splunk role settings, add the
``pan_logs`` index to the list of **Indexes searched by default**.

Splunk will not overwrite the data previously indexed, and you will have
access to all the data indexed before the upgrade. Logs will continue to be
stored in the ``pan_logs`` index according to the data inputs from the
previous App version, unless otherwise specified.  The data input can
optionally be changed to store logs in a different index.

Results still might not show up during a search. This is because the
``pan_logs`` index is not searched by default. To add the ``pan_logs`` index
to the list of indexes searched by default, in your Splunk settings, navigate
to **Access controls** -> **Roles** -> **<your role>**. Scroll down to the
section **Indexes searched by default**. Move ``pan_logs`` (or
``All non-internal indexes``) to the right column.

Lookups
~~~~~~~

The lookups have been moved to the Add-on (TA). However, Splunk Enterprise
does not remove lookup tables during the upgrade process. So you must remove
the lookup tables from the App after the upgrade, or you will see errors
while searching within the App.

**ACTION REQUIRED**: Delete any lookups in the App that you did not create.
If you did not create any lookups in the App directory, then you can safely
delete the entire lookup directory from the App. The path to the lookup
directory is ``$SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/lookups``

For example::

    rm -rf $SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/lookups

Sourcetype
~~~~~~~~~~

The sourcetype format has changed:

==============   ==============
Old sourcetype   New sourcetype
==============   ==============
pan_log          pan:log
pan_traffic      pan:traffic
pan_threat       pan:threat
pan_config       pan:config
pan_system       pan:system
==============   ==============

No action is required. The old sourcetypes will be interpreted as the new
sourcetype automatically. Optionally the data input can be changed to store
logs with the sourcetype ``pan:log`` instead of ``pan_log``. This is more
correct, but will not change the way logs are retrieved from the index.

.. note:: The data input should only specify pan:log or pan_log for the
   sourcetype. The logs are automatically parsed into the other sourcetypes
   (pan_traffic, pan_threat, etc) by the Add-on, so they should not be
   referenced in the data input.


Upgrade to App Version 4.1
--------------------------

This applies if upgrading from a pre-4.1 version of this app to 4.1.0 or higher.

Starting in version 4.1 of this app, all of the dashboards use the Splunk 6
Datamodel feature, which allows for pivot of Palo Alto Networks data and
better control and acceleration of summary indexes used by the dashboards.
This replaces the TSIDX feature from Splunk 5.

After upgrade to 4.1 or higher, you may delete the TSIDX files that were
generated by the previous version of the app.  To delete the TSIDX files,
look under ``$SPLUNK_HOME$/var/lib/splunk/tsidxstats/`` and remove any
directories that start with ``pan_``.  There could be up to 10 directories.

Splunk will backfill the datamodel with historic data up to 1 year old.  It
may take some time for historic data to show up in the dashboards, but it
will be available in the pivot interface and search immediately.  The time
range for historic data to be available in the dashboards can be adjusted
in the datamodel accelerations settings.

If you have customized the built-in dashboards of a previous app version,
then they will no longer work because the customized dashboards will still
use TSIDX.  Remove your custom dashboards from the ``local`` directory of the
app to use the new datamodel-based dashboards.  You can add your
customizations to the new dashboards.

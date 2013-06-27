echo "$@" >> /tmp/map_results.run
python $SPLUNK_HOME/etc/apps/SplunkforPaloAltoNetworks/bin/map_results.py "$@"

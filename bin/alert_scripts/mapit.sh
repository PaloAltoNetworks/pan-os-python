echo "$@" > /tmp/ammap_map_results.run
python $SPLUNK_HOME/etc/apps/AMMAP/bin/map_results.py "$@"

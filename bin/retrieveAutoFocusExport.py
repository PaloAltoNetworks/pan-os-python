# ##########################################
# Version 1.0
# Author: Palo Alto Networks
#
# About this script:
#
# Script's actions and warning messages are logged in
# $SPLUNK_HOME/var/log/splunk/python.log
############################################
############################################
# How to Use this script
# The script must be provided 3 things to retrieve
# an AutoFocus log from the cloud:
# 1.  An API Key. This is found at https://autofocus.paloaltonetworks.com
#   under 'Settings'.
# 3.  The Label of the export. Created on autoocus.paloaltonetworks.com.
###########################################
#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import os
import sys
import copy

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
import common
import pan.afapi
import json
# import splunklib.client as client
# from splunklib.client import connect
# import kvstore
from kvstore import KvStoreHandler


def validate_input(helper, definition):
    """Implement your own validation logic to 
    validate the input stanza configurations"""
    # This example accesses the modular input variable
    opt_labels = definition.parameters.get('label', None)
    pass


def collect_events(helper, inputs, ew):
    helper.set_log_level('debug')
    sessionKey = inputs.metadata.get('session_key')

    # Get API KEY
    # helper.log_debug("Getting Autofocus APIKey from encrypted store")
    af_apikey = helper.get_global_setting("autofocus_api_key")
    # helper.log_debug("AFAPIKEY: " + af_apikey)

    opt_labels = helper.get_arg('label')
    if hasattr(opt_labels, 'lower'):
        opt_labels = [opt_labels, ]

    # Loop through labels and call AF API to get entries.
    for label in opt_labels:
        helper.log_debug("Current Label: " + label)
        # Check if Label already exsist and get last submit date
        helper.log_debug("Getting AutoFocus Export for results")
        # Use API to get entries in Export List from AutoFocus
        values = {
            "apiKey": af_apikey,
            # "panosFormatted": "true",
            "exportMetadata": "true",
            "label": label
        }
        try:
            afapi = pan.afapi.PanAFapi(api_key=af_apikey)
            jsAfapi = afapi.export(json.dumps(values)).json
            af_export = jsAfapi['export_list']
            # helper.log_debug(jsAfapi)
        except pan.afapi.PanAFapiError as e:
            helper.log_debug(e)
            sys.exit(1)

        sync_kvstore = sync_to_kvstore(helper, sessionKey, label, af_export)
        helper.log_debug(sync_kvstore)
        # Label does not exsist in KVstore go ahead and batch import.
        if sync_kvstore == 1:
            helper.log_debug("New to KVSTORE")
            send_to_kvstore(helper, sessionKey, jsAfapi['export_list'])
        # Label does exsist in KVstore. Change Detected.
        elif sync_kvstore == -1:
            helper.log_debug("Update KVSTORE")
            # Delete entries for given label
            options = {
                "app": "Splunk_TA_paloalto",
                "owner": "nobody",
                "collection": "autofocus_export"
            }
            query = {"label": label}
            delete = True
            helper.log_debug("Delete entries for this label.")
            remove = KvStoreHandler.query(query, sessionKey, options, delete)
            helper.log_debug("Add entries with this label to kvstore")
            send_to_kvstore(helper, sessionKey, jsAfapi['export_list'])
        # NO CHANGE TO EXPORT LIST
        else:
            helper.log_debug("No Change")


def sync_to_kvstore(helper, sessionKey, label, af_export):
    helper.log_debug("checking KVSTORE")
    url_options = {
        "app": "Splunk_TA_paloalto",
        "owner": "nobody",
        "collection": "autofocus_export"
    }
    query = {"label": label}
    arg = {
        "query": query
    }
    response = KvStoreHandler.adv_query(arg, url_options, sessionKey)
    # helper.log_debug(response)
    results = 0
    kv_export = json.loads(response[1])
    # helper.log_debug("kv_export:")
    # helper.log_debug(kv_export)
    # helper.log_debug("af_export:")
    # helper.log_debug(af_export)

    # Check to see if we have entries in the KVstore already.
    if kv_export:
        helper.log_debug("Label Exist")
        # Check if list are same size
        if len(kv_export) == len(af_export):
            for entry in kv_export:
                # Remove fields from kv_export so dicts will match.
                if '_key' in entry:
                    del(entry['_key'])
                if '_user' in entry:
                    del(entry['_user'])
                if entry not in af_export:
                    helper.log_debug("not a match")
                    helper.log_debug(entry)
                    results = -1
                    return results
                else:
                    helper.log_debug("Match")
        else:
            helper.log_debug("List count not same.")
            results = -1
            return results
    else:
        helper.log_debug("Label return empty")
        results = 1
    return results


def send_to_kvstore(helper, sessionKey, export_list):
    helper.log_debug("Inside Send to KVSTORE")
    url_options = {
        "app": "Splunk_TA_paloalto",
        "owner": "nobody",
        "collection": "autofocus_export"
    }
    helper.log_debug(export_list)
    response = KvStoreHandler.batch_create(export_list, sessionKey, url_options)
    helper.log_debug(response)

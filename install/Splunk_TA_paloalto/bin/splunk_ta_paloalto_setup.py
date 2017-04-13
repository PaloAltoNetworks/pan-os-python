"""
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the
configuration page.

    handleList method: lists configurable parameters in the configuration page
    corresponds to handleractions = list in restmap.conf

    handleEdit method: controls the parameters and saves the values
    corresponds to handleractions = edit in restmap.conf
"""
import splunk_ta_paloalto_declare

import json
import splunk.clilib.cli_common as scc
import splunk.admin as admin


import solnlib.utils as utils
import solnlib.log as log
import solnlib.conf_manager as conf
import splunk_ta_paloalto_consts as setup_const

log.Logs.set_context(namespace="splunk_ta_paloalto")
logger = log.Logs().get_logger("setup")

def get_or_create_conf_file(conf_mgr, file_name):
    try:
        conf_file = conf_mgr.get_conf(file_name)
        return conf_file
    except conf.ConfManagerException as cme:
        conf_mgr._confs.create(file_name)
        return conf_mgr.get_conf(file_name, refresh=True)

def filter_eai_property(stanza):
    if isinstance(stanza, dict):
        for k in list(stanza.keys()):
            if k.startswith('eai:'):
                del stanza[k]
            else:
                stanza[k] = filter_eai_property(stanza[k])
    return stanza

class ConfigApp(admin.MConfigHandler):
    valid_args = ("all_settings",)

    stanza_map = {
        setup_const.global_settings: True,
        setup_const.myta_credential_settings: True,
        setup_const.myta_customized_settings: True,
    }

    global_cred_fields = [setup_const.proxy_password, setup_const.password]
    cred_fields = [setup_const.password]
    encrypt_fields_credential = (setup_const.password,)
    encrypt_fields_customized = (setup_const.password,)
    cred_confs = ((setup_const.myta_credential_settings, setup_const.myta_credential_conf),)

    def setup(self):
        """
        Set up supported arguments
        """
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in self.valid_args:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        logger.info("start list setup configure.")
        scheme, host, port = utils.extract_http_scheme_host_port(scc.getMgmtUri())
        conf_mgr = conf.ConfManager(self.getSessionKey(), self.appName, scheme=scheme, host=host, port=port)
        ta_conf_file = get_or_create_conf_file(conf_mgr, setup_const.myta_conf)
        # read globala and proxy settings
        all_settings = ta_conf_file.get_all()
        if not all_settings:
            all_settings = {}
        self._setNoneValues(all_settings.get(setup_const.global_settings, {}))
        # read account credential settings
        for cred, cred_conf in self.cred_confs:
            cred_conf_file = get_or_create_conf_file(conf_mgr, cred_conf)
            creds = cred_conf_file.get_all()
            if creds:
                self._setNoneValues(creds)
                all_settings.update({cred: creds})
        # customized conf
        customized_conf_file = get_or_create_conf_file(conf_mgr, setup_const.myta_customized_conf)
        settings = customized_conf_file.get_all()
        all_settings[setup_const.myta_customized_settings] = settings

        self._clearPasswords(all_settings, self.cred_fields)
        all_settings = filter_eai_property(all_settings)
        all_settings = json.dumps(all_settings)
        all_settings = utils.escape_json_control_chars(all_settings)
        confInfo[setup_const.myta_settings].append(setup_const.all_settings, all_settings)
        logger.info("list setup configure is done.")

    def handleEdit(self, confInfo):
        logger.info("start edit setup configure.")
        scheme, host, port = utils.extract_http_scheme_host_port(scc.getMgmtUri())
        conf_mgr = conf.ConfManager(self.getSessionKey(), self.appName, scheme=scheme, host=host, port=port)
        ta_conf_file = get_or_create_conf_file(conf_mgr, setup_const.myta_conf)
        customized_conf_file = get_or_create_conf_file(conf_mgr, setup_const.myta_customized_conf)
        all_origin_settings = ta_conf_file.get_all()
        all_settings = utils.escape_json_control_chars(
            self.callerArgs.data[setup_const.all_settings][0])
        all_settings = json.loads(all_settings)
        # write global and proxy settings
        self._updateGlobalSettings(setup_const.global_settings, all_settings,
                                   all_origin_settings, ta_conf_file)
        # write customized settings
        customized_conf_file = get_or_create_conf_file(conf_mgr, setup_const.myta_customized_conf)
        self._updateConfStanzas(all_settings.get(setup_const.myta_customized_settings, {}), customized_conf_file, self.encrypt_fields_customized)
        # write account credential settings
        for cred, conf_file in self.cred_confs:
            cred_conf_file = get_or_create_conf_file(conf_mgr, conf_file)
            creds = all_settings.get(cred, {})
            if creds == setup_const.ignore_backend_req:
                logger.info("Ignore backend rest request")
                continue
            if creds:
                self._updateConfStanzas(creds, cred_conf_file, self.encrypt_fields_credential)
        logger.info("edit setup configure is done")

    def _updateGlobalSettings(self, stanza, all_settings,
                              all_origin_settings, conf_file):
        if not self.stanza_map[stanza]:
            return
        global_settings = all_settings.get(stanza, {})
        if self._configChanges(global_settings, all_origin_settings.get(stanza, {})):
            logger.info("global setting stanza [%s] changed", stanza)
            conf_file.update(stanza, global_settings, self.global_cred_fields)

    def _updateConfStanzas(self, all_settings, conf_file, encrypt_fields):
        all_origin_settings = conf_file.get_all()
        if not all_origin_settings:
            all_origin_settings = {}
        for stanza, settings in all_settings.iteritems():
            conf_file.update(stanza, settings, encrypt_fields)
        updated_stanzas = all_settings.keys()
        to_be_deleted_stanzas = [ s for s in all_origin_settings if s not in updated_stanzas ]
        for stanza in to_be_deleted_stanzas:
            conf_file.delete(stanza)

    @staticmethod
    def _clearPasswords(settings, cred_fields):
        for k, val in settings.iteritems():
            if isinstance(val, dict):
                return ConfigApp._clearPasswords(val, cred_fields)
            elif isinstance(val, (str, unicode)):
                if k in cred_fields:
                    settings[k] = ""

    @staticmethod
    def _setNoneValues(stanza):
        for k, v in stanza.iteritems():
            if v is None:
                stanza[k] = ""

    @staticmethod
    def _configChanges(new_config, origin_config):
        for k, v in new_config.iteritems():
            if k in ConfigApp.cred_fields and v == "":
                continue
            if v != origin_config.get(k):
                return True
        return False


admin.init(ConfigApp, admin.CONTEXT_APP_ONLY)
import splunk_ta_paloalto_declare

import json
import os
import splunk.clilib.cli_common as scc
import splunk.admin as admin

import solnlib.utils as utils
import solnlib.conf_manager as conf
import splunk_ta_paloalto_consts as setup_const


'''
Usage Examples:
setup_util = Setup_Util(uri, session_key)
setup_util.get_log_level()
setup_util.get_proxy_settings()
setup_util.get_credential_account("my_account_name")
setup_util.get_customized_setting("my_customized_field_name")
'''


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


class Setup_Util(object):

    def __init__(self, uri, session_key, logger=None):
        self.__uri = uri
        self.__session_key = session_key
        self.__logger = logger
        self.scheme, self.host, self.port = utils.extract_http_scheme_host_port(
            self.__uri)
        self.encrypt_fields_credential = (setup_const.password,)
        self.encrypt_fields_customized = (setup_const.password,)
        self.cred_confs = (
            (setup_const.myta_credential_settings, setup_const.myta_credential_conf),)
        self.__cached_global_settings = None

    def log_error(self, msg):
        if self.__logger:
            self.__logger.error(msg)

    def log_info(self, msg):
        if self.__logger:
            self.__logger.info(msg)

    def log_debug(self, msg):
        if self.__logger:
            self.__logger.debug(msg)

    def _parse_conf(self):
        '''
        return the setting object
        {
            "customized_settings": {
                "mn": {
                    "type": "text",
                    "appName": "TA-abcd",
                    "disabled": false,
                    "content": "zhizihuakai",
                    "name": "mn",
                    "userName": "nobody"
                },
                "jk": {
                    "type": "bool",
                    "appName": "TA-abcd",
                    "bool": "1",
                    "disabled": false,
                    "name": "jk",
                    "userName": "nobody"
                }
            },
            "global_settings": {
                "log_level": "INFO",
                "appName": "TA-abcd",
                "disabled": "0",
                "name": "global_settings",
                "userName": "nobody"
            },
            "proxy_settings": {
                "proxy_password": null,
                "proxy_username": null,
                "disabled": "0",
                "proxy_port": null,
                "proxy_enabled": "0",
                "name": "proxy_settings",
                "appName": "TA-abcd",
                "proxy_rdns": "0",
                "proxy_url": null,
                "proxy_type": "http",
                "userName": "nobody"
            }
        }
        '''
        if setup_const.globalsetting_key in os.environ:
            return self._parse_conf_from_env(os.environ[setup_const.globalsetting_key])
        else:
            return self._parse_conf_from_rest()

    def _parse_conf_from_env(self, settings):
        '''
        this is run in test env
        '''
        if not self.__cached_global_settings:
            global_settings = json.loads(settings)
            # format the settings, the setting from env is from global_setting
            # meta
            self.__cached_global_settings = {}
            CUSTOMIZED_TYPE_MAP = {
                "text": "text",
                "checkbox": "bool",
                "password": "password"
            }
            GLOBAL_SETTING_VALUE_NAME_MAP = {
                "text": "content",
                "bool": "bool",
                "password": "password"
            }
            for s_k, s_v in global_settings.iteritems():
                if 'customized_settings' == s_k:
                    self.__cached_global_settings['customized_settings'] = {}
                    for s in s_v:
                        field_type = CUSTOMIZED_TYPE_MAP.get(
                            s.get('format_type'))
                        if not field_type:
                            self.log_error(
                                'unknown type for customized var:{}'.format(s))
                            continue
                        self.__cached_global_settings['customized_settings'][s.get('name', '')] = {
                            'type': field_type,
                            GLOBAL_SETTING_VALUE_NAME_MAP[field_type]: s.get('value')}
                elif s_k == "log_settings":
                    self.__cached_global_settings["global_settings"] = s_v
                else:
                    self.__cached_global_settings[s_k] = s_v

        return self.__cached_global_settings

    def _parse_conf_from_rest(self):
        conf_mgr = conf.ConfManager(
            self.__session_key, "Splunk_TA_paloalto", scheme=self.scheme, host=self.host, port=self.port)
        ta_conf_file = get_or_create_conf_file(conf_mgr, setup_const.myta_conf)
        credential_conf_file = get_or_create_conf_file(
            conf_mgr, setup_const.myta_credential_conf)
        # read global and proxy settings
        all_settings = ta_conf_file.get_all()
        if not all_settings:
            all_settings = {}
        self._setNoneValues(all_settings.get(setup_const.global_settings, {}))
        # read account credential settings
        for cred, cred_conf in self.cred_confs:
            try:
                cred_conf_file = get_or_create_conf_file(conf_mgr, cred_conf)
                creds_data = cred_conf_file.get_all()
                self._setNoneValues(creds_data)
                all_settings.update({cred: creds_data})
            except conf.ConfManagerException as e:
                self.log_info('Conf {} not found.'.format(cred))
        # read customized settings
        customized_conf_file = get_or_create_conf_file(
            conf_mgr, setup_const.myta_customized_conf)
        settings = customized_conf_file.get_all()
        all_settings[setup_const.myta_customized_settings] = settings

        self._setNoneValues(all_settings.get(
            setup_const.myta_customized_settings, {}))
        return filter_eai_property(all_settings)

    @staticmethod
    def _setNoneValues(stanza):
        for k, v in stanza.iteritems():
            if v is None:
                stanza[k] = ""

    def get_log_level(self):
        log_level = "INFO"
        global_settings = self._parse_conf().get('global_settings', None)
        if not global_settings:
            self.log_info("Log level is not set, use default INFO")
        else:
            log_level = global_settings.get('log_level', None)
            if not log_level:
                self.log_info("Log level is not set, use default INFO")
                log_level = "INFO"
        return log_level

    def get_proxy_settings(self):
        proxy_settings = self._parse_conf().get('proxy_settings', None)
        if not proxy_settings:
            self.log_info("Proxy is not set!")
            return {}
        proxy_enabled = utils.is_true(proxy_settings.get("proxy_enabled", '0'))
        if not proxy_enabled:
            return {}
        proxy_settings = {
            "proxy_url": proxy_settings.get("proxy_url", ""),
            "proxy_port": proxy_settings.get("proxy_port", ""),
            "proxy_username": proxy_settings.get("proxy_username", ""),
            "proxy_password": proxy_settings.get("proxy_password", ""),
            "proxy_type": proxy_settings.get("proxy_type", ""),
            "proxy_rdns": utils.is_true(proxy_settings.get("proxy_rdns", '0'))
        }
        return proxy_settings

    def get_credential_account(self, key):
        credential_settings = self._parse_conf().get('credential_settings', None)
        self.__logger.error(credential_settings)
        if not credential_settings:
            self.__logger.error("Credential account is not set")
            return None
        if not key in credential_settings:
            self.__logger.error("Credential key can not be found")
            return None
        credential_account = credential_settings.get(key, {})
        credential_account = {
            "username": key,
            "password": credential_account.get("password", "")
        }
        return credential_account

    def get_customized_setting(self, key):
        customized_settings = self._parse_conf().get(
            setup_const.myta_customized_settings, None)
        if not customized_settings:
            self.log_info("Customized setting is not set")
            return None
        if not key in customized_settings:
            self.log_info("Customized key can not be found")
            return None
        customized_setting = customized_settings.get(key, {})
        _type = customized_setting.get("type", None)
        if not _type:
            self.__logger.error("Type of this customized setting is not set")
            return None
        if _type == "bool":
            return utils.is_true(customized_setting.get("bool", '0'))
        elif _type == "text":
            return customized_setting.get("content", "")
        elif _type == "password":
            return customized_setting.get("password", "")
        else:
            raise Exception("Type of this customized setting is corrupted")
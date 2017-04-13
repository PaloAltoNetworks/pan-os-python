# encoding = utf-8
import importlib
import copy
import logging
import os
import tempfile

from splunklib import modularinput as smi
from solnlib.log import Logs
from solnlib.modular_input import checkpointer
from solnlib import utils as sutils
import requests


class BaseModInput(smi.Script):
    '''
    This is a modular input wrapper, which provides some helper
    functions to read the paramters from setup pages and the arguments
    from input definition
    '''
    LogLevelMapping = {'debug': logging.DEBUG,
                       'info': logging.INFO,
                       'error': logging.ERROR,
                       'warning': logging.WARNING}

    def __init__(self, app_namespace, input_name):
        super(BaseModInput, self).__init__()
        self._canceled = False
        self.input_name = None
        self.input_stanzas = {}
        self.context_meta = {}
        self.namespace = app_namespace
        # redirect all the logging to one file
        Logs.set_context(namespace=app_namespace,
                         root_logger_log_file=input_name)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.http_session = None
        self.requests_proxy = None
        # check point
        self.ckpt = None
        # try to load the setup util module
        self.setup_util_module = None
        self.setup_util = None
        try:
            self.setup_util_module = importlib.import_module(self.namespace +
                                                             "_setup_util")
        except ImportError as ie:
            self.logger.info("Can not import package:" +
                             self.namespace + "_setup_util")

    @property
    def app(self):
        return self.get_app_name()

    def get_app_name(self):
        raise NotImplemented

    def set_log_level(self, level):
        if isinstance(level, basestring):
            level = level.lower()
            if level in self.LogLevelMapping:
                level = self.LogLevelMapping[level]
            else:
                level = logging.INFO
        self.logger.setLevel(level)

    def log_error(self, msg):
        self.logger.error(msg)

    def log_debug(self, msg):
        self.logger.debug(msg)

    def log_info(self, msg):
        self.logger.info(msg)

    @property
    def proxy(self):
        return self.get_proxy()

    def get_proxy(self):
        ''' if the proxy setting is set. return a dict like
        {
        proxy_url: ... ,
        proxy_port: ... ,
        proxy_username: ... ,
        proxy_password: ... ,
        proxy_type: ... ,
        proxy_rdns: ...
        }
        '''
        if self.setup_util:
            return self.setup_util.get_proxy_settings()
        else:
            return None

    def get_global_setting(self, var_name):
        if self.setup_util:
            return self.setup_util.get_customized_setting(var_name)
        else:
            return None

    def get_user_credential(self, username):
        '''
        if the username exists, return
        {
            "username": username,
            "password": credential
        }
        '''
        if self.setup_util:
            return self.setup_util.get_credential_account(username)
        else:
            return None

    @property
    def log_level(self):
        return self.get_log_level()

    def get_log_level(self):
        if self.setup_util:
            return self.setup_util.get_log_level()
        else:
            return None

    def parse_input_args(self, inputs):
        raise NotImplemented()

    def new_event(self, data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True):
        '''
        :param data: ``string``, the event's text.
        :param time: ``float``, time in seconds, including up to 3 decimal places to represent milliseconds.
        :param host: ``string``, the event's host, ex: localhost.
        :param index: ``string``, the index this event is specified to write to, or None if default index.
        :param source: ``string``, the source of this event, or None to have Splunk guess.
        :param sourcetype: ``string``, source type currently set on this event, or None to have Splunk guess.
        :param done: ``boolean``, is this a complete ``Event``? False if an ``Event`` fragment.
        :param unbroken: ``boolean``, Is this event completely encapsulated in this ``Event`` object?
        '''
        return smi.Event(data=data, time=time, host=host, index=index,
                         source=source, sourcetype=sourcetype, done=done, unbroken=unbroken)

    def stream_events(self, inputs, ew):
        '''
        implement the splunklib modular input
        preprocess the input args
        '''
        # the input metadata is like
        # {
        #     'server_uri': 'https://127.0.0.1:8089',
        #     'server_host': 'localhost',
        #     'checkpoint_dir': '...',
        #     'session_key': 'ceAvf3z^hZHYxe7wjTyTNo6_0ZRpf5cvWPdtSg'
        # }
        self.context_meta = inputs.metadata
        input_definition = smi.input_definition.InputDefinition()
        input_definition.metadata = copy.deepcopy(inputs.metadata)
        input_definition.inputs = copy.deepcopy(inputs.inputs)
        self.parse_input_args(input_definition)
        if not self.input_stanzas:
            # if no stanza found. Just return
            return
        if self.setup_util_module:
            uri = self._input_definition.metadata["server_uri"]
            session_key = self._input_definition.metadata['session_key']
            self.setup_util = self.setup_util_module.Setup_Util(
                uri, session_key, self.logger)
            try:
                self.set_log_level(self.setup_util.get_log_level())
            except:
                self.log_debug('set log level fails.')
        try:
            self.collect_events(inputs, ew)
        except Exception as e:
            import traceback
            self.log_error('Get error when collecting events.\n' + traceback.format_exc(e))
            raise RuntimeError(str(e))

    def collect_events(self, inputs, event_writer):
        '''
        this method should be implemented in subclass
        '''
        raise NotImplemented()

    def get_input_name(self):
        '''
        get input names, if it is single instance modinput, return the name
        it it is multi instance modinput, return a list of names?
        This needs to be check!
        '''
        raise NotImplemented()

    def get_arg(self, arg_name, input_stanza_name=None):
        '''
        get the input argument from the input.conf stanza.
        '''
        raise NotImplemented()

    def get_output_index(self, input_stanza_name=None):
        return self.get_arg('index', input_stanza_name)

    def get_sourcetype(self, input_stanza_name=None):
        return self.get_arg('sourcetype', input_stanza_name)

    def _get_proxy_uri(self):
        '''
        proxy_url: ... ,
        proxy_port: ... ,
        proxy_username: ... ,
        proxy_password: ... ,
        proxy_type: ... ,
        proxy_rdns: ...
        '''
        uri = None
        proxy = self.get_proxy()
        if proxy and proxy.get('proxy_url') and proxy.get('proxy_type'):
            uri = proxy['proxy_url']
            if proxy.get('proxy_port'):
                uri = '{0}:{1}'.format(uri, proxy.get('proxy_port'))
            if proxy.get('proxy_username') and proxy.get('proxy_password'):
                uri = '{0}://{1}:{2}@{3}/'.format(proxy['proxy_type'], proxy[
                                                  'proxy_username'], proxy['proxy_password'], uri)
            else:
                uri = '{0}://{1}'.format(proxy['proxy_type'], uri)
        return uri

    def _init_request_session(self):
        self.http_session = requests.Session()
        self.http_session.mount(
            'http://', requests.adapters.HTTPAdapter(max_retries=3))
        self.http_session.mount(
            'https://', requests.adapters.HTTPAdapter(max_retries=3))
        proxy_uri = self._get_proxy_uri()
        if proxy_uri:
            self.requests_proxy = {'http': proxy_uri, 'https': proxy_uri}
            self.logger.info('set the proxy as %s', self.requests_proxy)

    def send_http_request(self, url, method, parameters=None, payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True):
        if self.http_session is None:
            self._init_request_session()
        requests_args = {'timeout': (10.0, 5.0), 'verify': verify}
        if parameters:
            requests_args['params'] = parameters
        if payload:
            if isinstance(payload, dict):
                requests_args['json'] = payload
            else:
                requests_args['data'] = payload
        if headers:
            requests_args['headers'] = headers
        if cookies:
            requests_args['cookies'] = cookies
        if cert:
            requests_args['cert'] = cookies
        if timeout is not None:
            requests_args['timeout'] = timeout
        if use_proxy and self.requests_proxy:
            requests_args['proxies'] = self.requests_proxy
        return self.http_session.request(method, url, **requests_args)

    def _init_ckpt(self):
        if self.ckpt is None:
            if 'AOB_TEST' in os.environ:
                ckpt_dir = self.context_meta.get('checkpoint_dir', tempfile.mkdtemp())
                if not os.path.exists(ckpt_dir):
                    os.makedirs(ckpt_dir)
                self.ckpt = checkpointer.FileCheckpointer(ckpt_dir)
            else:
                if 'server_uri' not in self.context_meta:
                    raise ValueError('server_uri not found in input meta.')
                if 'session_key' not in self.context_meta:
                    raise ValueError('session_key not found in input meta.')
                dscheme, dhost, dport = sutils.extract_http_scheme_host_port(self.context_meta[
                                                                             'server_uri'])
                self.ckpt = checkpointer.KVStoreCheckpointer(self.app + "_checkpointer", self.context_meta['session_key'], self.app,
                                                             scheme=dscheme, host=dhost, port=dport)

    def get_check_point(self, key):
        if self.ckpt is None:
            self._init_ckpt()
        return self.ckpt.get(key)

    def save_check_point(self, key, state):
        if self.ckpt is None:
            self._init_ckpt()
        self.ckpt.update(key, state)

    def batch_save_check_point(self, states):
        '''
        param: states is a dict, the key is the check point state key, the value is the state
        '''
        if self.ckpt is None:
            self._init_ckpt()
        self.ckpt.batch_update(states)

    def delete_check_point(self, key):
        if self.ckpt is None:
            self._init_ckpt()
        self.ckpt.delete(key)


class SingleInstanceModInput(BaseModInput):

    def __init__(self, app_namespace, input_name):
        super(SingleInstanceModInput, self).__init__(app_namespace, input_name)

    def parse_input_args(self, inputs):
        # the single instance modinput just has one sections
        self.input_name = None
        self.input_stanzas = {}
        while(len(inputs.inputs) > 0):
            input_stanza, stanza_args = inputs.inputs.popitem()
            kind_and_name = input_stanza.split('://')
            if len(kind_and_name) == 2:
                if self.input_name is not None:
                    assert self.input_name == kind_and_name[0]
                self.input_name = kind_and_name[0]
                self.input_stanzas[kind_and_name[1]] = stanza_args

    def get_input_name(self):
        return self.input_name

    def get_arg(self, arg_name, input_stanza_name=None):
        '''
        For single instance modinput, if the input_stanza_name is not given,
        return a dict when there are multiple args in multiple stanzas.
        '''
        if input_stanza_name is None:
            args_dict = {k: args[
                arg_name] for k, args in self.input_stanzas.iteritems() if arg_name in args}
            if len(args_dict) == 1:
                return args_dict.values()[0]
            else:
                return args_dict
        else:
            return self.input_stanzas.get(input_stanza_name, {}).get(arg_name, None)

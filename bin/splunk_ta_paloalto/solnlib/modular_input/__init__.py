# Copyright 2016 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License'): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
Splunk modular input.
'''

from solnlib.modular_input.event import EventException
from solnlib.modular_input.event import XMLEvent
from solnlib.modular_input.event import HECEvent
from solnlib.modular_input.event_writer import ClassicEventWriter
from solnlib.modular_input.event_writer import HECEventWriter
from solnlib.modular_input.checkpointer import CheckpointerException
from solnlib.modular_input.checkpointer import KVStoreCheckpointer
from solnlib.modular_input.checkpointer import FileCheckpointer
from splunklib.modularinput.argument import Argument
from solnlib.modular_input.modular_input import ModularInputException
from solnlib.modular_input.modular_input import ModularInput

__all__ = ['EventException',
           'XMLEvent',
           'HECEvent',
           'ClassicEventWriter',
           'HECEventWriter',
           'CheckpointerException',
           'KVStoreCheckpointer',
           'FileCheckpointer',
           'Argument',
           'ModularInputException',
           'ModularInput']

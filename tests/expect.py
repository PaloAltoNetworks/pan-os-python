# -*- coding: utf-8 -*-

op_show_interfaces_all_empty = {'response': {'result': None }}

op_show_interfaces_all = {'response': {'result': {'hw': {'entry': [{'duplex': 'full',
                                                                    'id': '16',
                                                                    'mac': '00:1b:17:e6:7d:10',
                                                                    'mode': '(autoneg)',
                                                                    'name': 'ethernet1/1',
                                                                    'speed': '10000',
                                                                    'state': 'up',
                                                                    'type': '0'},
                                                                   {'duplex': 'ukn',
                                                                    'id': '17',
                                                                    'mac': '00:1b:17:e6:7d:11',
                                                                    'mode': '(power-down)',
                                                                    'name': 'ethernet1/2',
                                                                    'speed': 'ukn',
                                                                    'state': 'down',
                                                                    'type': '0'}]},
                                                  'ifnet': {'entry': [{'addr': None,
                                                                       'addr6': None,
                                                                       'dyn-addr': None,
                                                                       'fwd': 'vr:default',
                                                                       'id': '16',
                                                                       'ip': '10.5.5.1/24',
                                                                       'name': 'ethernet1/1',
                                                                       'tag': '0',
                                                                       'vsys': '1',
                                                                       'zone': 'untrust'},
                                                                      {'addr': None,
                                                                       'addr6': None,
                                                                       'dyn-addr': None,
                                                                       'fwd': 'vr:default',
                                                                       'id': '17',
                                                                       'ip': '10.6.6.1/24',
                                                                       'name': 'ethernet1/2',
                                                                       'tag': '0',
                                                                       'vsys': '1',
                                                                       'zone': 'trust'}
                                                  ]}}}}
'''
op_show_interfaces_all = """<response status="success">
<result>
<ifnet>
<entry>
<name>ethernet1/1</name>
<zone>untrust</zone>
<fwd>vr:default</fwd>
<vsys>1</vsys>
<dyn-addr/>
<addr6/>
<tag>0</tag>
<ip>10.5.5.1/24</ip>
<id>16</id>
<addr/>
</entry>
<entry>
<name>ethernet1/2</name>
<zone>trust</zone>
<fwd>vr:default</fwd>
<vsys>1</vsys>
<dyn-addr/>
<addr6/>
<tag>0</tag>
<ip>10.6.6.1/24</ip>
<id>17</id>
<addr/>
</entry>
</ifnet>
<hw>
<entry>
<name>ethernet1/1</name>
<duplex>full</duplex>
<type>0</type>
<state>up</state>
<mac>00:1b:17:e6:7d:10</mac>
<mode>(autoneg)</mode>
<speed>10000</speed>
<id>16</id>
</entry>
<entry>
<name>ethernet1/2</name>
<duplex>full</duplex>
<type>0</type>
<state>up</state>
<mac>00:1b:17:e6:7d:11</mac>
<mode>(autoneg)</mode>
<speed>10000</speed>
<id>17</id>
</entry>
</hw>
</result>
</response>"""
'''

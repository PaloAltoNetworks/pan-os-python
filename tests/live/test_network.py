import random

from tests.live import testlib
from pandevice import network


class TestZones(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.Zone(
            testlib.random_name(),
            mode='layer3',
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.mode = 'layer2'

# StaticMac

class TestVlan(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_objs = []

        state.eths = testlib.get_available_interfaces(fw, 2)

        for eth in state.eths:
            state.eth_objs.append(network.EthernetInterface(
                eth, 'layer2'))
            fw.add(state.eth_objs[-1])
            state.eth_objs[-1].create()

    def setup_state_obj(self, fw, state):
        state.obj = network.Vlan(
            testlib.random_name(), state.eths[0],
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.interface = state.eths[1]

    def cleanup_dependencies(self, fw, state):
        for x in state.eth_objs:
            try:
                x.delete()
            except Exception:
                pass

# IPv6Address
# Interface - inherited by other interface objects
# SubinterfaceArp

class TestArpOnEthernetInterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, 'layer3', testlib.random_ip('/24'))
        fw.add(state.eth_obj)
        state.eth_obj.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.Arp(
            testlib.random_ip(), '00:30:48:52:ab:cd')
        state.eth_obj.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.hw_address = '00:30:48:52:12:9a'

    def cleanup_dependencies(self, fw, state):
        try:
            state.eth_obj.delete()
        except Exception:
            pass

class TestVirtualWire(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_objs = []
        state.eths = testlib.get_available_interfaces(fw, 3)

        for eth in state.eths:
            state.eth_objs.append(network.EthernetInterface(
                eth, 'virtual-wire'))
            fw.add(state.eth_objs[-1])
            state.eth_objs[-1].create()

    def setup_state_obj(self, fw, state):
        state.obj = network.VirtualWire(
            testlib.random_name(),
            tag=random.randint(1, 4000),
            interface1=state.eths[0],
            interface2=state.eths[1],
            multicast=True,
            pass_through=False,
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.tag = random.randint(1, 4000)
        state.obj.interface1 = state.eths[1]
        state.obj.interface2 = state.eths[2]
        state.obj.multicast = False
        state.obj.pass_through = True

    def cleanup_dependencies(self, fw, state):
        for x in state.eth_objs:
            try:
                x.delete()
            except Exception:
                pass

# Subinterface - inherited by others
# AbstractSubinterface

class TestL3Subinterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.management_profile = network.ManagementProfile(
            testlib.random_name(), ping=True)
        state.eth = None

        fw.add(state.management_profile)
        state.management_profile.create()

        state.eth = testlib.get_available_interfaces(fw)[0]
        state.parent = network.EthernetInterface(
            state.eth, 'layer3', ip=testlib.random_ip('/24'),
        )
        fw.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        tag = random.randint(1, 4000)
        name = '{0}.{1}'.format(state.eth, tag)
        state.obj = network.Layer3Subinterface(
            name, tag, testlib.random_ip('/24'), False,
            state.management_profile, random.randint(576, 1500),
            True, None, 'This is my subeth',
            random.randint(40, 300), random.randint(60, 300),
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.comment = 'Update the comment'
        state.obj.ip = testlib.random_ip('/24')

    def cleanup_dependencies(self, fw, state):
        try:
            state.management_profile.delete()
        except Exception:
            pass

        try:
            state.parent.delete()
        except Exception:
            pass

class TestL2Subinterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth = None

        state.eth = testlib.get_available_interfaces(fw)[0]
        state.parent = network.EthernetInterface(
            state.eth, 'layer2',
        )
        fw.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        tag = random.randint(1, 4000)
        name = '{0}.{1}'.format(state.eth, tag)
        state.obj = network.Layer2Subinterface(
            name, tag, comment='This is my L2 subinterface',
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.comment = 'Updated comment'

    def cleanup_dependencies(self, fw, state):
        try:
            state.parent.delete()
        except Exception:
            pass

# PhysicalInterface - inherited by others

class TestL3EthernetInterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.management_profiles = []

        state.eth = testlib.get_available_interfaces(fw)[0]
        state.management_profiles = [
            network.ManagementProfile(testlib.random_name(), ping=True,
                                      ssh=True, https=False)
            for x in range(2)
        ]
        for x in state.management_profiles:
            fw.add(x)
            x.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.EthernetInterface(
            state.eth, 'layer3', testlib.random_ip('/24'),
            ipv6_enabled=False,
            management_profile=state.management_profiles[0],
            mtu=random.randint(600, 1500),
            adjust_tcp_mss=True,
            link_speed='auto',
            link_duplex='auto',
            link_state='auto',
            comment='This is my interface',
            ipv4_mss_adjust=random.randint(40, 300),
            ipv6_mss_adjust=random.randint(60, 300),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.management_profile = state.management_profiles[1]
        state.obj.mtu = random.randint(600, 1500)
        state.obj.ipv4_mss_adjust = random.randint(40, 300)
        state.obj.ipv6_mss_adjust = random.randint(60, 300)
        state.obj.comment = 'This is an update layer3 interface'

    def cleanup_dependencies(self, fw, state):
        for x in state.management_profiles:
            try:
                x.delete()
            except Exception:
                pass

class TestL2EthernetInterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.management_profiles = []

        state.eth = testlib.get_available_interfaces(fw)[0]
        state.management_profiles = [
            network.ManagementProfile(testlib.random_name(), ping=True,
                                      ssh=True, https=False)
            for x in range(2)
        ]
        for x in state.management_profiles:
            fw.add(x)
            x.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.EthernetInterface(
            state.eth, 'layer2',
            management_profile=state.management_profiles[0])
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.management_profile = state.management_profiles[1]

    def cleanup_dependencies(self, fw, state):
        for x in state.management_profiles:
            try:
                x.delete()
            except Exception:
                pass

# AggregateInterface
# VlanInterface
# LoopbackInterface
# TunnelInterface

class TestStaticRoute(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.vr = network.VirtualRouter(testlib.random_name())
        fw.add(state.vr)
        state.vr.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.StaticRoute(
            testlib.random_name(),
            destination=testlib.random_ip('/32'),
            nexthop_type='ip-address',
            nexthop=testlib.random_ip(),
            admin_dist=random.randint(10, 240),
            metric=random.randint(1, 65535),
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.destination = testlib.random_ip('/32')
        state.obj.nexthop_type = 'discard'
        state.obj.nexthop = None

    def cleanup_dependencies(self, fw, state):
        try:
            state.vr.delete()
        except Exception:
            pass

# StaticRouteV6

class TestVirtualRouter(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, 'layer3', testlib.random_ip('/24'))
        fw.add(state.eth_obj)
        state.eth_obj.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.VirtualRouter(
            testlib.random_name(),
            interface=state.eth,
            ad_static=random.randint(10, 240),
            ad_static_ipv6=random.randint(10, 240),
            ad_ospf_int=random.randint(10, 240),
            ad_ospf_ext=random.randint(10, 240),
            ad_ospfv3_int=random.randint(10, 240),
            ad_ospfv3_ext=random.randint(10, 240),
            ad_ibgp=random.randint(10, 240),
            ad_ebgp=random.randint(10, 240),
            ad_rip=random.randint(10, 240),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ad_static = random.randint(10, 240)
        state.obj.ad_rip = random.randint(10, 240)

    def cleanup_dependencies(self, fw, state):
        try:
            state.eth_obj.delete()
        except Exception:
            pass

class OspfFlow(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_objs = []
        state.vr = None
        state.eths = testlib.get_available_interfaces(fw, 2)

        for e in state.eths:
            state.eth_objs.append(network.EthernetInterface(
                e, 'layer3', testlib.random_ip('/24')))
            fw.add(state.eth_objs[-1])
            state.eth_objs[-1].create()

        state.vr = network.VirtualRouter(testlib.random_name(), state.eths)
        fw.add(state.vr)
        state.vr.create()

    def cleanup_dependencies(self, fw, state):
        try:
            state.vr.delete()
        except Exception:
            pass

        for e in state.eth_objs:
            try:
                e.delete()
            except Exception:
                pass

class TestRedistributionProfile(OspfFlow):
    def setup_state_obj(self, fw, state):
        some_ip = testlib.random_ip()

        # TODO(gfreeman) - add bgp_filter_* params
        state.obj = network.RedistributionProfile(
            testlib.random_name(),
            priority=random.randint(1, 255),
            action='no-redist',
            filter_type=['ospf', 'static', 'connect'],
            filter_interface=random.choice(state.eths),
            filter_destination=testlib.random_ip(),
            filter_nexthop=testlib.random_ip(),
            ospf_filter_pathtype=('intra-area', 'ext-1'),
            ospf_filter_area=some_ip,
            ospf_filter_tag=some_ip,
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.action = 'redist'
        state.obj.filter_type = ('ospf', 'rip', 'bgp')
        state.obj.ospf_filter_pathtype = ('inter-area', 'ext-2')

# Ospf
# OspfArea
# OspfRange
# OspfNssaExternalRange
# OspfAreaInterface
# OspfNeighbor
# OspfAuthProfile
# OspfAuthProfileMd5
# OspfExportRules

class TestManagementProfile(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.ManagementProfile(
            testlib.random_name(),
            ping=True,
            telnet=False,
            ssh=True,
            http=False,
            http_ocsp=True,
            https=False,
            snmp=True,
            response_pages=False,
            userid_service=True,
            userid_syslog_listener_ssl=False,
            userid_syslog_listener_udp=True,
            permitted_ip=['1.2.3.4', '5.6.7.8'],
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.permitted_ip = ['9.8.7.6', ]
        state.obj.https = True

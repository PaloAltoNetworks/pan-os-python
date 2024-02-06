import random

from panos import device, network
from tests.live import testlib


class TestZoneBasic(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.Zone(
            testlib.random_name(),
            mode="layer3",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.mode = "layer2"


class TestZone(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_objs = []
        state.eths = testlib.get_available_interfaces(fw, 2)

        state.eth_objs.append(network.EthernetInterface(state.eths[0], "layer2"))
        state.eth_objs.append(network.EthernetInterface(state.eths[1], "layer3"))
        for x in state.eth_objs:
            fw.add(x)
        fw.create_type(network.EthernetInterface)

    def setup_state_obj(self, fw, state):
        state.obj = network.Zone(
            testlib.random_name(),
            "layer2",
            state.eths[0],
            enable_user_identification=False,
            include_acl=testlib.random_ip("/24"),
            exclude_acl=testlib.random_ip("/24"),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.mode = "layer3"
        state.obj.interface = state.eths[1]
        state.obj.include_acl = [testlib.random_ip("/24") for x in range(2)]
        state.obj.exclude_acl = [testlib.random_ip("/24") for x in range(2)]

    def cleanup_dependencies(self, fw, state):
        try:
            fw.delete_type(network.EthernetInterface)
        except Exception:
            pass


class TestStaticMac(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.parent = None
        state.eth_objs = []

        state.eths = testlib.get_available_interfaces(fw, 2)

        for eth in state.eths:
            state.eth_objs.append(network.EthernetInterface(eth, "layer2"))
            fw.add(state.eth_objs[-1])
        state.eth_objs[0].create_similar()

        state.parent = network.Vlan(testlib.random_name(), state.eths)
        fw.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.StaticMac(
            testlib.random_mac(),
            state.eths[0],
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.interface = state.eths[1]

    def cleanup_dependencies(self, fw, state):
        try:
            state.parent.delete()
        except Exception:
            pass

        try:
            state.eth_objs[0].delete_similar()
        except Exception:
            pass


class TestVlan(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_objs = []

        state.eths = testlib.get_available_interfaces(fw, 2)

        for eth in state.eths:
            state.eth_objs.append(network.EthernetInterface(eth, "layer2"))
            fw.add(state.eth_objs[-1])
        state.eth_objs[0].create_similar()

        state.vlan_interface = network.VlanInterface(
            "vlan.{0}".format(random.randint(100, 200))
        )
        fw.add(state.vlan_interface)
        state.vlan_interface.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.Vlan(
            testlib.random_name(),
            state.eths[0],
            state.vlan_interface.uid,
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.interface = state.eths[1]

    def cleanup_dependencies(self, fw, state):
        try:
            state.vlan_interface.delete()
        except Exception:
            pass

        try:
            state.eth_objs[0].delete_similar()
        except Exception:
            pass


class TestIPv6AddressOnEthernetInterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.parent = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.parent = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
        fw.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.IPv6Address(
            testlib.random_ipv6(),
            False,
            True,
            False,
            True,
            2420000,
            604800,
            True,
            False,
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable_on_interface = True
        state.obj.prefix = False
        state.obj.anycast = True

    def cleanup_dependencies(self, fw, state):
        try:
            state.parent.delete()
        except Exception:
            pass


class TestIPv6AddressOnLayer3Subinterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj)
        state.eth_obj.create()

        tag = random.randint(1, 4000)
        state.parent = network.Layer3Subinterface(
            "{0}.{1}".format(state.eth, tag), tag, testlib.random_ip("/24")
        )
        state.eth_obj.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.IPv6Address(
            testlib.random_ipv6(),
            False,
            True,
            False,
            True,
            2420000,
            604800,
            True,
            False,
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable_on_interface = True
        state.obj.prefix = False
        state.obj.anycast = True

    def cleanup_dependencies(self, fw, state):
        try:
            state.parent.delete()
        except Exception:
            pass

        try:
            state.eth_obj.delete()
        except Exception:
            pass


# Interface - inherited by other interface objects


class TestArpOnEthernetInterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj)
        state.eth_obj.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.Arp(testlib.random_ip(), "00:30:48:52:ab:cd")
        state.eth_obj.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.hw_address = "00:30:48:52:12:9a"

    def cleanup_dependencies(self, fw, state):
        try:
            state.eth_obj.delete()
        except Exception:
            pass


class TestArpOnSubinterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj)
        state.eth_obj.create()

        tag = random.randint(1, 4000)
        state.parent = network.Layer3Subinterface(
            "{0}.{1}".format(state.eth, tag), tag, testlib.random_ip("/24")
        )
        state.eth_obj.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.Arp(testlib.random_ip(), testlib.random_mac())
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.hw_address = testlib.random_mac()

    def cleanup_dependencies(self, fw, state):
        try:
            state.parent.delete()
        except Exception:
            pass

        try:
            state.eth_obj.delete()
        except Exception:
            pass


class TestVirtualWire(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_objs = []
        state.eths = testlib.get_available_interfaces(fw, 3)

        for eth in state.eths:
            state.eth_objs.append(network.EthernetInterface(eth, "virtual-wire"))
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
            testlib.random_name(), ping=True
        )
        state.eth = None

        fw.add(state.management_profile)
        state.management_profile.create()

        state.eth = testlib.get_available_interfaces(fw)[0]
        state.parent = network.EthernetInterface(
            state.eth,
            "layer3",
            ip=testlib.random_ip("/24"),
        )
        fw.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        tag = random.randint(1, 4000)
        name = "{0}.{1}".format(state.eth, tag)
        state.obj = network.Layer3Subinterface(
            name,
            tag,
            testlib.random_ip("/24"),
            False,
            state.management_profile,
            random.randint(576, 1500),
            True,
            None,
            "This is my subeth",
            random.randint(40, 300),
            random.randint(60, 300),
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.comment = "Update the comment"
        state.obj.ip = testlib.random_ip("/24")

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
            state.eth,
            "layer2",
        )
        fw.add(state.parent)
        state.parent.create()

    def setup_state_obj(self, fw, state):
        tag = random.randint(1, 4000)
        name = "{0}.{1}".format(state.eth, tag)
        state.obj = network.Layer2Subinterface(
            name,
            tag,
            comment="This is my L2 subinterface",
        )
        state.parent.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.comment = "Updated comment"

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
            network.ManagementProfile(testlib.random_name(), ping=bool(x))
            for x in range(2)
        ]
        for x in state.management_profiles:
            fw.add(x)

        state.management_profiles[0].create_similar()

    def setup_state_obj(self, fw, state):
        state.obj = network.EthernetInterface(
            state.eth,
            "layer3",
            testlib.random_ip("/24"),
            ipv6_enabled=False,
            management_profile=state.management_profiles[0],
            mtu=random.randint(600, 1500),
            adjust_tcp_mss=True,
            link_speed="auto",
            link_duplex="auto",
            link_state="auto",
            comment="This is my interface",
            ipv4_mss_adjust=random.randint(40, 300),
            ipv6_mss_adjust=random.randint(60, 300),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.management_profile = state.management_profiles[1]
        state.obj.mtu = random.randint(600, 1500)
        state.obj.ipv4_mss_adjust = random.randint(40, 300)
        state.obj.ipv6_mss_adjust = random.randint(60, 300)
        state.obj.comment = "This is an update layer3 interface"

    def cleanup_dependencies(self, fw, state):
        try:
            state.management_profiles[0].delete_similar()
        except IndexError:
            pass


class TestL2EthernetInterface(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.management_profiles = []

        state.eth = testlib.get_available_interfaces(fw)[0]
        state.management_profiles = [
            network.ManagementProfile(testlib.random_name(), ping=bool(x))
            for x in range(2)
        ]
        for x in state.management_profiles:
            fw.add(x)

        state.management_profiles[0].create_similar()

    def setup_state_obj(self, fw, state):
        state.obj = network.EthernetInterface(
            state.eth, "layer2", management_profile=state.management_profiles[0]
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.management_profile = state.management_profiles[1]

    def cleanup_dependencies(self, fw, state):
        try:
            state.management_profiles[0].delete_similar()
        except IndexError:
            pass


# AggregateInterface


class TestVlanInterface(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.VlanInterface(
            "vlan.{0}".format(random.randint(20, 5000)),
            testlib.random_ip("/24"),
            mtu=random.randint(800, 1000),
            adjust_tcp_mss=True,
            comment="Vlan interface",
            ipv4_mss_adjust=random.randint(100, 200),
            ipv6_mss_adjust=random.randint(100, 200),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ip = None
        state.obj.comment = "Updated vlan"
        state.obj.enable_dhcp = True
        state.obj.create_dhcp_default_route = True
        state.obj.dhcp_default_route_metric = random.randint(50, 200)


class TestLoopbackInterface(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.LoopbackInterface(
            "loopback.{0}".format(random.randint(20, 5000)),
            testlib.random_ip(),
            mtu=random.randint(800, 1000),
            adjust_tcp_mss=True,
            comment="Some loopback interface",
            ipv4_mss_adjust=random.randint(100, 200),
            ipv6_mss_adjust=random.randint(100, 200),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ip = testlib.random_ip()
        state.obj.comment = "Updated loopback"


class TestTunnelInterface(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.TunnelInterface(
            "tunnel.{0}".format(random.randint(20, 5000)),
            testlib.random_ip("/24"),
            mtu=random.randint(800, 1000),
            comment="Underground interface",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ip = testlib.random_ip("/24")
        state.obj.comment = "Updated tunnel"


class TestStaticRoute(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj)
        state.eth_obj.create()

        state.vr = network.VirtualRouter(testlib.random_name(), interface=state.eth)
        fw.add(state.vr)
        state.vr.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.StaticRoute(
            testlib.random_name(),
            testlib.random_ip("/32"),
            "ip-address",
            testlib.random_ip(),
            state.eth,
            random.randint(10, 240),
            random.randint(1, 65535),
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.destination = testlib.random_ip("/32")
        state.obj.nexthop_type = "discard"
        state.obj.nexthop = None
        state.obj.interface = None

    def cleanup_dependencies(self, fw, state):
        try:
            state.vr.delete()
        except Exception:
            pass

        try:
            state.eth_obj.delete()
        except Exception:
            pass


class TestStaticRouteV6(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24"), ipv6_enabled=True
        )
        fw.add(state.eth_obj)
        state.eth_obj.create()

        state.vr = network.VirtualRouter(testlib.random_name(), interface=state.eth)
        fw.add(state.vr)
        state.vr.create()

    def setup_state_obj(self, fw, state):
        ip = testlib.random_ipv6("")
        state.obj = network.StaticRouteV6(
            testlib.random_name(),
            destination=ip + "/64",
            nexthop_type="ipv6-address",
            nexthop=ip + "1",
            interface=state.eth,
            admin_dist=random.randint(100, 200),
            metric=random.randint(1, 65535),
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.destination = testlib.random_ipv6("/64")
        state.obj.nexthop_type = "discard"
        state.obj.nexthop = None
        state.obj.interface = None

    def cleanup_dependencies(self, fw, state):
        try:
            state.vr.delete()
        except Exception:
            pass

        try:
            state.eth_obj.delete()
        except Exception:
            pass


class TestVirtualRouter(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
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


class MakeVirtualRouter(testlib.FwFlow):
    WITH_OSPF = False
    WITH_AREA = False
    WITH_AUTH_PROFILE = False
    WITH_AREA_INTERFACE = False
    WITH_REDISTRIBUTION_PROFILE = False
    WITH_BGP = False
    WITH_BGP_ROUTING_OPTIONS = False
    WITH_BGP_AUTH_PROFILE = False
    WITH_BGP_PEER_GROUP = False
    WITH_BGP_PEER = False
    WITH_BGP_IMPORT_RULE = False
    WITH_BGP_EXPORT_RULE = False
    WITH_RIP = False
    WITH_RIP_AUTH_PROFILE = False
    WITH_RIP_AUTH_PROFILE_MD5 = False
    WITH_RIP_EXPORT_RULES = False
    WITH_RIP_INTERFACE = False

    def create_dependencies(self, fw, state):
        state.eths = testlib.get_available_interfaces(fw, 2)

        state.eth_obj_v4 = network.EthernetInterface(
            state.eths[0], "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj_v4)

        state.eth_obj_v6 = network.EthernetInterface(
            state.eths[1], "layer3", ipv6_enabled=True
        )
        fw.add(state.eth_obj_v6)

        state.eth_obj_v4.create_similar()

        state.vr = network.VirtualRouter(testlib.random_name(), state.eths)
        fw.add(state.vr)
        state.vr.create()

        if self.WITH_REDISTRIBUTION_PROFILE:
            some_ip = testlib.random_ip()

            state.redist_profile = network.RedistributionProfile(
                testlib.random_name(),
                priority=random.randint(1, 255),
                action="no-redist",
                filter_type=["ospf", "static", "connect", "bgp"],
                filter_interface=random.choice(state.eths),
                filter_destination=testlib.random_ip(),
                filter_nexthop=testlib.random_ip(),
                ospf_filter_pathtype=("intra-area", "ext-1"),
                ospf_filter_area=some_ip,
                ospf_filter_tag=some_ip,
            )
            state.vr.add(state.redist_profile)
            state.redist_profile.create()

        if any(
            (
                self.WITH_RIP,
                self.WITH_RIP_AUTH_PROFILE,
                self.WITH_RIP_AUTH_PROFILE_MD5,
                self.WITH_RIP_EXPORT_RULES,
                self.WITH_RIP_INTERFACE,
            )
        ):
            state.rip = network.Rip(
                enable=True,
                reject_default_route=False,
                allow_redist_default_route=True,
                delete_intervals=random.randint(1, 255),
                expire_intervals=random.randint(1, 255),
                interval_seconds=random.randint(1, 60),
                update_intervals=random.randint(1, 255),
            )
            state.vr.add(state.rip)

            if self.WITH_RIP_AUTH_PROFILE:
                state.rip_auth_profile = network.RipAuthProfile(
                    testlib.random_name(),
                    auth_type="password",
                    password=testlib.random_name(),
                )
                state.rip.add(state.rip_auth_profile)

            if self.WITH_RIP_AUTH_PROFILE_MD5:
                state.rip_auth_profile = network.RipAuthProfile(
                    testlib.random_name(), type="md5"
                )
                state.md5 = network.RipAuthProfileMd5(
                    keyid=random.randint(1, 255),
                    key=testlib.random_name(),
                    preferred=True,
                )
                state.rip_auth_profile.add(state.md5)
                state.rip.add(state.rip_auth_profile)

            if self.WITH_RIP_EXPORT_RULES and self.WITH_REDISTRIBUTION_PROFILE:
                state.rip_export_rules = network.RipExportRule(
                    name=str(state.redist_profile), metric=random.randint(1, 15)
                )
                state.rip.add(state.rip_export_rules)

            if self.WITH_RIP_INTERFACE:
                auth_profile = (
                    str(state.rip_auth_profile) if self.WITH_RIP_AUTH_PROFILE else None
                )
                state.rip.add(
                    network.RipInterface(
                        name=state.eths[0],
                        enable=True,
                        advertise_default_route="advertise",
                        metric=random.randint(1, 15),
                        auth_profile=auth_profile,
                        mode="passive",
                    )
                )

            state.rip.create()

        if any(
            (
                self.WITH_OSPF,
                self.WITH_AUTH_PROFILE,
                self.WITH_AREA,
                self.WITH_AREA_INTERFACE,
            )
        ):
            state.ospf = network.Ospf(True, testlib.random_ip())
            state.vr.add(state.ospf)

            if self.WITH_AUTH_PROFILE:
                state.auth = network.OspfAuthProfile(testlib.random_name(), "md5")
                state.ospf.add(state.auth)

            if self.WITH_AREA or self.WITH_AREA_INTERFACE:
                state.area = network.OspfArea(testlib.random_ip())
                state.ospf.add(state.area)

                if self.WITH_AREA_INTERFACE:
                    state.iface = network.OspfAreaInterface(
                        state.eths[0], True, True, "p2mp"
                    )
                    state.area.add(state.iface)

            state.ospf.create()

        if any(
            (
                self.WITH_BGP,
                self.WITH_BGP_ROUTING_OPTIONS,
                self.WITH_BGP_AUTH_PROFILE,
                self.WITH_BGP_PEER_GROUP,
                self.WITH_BGP_PEER,
                self.WITH_BGP_IMPORT_RULE,
                self.WITH_BGP_EXPORT_RULE,
            )
        ):
            state.bgp = network.Bgp(
                enable=True,
                router_id=testlib.random_ip(),
                reject_default_route=True,
                allow_redist_default_route=True,
                install_route=True,
                ecmp_multi_as=True,
                enforce_first_as=True,
                local_as=random.randint(1, 2000),
            )
            state.vr.add(state.bgp)

            if self.WITH_BGP_AUTH_PROFILE:
                state.bgp_auth = network.BgpAuthProfile(testlib.random_name(), "MD5")
                state.bgp.add(state.bgp_auth)
                state.bgp.apply()

            if self.WITH_BGP_ROUTING_OPTIONS:
                state.bgp_opts = network.BgpRoutingOptions(as_format="2-byte")
                state.bgp.add(state.bgp_opts)
                state.bgp.apply()

            if any((self.WITH_BGP_PEER_GROUP, self.WITH_BGP_PEER)):
                state.pg = network.BgpPeerGroup(
                    name=testlib.random_name(),
                    enable=True,
                    aggregated_confed_as_path=True,
                    soft_reset_with_stored_info=True,
                    export_nexthop="resolve",
                    import_nexthop="original",
                    remove_private_as=True,
                )
                state.bgp.add(state.pg)
                state.bgp.apply()

                if self.WITH_BGP_PEER:
                    state.peer = network.BgpPeer(
                        name=testlib.random_name(),
                        enable=True,
                        peer_as=random.randint(1000, 1255),
                        local_interface=state.eths[0],
                        peer_address_ip=testlib.random_ip(),
                    )
                    state.pg.add(state.peer)
                    state.pg.apply()

            if self.WITH_BGP_IMPORT_RULE:
                state.import_rule = network.BgpPolicyImportRule(
                    name=testlib.random_name(),
                    enable=True,
                )
                state.bgp.add(state.import_rule)
                state.bgp.apply()

            if self.WITH_BGP_EXPORT_RULE:
                state.export_rule = network.BgpPolicyExportRule(
                    name=testlib.random_name(),
                    enable=True,
                )
                state.bgp.add(state.export_rule)
                state.bgp.apply()

            state.bgp.create()

    def cleanup_dependencies(self, fw, state):
        try:
            state.vr.delete()
        except Exception:
            pass

        try:
            state.eth_obj_v4.delete_similar()
        except Exception:
            pass


class TestRip(MakeVirtualRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.Rip(
            enable=True,
            reject_default_route=True,
            allow_redist_default_route=True,
            delete_intervals=random.randint(1, 255),
            expire_intervals=random.randint(1, 255),
            interval_seconds=random.randint(1, 60),
            update_intervals=random.randint(1, 255),
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = True
        state.obj.reject_default_route = False
        state.obj.allow_redist_default_route = True
        state.obj.delete_intervals = random.randint(1, 255)
        state.obj.expire_intervals = random.randint(1, 255)
        state.obj.interval_seconds = random.randint(1, 60)
        state.obj.update_intervals = random.randint(1, 255)


class TestRipAuthProfile(MakeVirtualRouter):
    WITH_RIP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RipAuthProfile(
            name=testlib.random_name(),
            auth_type="password",
            password=testlib.random_name(),
        )
        state.rip.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.password = testlib.random_name()


class TestRipAuthProfileMd5(MakeVirtualRouter):
    WITH_RIP_AUTH_PROFILE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RipAuthProfileMd5(keyid="1", key="secret1", preferred=False)
        state.rip_auth_profile.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.preferred = True

    def test_05_add_second_profile_not_preferred(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.rip_auth_profile_md5 = network.RipAuthProfileMd5(
            keyid="1", key="secret2", preferred=False
        )

        state.rip_auth_profile.add(state.rip_auth_profile_md5)
        state.rip_auth_profile_md5.create()


class TestRipInterface(MakeVirtualRouter):
    WITH_RIP = True
    WITH_RIP_AUTH_PROFILE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RipInterface(
            name=state.eths[0],
            enable=True,
            auth_profile=str(state.rip_auth_profile),
            mode="normal",
        )
        state.rip.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = True
        state.obj.advertise_default_route = "advertise"
        state.obj.metric = random.randint(1, 15)
        state.obj.auth_profile = None
        state.obj.mode = "passive"


class TestRipExportRule(MakeVirtualRouter):
    WITH_RIP = True
    WITH_REDISTRIBUTION_PROFILE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RipExportRule(
            name=str(state.redist_profile), metric=random.randint(1, 15)
        )
        state.rip.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.new_path_type = str(state.redist_profile)
        state.obj.metric = random.randint(1, 15)


class TestRedistributionProfile(MakeVirtualRouter):
    def setup_state_obj(self, fw, state):
        some_ip = testlib.random_ip()

        state.obj = network.RedistributionProfile(
            testlib.random_name(),
            priority=random.randint(1, 255),
            action="no-redist",
            filter_type=["ospf", "static", "connect"],
            filter_interface=random.choice(state.eths),
            filter_destination=testlib.random_ip(),
            filter_nexthop=testlib.random_ip(),
            ospf_filter_pathtype=("intra-area", "ext-1"),
            ospf_filter_area=some_ip,
            ospf_filter_tag=some_ip,
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.action = "redist"
        state.obj.filter_type = ("ospf", "rip", "bgp")
        state.obj.ospf_filter_pathtype = ("inter-area", "ext-2")
        state.obj.bgp_filter_community = ("local-as", "no-export")


class TestOspf(MakeVirtualRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.Ospf(
            True,
            testlib.random_ip(),
            True,
            True,
            True,
            2,
            3,
            False,
            300,
            False,
            False,
            400,
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.reject_default_route = False
        state.obj.allow_redist_default_route = False
        state.obj.rfc1583 = False
        state.obj.spf_calculation_delay = 3
        state.obj.lsa_interval = 4
        state.obj.graceful_restart_enable = True
        state.obj.gr_helper_enable = True
        state.obj.gr_strict_lsa_checking = True


class TestOspfArea(MakeVirtualRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfArea(testlib.random_ip(), "normal")
        state.ospf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.type = "stub"
        state.obj.accept_summary = True
        state.obj.default_route_advertise = "disable"

    def test_05_stub_area_with_default_route_advertise(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.default_route_advertise = "advertise"
        state.obj.default_route_advertise_metric = 45

        state.obj.apply()

    def test_06_nssa_area_type_ext1(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.type = "nssa"
        state.obj.default_route_advertise_type = "ext-1"

        state.obj.apply()

    def test_07_nssa_area_type_ext2(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.default_route_advertise_type = "ext-2"

        state.obj.apply()


class TestOspfRange(MakeVirtualRouter):
    WITH_AREA = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfRange(testlib.random_ip(), "advertise")
        state.area.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.mode = "suppress"


class TestOspfNssaExternalRange(MakeVirtualRouter):
    WITH_AREA = True

    def create_dependencies(self, fw, state):
        super(TestOspfNssaExternalRange, self).create_dependencies(fw, state)
        state.area.type = "nssa"
        state.area.apply()

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfNssaExternalRange(testlib.random_ip("/24"), "advertise")
        state.area.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.mode = "suppress"


class TestOspfAreaInterface(MakeVirtualRouter):
    WITH_AREA = True
    WITH_AUTH_PROFILE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfAreaInterface(
            random.choice(state.eths),
            True,
            True,
            "broadcast",
            4096,
            50,
            12,
            3,
            4,
            5,
            6,
            state.auth.uid,
        )
        state.area.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.passive = False
        state.obj.link_type = "p2p"

    def test_05_link_type_p2mp(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.enable = True
        state.obj.link_type = "p2mp"

        state.obj.apply()


class TestOspfNeighbor(MakeVirtualRouter):
    WITH_AREA_INTERFACE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfNeighbor(testlib.random_ip(), 10)
        state.iface.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.metric = 11


class TestOspfAuthProfile(MakeVirtualRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfAuthProfile(testlib.random_name(), "password", "secret")
        state.ospf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.password = "secret2"


class TestOspfAuthProfileMd5(MakeVirtualRouter):
    WITH_AUTH_PROFILE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfAuthProfileMd5("1", "secret1", False)
        state.auth.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.preferred = True

    def test_05_add_second_profile_not_preferred(self, fw, state_map):
        state = self.sanity(fw, state_map)

        o = network.OspfAuthProfileMd5("2", "secret2", False)

        state.auth.add(o)
        o.create()


class TestOspfExportRules(MakeVirtualRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.obj = network.OspfExportRules(
            testlib.random_netmask(), "ext-2", testlib.random_ip(), 2048
        )
        state.ospf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.new_path_type = "ext-1"
        state.obj.metric = 5309


class TestBgp(MakeVirtualRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.Bgp(
            enable=True,
            router_id=testlib.random_ip(),
            reject_default_route=True,
            allow_redist_default_route=True,
            install_route=True,
            ecmp_multi_as=True,
            enforce_first_as=True,
            local_as=random.randint(1, 2000),
        )
        state.vr.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.reject_default_route = False
        state.obj.allow_redist_default_route = False
        state.obj.install_route = False
        state.obj.ecmp_multi_as = False
        state.obj.enforce_first_as = False
        state.obj.local_as = 101


class TestBgpAuthProfile(MakeVirtualRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpAuthProfile(testlib.random_name(), "md5")
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.secret = "sha256"


class TestBgpRoutingOptions(MakeVirtualRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpRoutingOptions(
            as_format="2-byte",
            always_compare_med=True,
            deterministic_med_comparison=True,
            default_local_preference=10,
            graceful_restart_enable=True,
            gr_stale_route_time=10,
            gr_local_restart_time=60,
            gr_max_peer_restart_time=120,
            reflector_cluster_id="192.168.19.104",
            confederation_member_as=random.randint(1, 100),
            aggregate_med=True,
        )
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.as_format = "4-byte"
        state.obj.always_compare_med = False
        state.obj.deterministic_med_comparison = False
        state.obj.default_local_preference = False
        state.obj.graceful_restart_enable = False
        state.obj.gr_stale_route_time = 120
        state.obj.gr_local_restart_time = 60
        state.obj.gr_max_peer_restart_time = 10
        state.obj.reflector_cluster_id = "192.168.19.14"
        state.obj.confederation_member_as = "13634.10467"
        state.obj.aggregate_med = False


# # unsupported configuration, test disabled
# class TestBgpOutboundRouteFilter(MakeVirtualRouter):
#     WITH_BGP_ROUTING_OPTIONS = True

#     def setup_state_obj(self, fw, state):
#         state.obj = network.BgpOutboundRouteFilter(
#             enable = True,
#             max_received_entries = 100,
#             cisco_prefix_mode = False,
#         )
#         state.bgp_opts.add(state.obj)

#     def update_state_obj(self, fw, state):
#         state.obj.enable = False
#         state.obj.max_received_entries = 200
#         state.obj.cisco_prefix_mode = True


class TestBgpDampeningProfile(MakeVirtualRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpDampeningProfile(
            name=testlib.random_name(),
            enable=True,
            cutoff=random.randint(1, 3),
            reuse=random.random(),
            max_hold_time=random.randint(1, 3600),
            decay_half_life_reachable=random.randint(1, 3600),
            decay_half_life_unreachable=random.randint(1, 3600),
        )
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.cutoff = random.randint(1, 3)
        state.obj.reuse = random.random()
        state.obj.max_hold_time = random.randint(1, 3600)
        state.obj.decay_half_life_reachable = random.randint(1, 3600)
        state.obj.decay_half_life_unreachable = random.randint(1, 3600)


class TestBgpPeerGroup(MakeVirtualRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpPeerGroup(
            name=testlib.random_name(),
            enable=True,
            aggregated_confed_as_path=True,
            soft_reset_with_stored_info=True,
            # # 'type'='ebgp',
            export_nexthop="resolve",
            import_nexthop="original",
            remove_private_as=True,
        )
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.aggregated_confed_as_path = False
        state.obj.soft_reset_with_stored_info = False
        state.obj.export_nexthop = "use-self"
        state.obj.import_nexhop = "use-peer"
        state.obj.remove_private_as = False


class TestBgpPeer(MakeVirtualRouter):
    WITH_BGP = True
    WITH_BGP_AUTH_PROFILE = True
    WITH_BGP_PEER_GROUP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpPeer(
            name=testlib.random_name(),
            enable=True,
            peer_as=random.randint(1000, 1255),
            enable_mp_bgp=False,
            address_family_identifier="ipv4",
            subsequent_address_unicast=True,
            subsequent_address_multicast=False,
            local_interface=state.eths[0],
            peer_address_ip=testlib.random_ip(),
            connection_authentication=state.bgp_auth.name,
            connection_keep_alive_interval=random.randint(25, 35),
            connection_min_route_adv_interval=random.randint(25, 35),
            connection_multihop=0,
            connection_open_delay_time=0,
            connection_hold_time=random.randint(85, 95),
            connection_idle_hold_time=random.randint(5, 15),
            connection_incoming_allow=True,
            connection_outgoing_allow=True,
            connection_incoming_remote_port=0,
            connection_outgoing_local_port=0,
            enable_sender_side_loop_detection=True,
            reflector_client="non-client",
            peering_type="unspecified",
            # aggregated_confed_as_path=True,
            max_prefixes=random.randint(4000, 6000),
            # max_orf_entries=random.randint(4000, 6000),
            # soft_reset_with_stored_info=True,
            bfd_profile="Inherit-vr-global-setting",
        )
        state.pg.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.peer_as = random.randint(1000, 1255)
        state.obj.enable_mp_bgp = True
        state.obj.subsequent_address_multicast = True
        state.obj.subsequent_address_unicast = False
        state.obj.enable_mp_bgp = True
        state.obj.local_interface = state.eths[1]
        state.obj.connection_authentication = None
        state.obj.connection_keep_alive_interval = random.randint(1, 1200)
        state.obj.connection_min_route_adv_interval = random.randint(1, 600)
        state.obj.connection_multihop = random.randint(0, 255)
        state.obj.connection_open_delay_time = random.randint(0, 240)
        state.obj.connection_hold_time = random.randint(3, 3600)
        state.obj.connection_idle_hold_time = random.randint(1, 3600)
        state.obj.connection_incoming_allow = False
        state.obj.connection_outgoing_allow = False
        state.obj.connection_incoming_remote_port = random.randint(1025, 65535)
        state.obj.connection_outgoing_local_port = random.randint(1025, 65535)
        state.obj.enable_sender_side_loop_detection = False
        state.obj.reflector_client = "client"
        state.obj.peering_type = "bilateral"
        # state.obj.aggregated_confed_as_path=False
        state.obj.max_prefixes = random.randint(4000, 6000)
        # state.obj.max_orf_entries=random.randint(4000, 6000)
        # state.obj.soft_reset_with_stored_info=False
        state.obj.bfd_profile = None


class MakeBgpPolicyRule(MakeVirtualRouter):
    WITH_BGP = True
    WITH_BGP_PEER = True
    WITH_BGP_PEER_GROUP = True
    USE_IMPORT_RULE = False
    USE_EXPORT_RULE = False

    def setup_state_obj(self, fw, state):
        rule_spec = {
            "name": testlib.random_name(),
            "enable": True,
            "used_by": state.pg.name,
            # match_afi/match_safi are unsupported for testing
            # 'match_afi': 'ip',
            # 'match_safi': 'ip',
            "match_route_table": "unicast",
            "match_nexthop": [
                testlib.random_ip("/32"),
            ],
            "match_from_peer": state.peer.name,
            "match_med": random.randint(0, 4294967295),
            "match_as_path_regex": "as-path-regex",
            "match_community_regex": "community-regex",
            "match_extended_community_regex": "ext-comm-regex",
            "action": "allow",
            "action_local_preference": random.randint(0, 4294967295),
            "action_med": random.randint(0, 4294967295),
            "action_nexthop": testlib.random_ip(),
            "action_origin": "incomplete",
            "action_as_path_limit": random.randint(1, 255),
            "action_as_path_type": "none",
        }
        if self.USE_IMPORT_RULE:
            state.obj = network.BgpPolicyImportRule(**rule_spec)
        elif self.USE_EXPORT_RULE:
            state.obj = network.BgpPolicyExportRule(**rule_spec)

        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.match_route_table = "both"
        state.obj.match_nexthop = [
            testlib.random_ip("/32"),
        ]
        state.obj.match_from_peer = None
        state.obj.match_med = random.randint(0, 4294967295)
        state.obj.match_as_path_regex = "updated-as-path-regex"
        state.obj.match_community_regex = "updated-community-regex"
        state.obj.match_extended_community_regex = "updated-ext-comm-regex"
        state.obj.action_local_preference = random.randint(0, 4294967295)
        state.obj.action_med = random.randint(0, 4294967295)
        state.obj.action_nexthop = testlib.random_ip()
        state.obj.action_origin = "incomplete"
        state.obj.action_as_path_limit = random.randint(1, 255)
        state.obj.action_as_path_type = "none"

    def test_05_action_community_regex_argument(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.action = "allow"
        state.obj.action_community_type = "remove-regex"
        state.obj.action_community_argument = "test-regex"

        state.obj.apply()

    def test_06_action_extended_community_regex_argument(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.action = "allow"
        state.obj.action_extended_community_type = "remove-regex"
        state.obj.action_extended_community_argument = "test-regex"

        state.obj.apply()

    def test_07_action_deny(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.action = "deny"

        state.obj.apply()


class TestBgpPolicyImportRule(MakeBgpPolicyRule):
    USE_IMPORT_RULE = True
    """Define any Import specific tests here"""


class TestBgpPolicyExportRule(MakeBgpPolicyRule):
    USE_EXPORT_RULE = True
    """Define any Export specific tests here"""


class MakeBgpPolicyAddressPrefix(MakeVirtualRouter):
    WITH_BGP = True
    WITH_BGP_IMPORT_RULE = False
    WITH_BGP_EXPORT_RULE = False

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpPolicyAddressPrefix(
            name=testlib.random_netmask(),
            exact=True,
        )
        if self.WITH_BGP_IMPORT_RULE:
            state.import_rule.add(state.obj)
        elif self.WITH_BGP_EXPORT_RULE:
            state.export_rule.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.exact = False

    def test_05_multiple_prefixes(self, fw, state_map):
        state = self.sanity(fw, state_map)

        prefixes = [
            network.BgpPolicyAddressPrefix(
                name=testlib.random_netmask(), exact=random.choice([True, False])
            )
            for x in range(2)
        ]

        if self.WITH_BGP_IMPORT_RULE:
            state.import_rule.extend(prefixes)
            state.import_rule.apply()
        elif self.WITH_BGP_EXPORT_RULE:
            state.export_rule.extend(prefixes)
            state.export_rule.apply()


class TestBgpPolicyImportRuleAddressPrefix(MakeBgpPolicyAddressPrefix):
    WITH_BGP_IMPORT_RULE = True


class TestBgpPolicyExportRuleAddressPrefix(MakeBgpPolicyAddressPrefix):
    WITH_BGP_EXPORT_RULE = True


class TestBgpPolicyConditionalAdvertisement(MakeVirtualRouter):
    WITH_BGP = True
    WITH_BGP_PEER = True
    WITH_BGP_PEER_GROUP = True

    def setup_state_obj(self, fw, state):
        prefixes = [
            network.BgpPolicyAddressPrefix(name=testlib.random_netmask())
            for x in range(2)
        ]

        non_exist = network.BgpPolicyNonExistFilter(
            name=testlib.random_name(), enable=False
        )
        non_exist.extend(prefixes)
        advert = network.BgpPolicyAdvertiseFilter(
            name=testlib.random_name(), enable=False
        )
        advert.extend(prefixes)
        state.obj = network.BgpPolicyConditionalAdvertisement(
            name=testlib.random_name(),
            enable=True,
            used_by=state.pg.name,
        )
        state.obj.add(non_exist)
        state.obj.add(advert)
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.used_by = None


class TestBgpPolicyAggregationAddress(MakeVirtualRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        prefixes = [
            network.BgpPolicyAddressPrefix(
                name=testlib.random_netmask(), exact=random.choice([True, False])
            )
            for x in range(2)
        ]

        suppress = network.BgpPolicySuppressFilter(
            name=testlib.random_name(), enable=False
        )
        suppress.extend(prefixes)
        advert = network.BgpPolicyAdvertiseFilter(
            name=testlib.random_name(), enable=False
        )
        advert.extend(prefixes)
        state.obj = network.BgpPolicyAggregationAddress(
            name=testlib.random_name(),
            enable=True,
            prefix=testlib.random_netmask(),
            summary=False,
        )
        state.obj.add(suppress)
        state.obj.add(advert)
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False
        state.obj.prefix = testlib.random_netmask()
        state.obj.summary = True

    def test_05_attributes(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.enable = True
        state.obj.prefix = testlib.random_netmask()
        state.obj.summary = True
        state.obj.as_set = True
        state.obj.attr_local_preference = random.randint(0, 4294967295)
        state.obj.attr_med = random.randint(0, 4294967295)
        state.obj.attr_nexthop = testlib.random_ip()
        state.obj.attr_origin = "incomplete"
        state.obj.attr_as_path_limit = random.randint(1, 255)
        state.obj.attr_as_path_type = "none"


class TestBgpRedistributionRule(MakeVirtualRouter):
    WITH_BGP = True
    WITH_REDISTRIBUTION_PROFILE = True

    def setup_state_obj(self, fw, state):
        state.obj = network.BgpRedistributionRule(
            name=state.redist_profile.name,
            enable=True,
            address_family_identifier="ipv4",
        )
        state.bgp.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False


class TestAreEnableAdvancedRoutingEngine(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        advanced_routing_engine = device.AdvancedRoutingEngine(enable=True)
        state.obj = advanced_routing_engine
        fw.add(state.obj)


class TestAreLogicalRouter(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.advanced_routing_engine_obj = device.AdvancedRoutingEngine(enable=True)
        fw.add(state.advanced_routing_engine_obj)
        state.advanced_routing_engine_obj.create()

        state.eth_obj = None
        state.eth = testlib.get_available_interfaces(fw)[0]

        state.eth_obj = network.EthernetInterface(
            state.eth, "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj)
        state.eth_obj.create()

    def setup_state_obj(self, fw, state):
        vrf = network.Vrf(
            "default",
            interface=state.eth,
            ad_static=random.randint(10, 240),
            ad_static_ipv6=random.randint(10, 240),
            ad_ospf_inter=random.randint(10, 240),
            ad_ospf_intra=random.randint(10, 240),
            ad_ospf_ext=random.randint(10, 240),
            ad_ospfv3_inter=random.randint(10, 240),
            ad_ospfv3_intra=random.randint(10, 240),
            ad_ospfv3_ext=random.randint(10, 240),
            ad_bgp_internal=random.randint(10, 240),
            ad_bgp_external=random.randint(10, 240),
            ad_bgp_local=random.randint(10, 240),
            ad_rip=random.randint(10, 240),
            bgp_enable=True,
            bgp_router_id="11.22.33.44",
            bgp_local_as=64512,
            bgp_install_route=True,
        )
        lr = network.LogicalRouter(testlib.random_name())
        lr.add(vrf)
        state.obj = lr
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ad_static = random.randint(10, 240)
        state.obj.ad_rip = random.randint(10, 240)

    def cleanup_dependencies(self, fw, state):
        try:
            state.eth_obj.delete()
            state.advanced_routing_engine_obj.delete()
        except Exception:
            pass


class MakeLogicalRouter(testlib.FwFlow):
    WITH_OSPF = False
    WITH_BGP = False

    def create_dependencies(self, fw, state):
        state.advanced_routing_engine_obj = device.AdvancedRoutingEngine(enable=True)
        fw.add(state.advanced_routing_engine_obj)
        state.advanced_routing_engine_obj.create()

        state.eths = testlib.get_available_interfaces(fw, 2)

        state.eth_obj_v4 = network.EthernetInterface(
            state.eths[0], "layer3", testlib.random_ip("/24")
        )
        fw.add(state.eth_obj_v4)

        state.eth_obj_v6 = network.EthernetInterface(
            state.eths[1], "layer3", ipv6_enabled=True
        )
        fw.add(state.eth_obj_v6)

        state.eth_obj_v4.create_similar()

        if self.WITH_BGP:
            state.bgp_local_as = random.randint(64500, 64550)
            state.vrf = network.Vrf(
                "default",
                interface=[state.eth_obj_v4, state.eth_obj_v6],
                ad_static=random.randint(10, 240),
                ad_static_ipv6=random.randint(10, 240),
                ad_ospf_inter=random.randint(10, 240),
                ad_ospf_intra=random.randint(10, 240),
                ad_ospf_ext=random.randint(10, 240),
                ad_ospfv3_inter=random.randint(10, 240),
                ad_ospfv3_intra=random.randint(10, 240),
                ad_ospfv3_ext=random.randint(10, 240),
                ad_bgp_internal=random.randint(10, 240),
                ad_bgp_external=random.randint(10, 240),
                ad_bgp_local=random.randint(10, 240),
                ad_rip=random.randint(10, 240),
                bgp_enable=True,
                bgp_router_id=testlib.random_ip(),
                bgp_local_as=state.bgp_local_as,
                bgp_install_route=True,
            )
        elif self.WITH_OSPF:
            state.vrf = network.Vrf(
                "default",
                interface=[state.eth_obj_v4, state.eth_obj_v6],
                ad_static=random.randint(10, 240),
                ad_static_ipv6=random.randint(10, 240),
                ad_ospf_inter=random.randint(10, 240),
                ad_ospf_intra=random.randint(10, 240),
                ad_ospf_ext=random.randint(10, 240),
                ad_ospfv3_inter=random.randint(10, 240),
                ad_ospfv3_intra=random.randint(10, 240),
                ad_ospfv3_ext=random.randint(10, 240),
                ad_bgp_internal=random.randint(10, 240),
                ad_bgp_external=random.randint(10, 240),
                ad_bgp_local=random.randint(10, 240),
                ad_rip=random.randint(10, 240),
                ospf_enable=True,
                ospf_router_id=testlib.random_ip(),
                ospfv3_enable=True,
                ospfv3_router_id=testlib.random_ip(),
            )
        else:
            state.vrf = network.Vrf(
                "default",
                interface=[state.eth_obj_v4, state.eth_obj_v6],
                ad_static=random.randint(10, 240),
                ad_static_ipv6=random.randint(10, 240),
                ad_ospf_inter=random.randint(10, 240),
                ad_ospf_intra=random.randint(10, 240),
                ad_ospf_ext=random.randint(10, 240),
                ad_ospfv3_inter=random.randint(10, 240),
                ad_ospfv3_intra=random.randint(10, 240),
                ad_ospfv3_ext=random.randint(10, 240),
                ad_bgp_internal=random.randint(10, 240),
                ad_bgp_external=random.randint(10, 240),
                ad_bgp_local=random.randint(10, 240),
                ad_rip=random.randint(10, 240),
            )
        state.lr = network.LogicalRouter(testlib.random_name())
        state.lr.add(state.vrf)
        fw.add(state.lr)
        state.lr.create()

        if self.WITH_BGP:
            state.bgp_address_family_ipv4_name = testlib.random_name()
            state.bgp_address_family_ipv4 = network.RoutingProfileBgpAddressFamily(
                state.bgp_address_family_ipv4_name,
                afi="ipv4",
                unicast_enable=True,
                unicast_soft_reconfig_with_stored_info=True,
                unicast_add_path_tx_all_paths=True,
                unicast_add_path_tx_bestpath_per_as=True,
                unicast_as_override=True,
                unicast_route_reflector_client=True,
                unicast_default_originate=True,
                unicast_allowas_in="occurrence",
                unicast_allowas_in_occurrence=10,
                unicast_maximum_prefix_num_prefixes=900,
                unicast_maximum_prefix_threshold=60,
                unicast_maximum_prefix_action="restart",
                unicast_maximum_prefix_action_restart_interval=15,
                unicast_next_hop="self",
                unicast_remove_private_as="all",
                unicast_send_community="both",
                unicast_orf="none",
                multicast_enable=False,
                multicast_soft_reconfig_with_stored_info=False,
                multicast_add_path_tx_all_paths=False,
                multicast_add_path_tx_bestpath_per_as=False,
                multicast_as_override=False,
                multicast_route_reflector_client=False,
                multicast_default_originate=False,
                multicast_allowas_in="origin",
                multicast_maximum_prefix_num_prefixes=800,
                multicast_maximum_prefix_threshold=50,
                multicast_maximum_prefix_action="warning-only",
                multicast_next_hop="self-force",
                multicast_remove_private_as="replace-AS",
                multicast_send_community="extended",
                multicast_orf="receive",
            )
            fw.add(state.bgp_address_family_ipv4)
            state.bgp_address_family_ipv4.create()

    def cleanup_dependencies(self, fw, state):
        try:
            state.lr.delete()
            state.bgp_address_family_ipv4.delete()
        except Exception:
            pass

        try:
            state.eth_obj_v4.delete_similar()
            state.eth_obj_v6.delete_similar()
            state.advanced_routing_engine_obj.delete()
        except Exception:
            pass


class TestAreVrfStaticRoute(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.VrfStaticRoute(
            name=testlib.random_name(),
            destination=testlib.random_netmask(),
            nexthop_type="ip-address",
            nexthop=testlib.random_ip(),
            interface=state.eths[0],
            admin_dist="10",
            metric="1",
        )
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.destination = testlib.random_netmask()


class TestAreVrfStaticRouteV6(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.VrfStaticRouteV6(
            name=testlib.random_name(),
            destination="2001:db9:abcd:0012::0/64",
            nexthop_type="ipv6-address",
            nexthop=testlib.random_ipv6(),
            interface=state.eths[1],
            admin_dist="10",
            metric="1",
        )
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.nexthop = testlib.random_ipv6()


class TestAreVrfBgpPeerGroup(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.VrfBgpPeerGroup(
            name=testlib.random_name(),
            enable=True,
            address_family_ipv4=state.bgp_address_family_ipv4_name,
        )
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.enable = False


class TestAreVrfBgpPeer(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.VrfBgpPeerGroup(
            name=testlib.random_name(),
            enable=True,
            type="ibgp",
            address_family_ipv4=state.bgp_address_family_ipv4_name,
        )
        state.bgp_peer = network.VrfBgpPeer(
            name=testlib.random_name(),
            peer_as=state.bgp_local_as,
            local_address_interface=state.eths[0],
            peer_address_type="fqdn",
            peer_address_value="peer-test.example.com",
        )
        state.obj.add(state.bgp_peer)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.bgp_peer.peer_address_value = "changed-peer-test.example.com"


class TestAreVrfEcmpInterfaceWeight(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.VrfEcmpInterfaceWeight(
            state.eths[0], weight=random.randint(100, 200)
        )
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.weight = random.randint(100, 200)


class TestAreRoutingProfileBfd(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBfd(
            name=testlib.random_name(),
            mode="passive",
            min_tx_interval=random.randint(300, 400),
            min_received_ttl=random.randint(100, 200),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.min_tx_interval = random.randint(300, 400)


class TestAreRoutingProfileBgpAuth(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBgpAuth(
            name=testlib.random_name(),
            secret=testlib.random_name(),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.secret = testlib.random_name()


class TestAreRoutingProfileBgpTimer(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBgpTimer(
            testlib.random_name(),
            keep_alive_interval=random.randint(1, 60),
            hold_time=random.randint(100, 150),
            reconnect_retry_interval=random.randint(10, 60),
            open_delay_time=random.randint(10, 60),
            min_route_adv_interval=random.randint(10, 60),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.hold_time = random.randint(100, 150)


class TestAreRoutingProfileBgpAddressFamily(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBgpAddressFamily(
            testlib.random_name(),
            afi="ipv4",
            unicast_enable=True,
            unicast_soft_reconfig_with_stored_info=True,
            unicast_add_path_tx_all_paths=True,
            unicast_add_path_tx_bestpath_per_as=True,
            unicast_as_override=True,
            unicast_route_reflector_client=True,
            unicast_default_originate=True,
            unicast_allowas_in="occurrence",
            unicast_allowas_in_occurrence=random.randint(1, 10),
            unicast_maximum_prefix_num_prefixes=random.randint(700, 900),
            unicast_maximum_prefix_threshold=random.randint(10, 60),
            unicast_maximum_prefix_action="restart",
            unicast_maximum_prefix_action_restart_interval=random.randint(10, 60),
            unicast_next_hop="self",
            unicast_remove_private_as="all",
            unicast_send_community="both",
            unicast_orf="none",
            multicast_enable=False,
            multicast_soft_reconfig_with_stored_info=False,
            multicast_add_path_tx_all_paths=False,
            multicast_add_path_tx_bestpath_per_as=False,
            multicast_as_override=False,
            multicast_route_reflector_client=False,
            multicast_default_originate=False,
            multicast_allowas_in="origin",
            multicast_maximum_prefix_num_prefixes=random.randint(700, 900),
            multicast_maximum_prefix_threshold=random.randint(10, 60),
            multicast_maximum_prefix_action="warning-only",
            multicast_next_hop="self-force",
            multicast_remove_private_as="replace-AS",
            multicast_send_community="extended",
            multicast_orf="receive",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.unicast_allowas_in_occurrence = random.randint(1, 10)


class TestAreRoutingProfileBgpDampening(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBgpDampening(
            testlib.random_name(),
            half_life=random.randint(10, 45),
            reuse_limit=random.randint(700, 900),
            suppress_limit=random.randint(1000, 2000),
            max_suppress_limit=random.randint(10, 60),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.reuse_limit = random.randint(700, 900)


class TestAreRoutingProfileBgpRedistribution(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBgpRedistribution(
            testlib.random_name(),
            static_enable=True,
            static_metric=random.randint(65300, 65500),
            connected_enable=True,
            connected_metric=random.randint(100, 120),
            ospf_enable=True,
            ospf_metric=random.randint(47000, 50000),
            rip_enable=True,
            rip_metric=random.randint(12000, 15000),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.static_metric = random.randint(65300, 65500)


class TestAreRoutingProfileBgpFiltering(MakeLogicalRouter):
    WITH_BGP = True

    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileBgpFiltering(
            testlib.random_name(), description="IPv4 profile"
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.description = "Updated IPv4 profile"


class TestAreVrfOspfArea(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.obj = network.VrfOspfArea(testlib.random_ip(), type="normal")
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.type = "stub"


class TestAreVrfOspfAreaRange(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.ospf_area_range = network.VrfOspfAreaRange(
            testlib.random_netmask(),
            substitute=testlib.random_netmask(),
            advertise="false",
        )
        state.obj = network.VrfOspfArea(testlib.random_ip(), type="normal")
        state.obj.add(state.ospf_area_range)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.ospf_area_range.substitute = testlib.random_netmask()


class TestAreVrfOspfAreaInterface(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.ospf_area_interface = network.VrfOspfAreaInterface(
            state.eths[0],
            metric=random.randint(10, 50),
            mtu_ignore=True,
            passive=True,
            priority=2,
        )
        state.obj = network.VrfOspfArea(testlib.random_ip(), type="normal")
        state.obj.add(state.ospf_area_interface)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.ospf_area_interface.metric = random.randint(10, 50)


class TestAreVrfOspfAreaVirtualLink(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.ospf_area_id = testlib.random_ip()
        state.ospf_are_virtual_link = network.VrfOspfAreaVirtualLink(
            testlib.random_name(),
            enable=True,
            neighbor_id=testlib.random_ip(),
            transit_area_id=state.ospf_area_id,
        )
        state.obj = network.VrfOspfArea(state.ospf_area_id, type="normal")
        state.obj.add(state.ospf_are_virtual_link)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.ospf_are_virtual_link.neighbor_id = testlib.random_ip()


class TestAreVrfOspfv3Area(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.obj = network.VrfOspfv3Area(testlib.random_ip(), type="normal")
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.type = "stub"


class TestAreVrfOspfv3AreaRange(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.ospf_area_range = network.VrfOspfv3AreaRange(
            testlib.random_ipv6(ending="/64"),
            substitute=testlib.random_ipv6(ending="/64"),
            advertise="false",
        )
        state.obj = network.VrfOspfv3Area(testlib.random_ip(), type="normal")
        state.obj.add(state.ospf_area_range)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.ospf_area_range.substitute = testlib.random_netmask()


class TestAreVrfOspfv3AreaInterface(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.ospf_area_interface = network.VrfOspfv3AreaInterface(
            state.eths[1],
            metric=random.randint(10, 50),
            mtu_ignore=True,
            passive=True,
            priority=2,
        )
        state.obj = network.VrfOspfv3Area(testlib.random_ip(), type="normal")
        state.obj.add(state.ospf_area_interface)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.ospf_area_interface.metric = random.randint(10, 50)


class TestAreVrfOspfv3AreaVirtualLink(MakeLogicalRouter):
    WITH_OSPF = True

    def setup_state_obj(self, fw, state):
        state.ospf_area_id = testlib.random_ip()
        state.ospf_are_virtual_link = network.VrfOspfv3AreaVirtualLink(
            testlib.random_name(),
            enable=True,
            neighbor_id=testlib.random_ip(),
            transit_area_id=state.ospf_area_id,
        )
        state.obj = network.VrfOspfv3Area(state.ospf_area_id, type="normal")
        state.obj.add(state.ospf_are_virtual_link)
        state.vrf.add(state.obj)

    def update_state_obj(self, fw, state):
        state.ospf_are_virtual_link.neighbor_id = testlib.random_ip()


class TestAreRoutingProfileOspfAuth(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfAuth(
            testlib.random_name(), password=testlib.random_name(8)
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.password = testlib.random_name(8)


class TestAreRoutingProfileOspfIfTimer(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfIfTimer(
            testlib.random_name(),
            hello_interval=random.randint(1, 50),
            dead_counts=random.randint(3, 20),
            retransmit_interval=random.randint(1, 50),
            transit_delay=random.randint(1, 50),
            gr_delay=random.randint(1, 10),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.hello_interval = random.randint(1, 50)


class TestAreRoutingProfileOspfSpfTimer(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfSpfTimer(
            testlib.random_name(),
            lsa_interval=random.randint(1, 10),
            spf_calculation_delay=random.randint(1, 50),
            initial_hold_time=random.randint(1, 50),
            max_hold_time=random.randint(1, 50),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.lsa_interval = random.randint(1, 10)


class TestAreRoutingProfileOspfRedistribution(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfRedistribution(
            testlib.random_name(),
            static="static",
            static_enable=True,
            static_metric=random.randint(1, 50),
            static_metric_type="type-2",
            connected="connected",
            connected_enable=True,
            connected_metric=2,
            rip="rip",
            rip_enable=True,
            rip_metric=random.randint(100, 200),
            rip_metric_type="type-2",
            bgp="bgp",
            bgp_enable=True,
            bgp_metric=random.randint(300, 500),
            bgp_metric_type="type-1",
            default_route="default-route",
            default_route_always=False,
            default_route_enable=True,
            default_route_metric=77,
            default_route_metric_type="type-2",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.static_metric = random.randint(1, 50)


class TestAreRoutingProfileOspfv3Auth(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfv3Auth(
            testlib.random_name(),
            spi="01234568",
            protocol="ah",
            ah_type="sha384",
            ah_key="123",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ah_key = "456"


class TestAreRoutingProfileOspfv3IfTimer(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfv3IfTimer(
            testlib.random_name(),
            hello_interval=random.randint(1, 50),
            dead_counts=random.randint(3, 20),
            retransmit_interval=random.randint(1, 50),
            transit_delay=random.randint(1, 50),
            gr_delay=random.randint(1, 10),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.hello_interval = random.randint(1, 50)


class TestAreRoutingProfileOspfv3SpfTimer(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfv3SpfTimer(
            testlib.random_name(),
            lsa_interval=random.randint(1, 10),
            spf_calculation_delay=random.randint(1, 50),
            initial_hold_time=random.randint(1, 50),
            max_hold_time=random.randint(1, 10),
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.lsa_interval = random.randint(1, 10)


class TestAreRoutingProfileOspfv3Redistribution(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileOspfv3Redistribution(
            testlib.random_name(),
            static="static",
            static_enable=True,
            static_metric=random.randint(1, 50),
            static_metric_type="type-2",
            connected="connected",
            connected_enable=True,
            connected_metric=2,
            bgp="bgp",
            bgp_enable=True,
            bgp_metric=random.randint(100, 500),
            bgp_metric_type="type-1",
            default_route="default-route",
            default_route_always=False,
            default_route_enable=True,
            default_route_metric=random.randint(60, 90),
            default_route_metric_type="type-2",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.static_metric = random.randint(1, 50)


class TestAreRoutingProfileFilterAccessListIpv4(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.filter_access_list_entry_ipv4 = (
            network.RoutingProfileFilterAccessListEntryIpv4(
                1,
                action="permit",
                source_address_type="any",
                destination_address_type="any",
            )
        )
        state.obj = network.RoutingProfileFilterAccessList(
            testlib.random_name(),
            description="access list IPv4",
            type="ipv4",
        )
        state.obj.add(state.filter_access_list_entry_ipv4)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.filter_access_list_entry_ipv4.action = "deny"


class TestAreRoutingProfileFilterAccessListIpv6(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.filter_access_list_entry_ipv6 = (
            network.RoutingProfileFilterAccessListEntryIpv6(
                1,
                action="permit",
                source_address_type="any",
            )
        )
        state.obj = network.RoutingProfileFilterAccessList(
            testlib.random_name(),
            description="access list IPv6",
            type="ipv6",
        )
        state.obj.add(state.filter_access_list_entry_ipv6)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.filter_access_list_entry_ipv6.action = "deny"


class TestAreRoutingProfileFilterPrefixListIpv4(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.prefix_list_entry_ipv4 = network.RoutingProfileFilterPrefixListEntryIpv4(
            1, action="deny", prefix="any"
        )
        state.obj = network.RoutingProfileFilterPrefixList(
            testlib.random_name(), description="prefix list IPv4", type="ipv4"
        )
        state.obj.add(state.prefix_list_entry_ipv4)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.prefix_list_entry_ipv4.action = "permit"


class TestAreRoutingProfileFilterPrefixListIpv6(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.prefix_list_entry_ipv6 = network.RoutingProfileFilterPrefixListEntryIpv6(
            1, action="deny", prefix="any"
        )
        state.obj = network.RoutingProfileFilterPrefixList(
            testlib.random_name(),
            description="prefix list IPv6",
            type="ipv6",
        )
        state.obj.add(state.prefix_list_entry_ipv6)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.prefix_list_entry_ipv6.action = "permit"


class TestAreRoutingProfileFilterAsPathAccessList(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.as_path_prefix_entry = network.RoutingProfileFilterAsPathAccessListEntry(
            1, action="permit", aspath_regex="123.*"
        )
        state.obj = network.RoutingProfileFilterAsPathAccessList(testlib.random_name())
        state.obj.add(state.as_path_prefix_entry)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.as_path_prefix_entry.action = "deny"


class TestAreRoutingProfileFilterCommunityListEntryRegular(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.filter_community_regular = (
            network.RoutingProfileFilterCommunityListEntryRegular(
                1, action="permit", community=["accept-own", "no-peer"]
            )
        )
        state.obj = network.RoutingProfileFilterCommunityList(testlib.random_name())
        state.obj.add(state.filter_community_regular)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.filter_community_regular.action = "deny"


class TestAreRoutingProfileFilterCommunityListEntryLarge(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.filter_community_large = (
            network.RoutingProfileFilterCommunityListEntryLarge(
                1, action="permit", lc_regex=["123.*:456.*:987.*", "1.*:2.*:3.*"]
            )
        )
        state.obj = network.RoutingProfileFilterCommunityList(
            testlib.random_name(), type="large"
        )
        state.obj.add(state.filter_community_large)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.filter_community_large.action = "deny"


class TestAreRoutingProfileFilterCommunityListEntryExtended(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.filter_community_extended = (
            network.RoutingProfileFilterCommunityListEntryExtended(
                1, action="permit", ec_regex=["123.*:456.*", "1.*:2.*"]
            )
        )
        state.obj = network.RoutingProfileFilterCommunityList(
            testlib.random_name(), type="extended"
        )
        state.obj.add(state.filter_community_extended)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.filter_community_extended.action = "deny"


class TestAreRoutingProfileFilterRouteMaps(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.filter_route_map_entry = network.RoutingProfileFilterRouteMapsEntry(
            1,
            action="permit",
            description="Test BGP route",
            match_interface="ethernet1/1",
            match_origin="egp",
            match_metric="200",
            match_tag="12",
            match_local_preference="20",
            match_peer="local",
            set_aggregator_as="1200",
            set_aggregator_router_id="12.12.12.12",
            set_tag="21",
            set_local_preference="31",
            set_weight="11",
            set_origin="egp",
            set_atomic_aggregate=True,
            set_metric_action="set",
            set_metric_value="12",
            set_originator_id="21.21.21.21",
            set_overwrite_regular_community=True,
            set_overwrite_large_community=True,
            set_aspath_exclude=["1", "2"],
            set_aspath_prepend=["21", "22"],
            set_regular_community=["internet"],
            set_large_community=["123:456:789"],
        )
        state.obj = network.RoutingProfileFilterRouteMaps(testlib.random_name())
        state.obj.add(state.filter_route_map_entry)
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.filter_route_map_entry.action = "deny"


class TestAreRoutingProfileFilterRouteMapsRedistribution(MakeLogicalRouter):
    def setup_state_obj(self, fw, state):
        state.obj = network.RoutingProfileFilterRouteMapsRedistribution(
            testlib.random_name()
        )
        fw.add(state.obj)


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
            permitted_ip=["1.2.3.4", "5.6.7.8"],
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.permitted_ip = [
            "9.8.7.6",
        ]
        state.obj.https = True
        state.obj.http_ocsp = False


class TestIkeCryptoProfile(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.IkeCryptoProfile(
            testlib.random_name(),
            authentication=[
                "sha256",
            ],
            dh_group=[
                "group1",
            ],
            lifetime_minutes=42,
        )
        fw.add(state.obj)
        state.obj.set_encryption("3des")

    def update_state_obj(self, fw, state):
        state.obj.dh_group = ["group5", "group2"]
        state.obj.lifetime_minutes = None
        state.obj.lifetime_hours = 4
        state.obj.authentication_multiple = 3
        state.obj.set_encryption(["3des", "aes128"])


class TestIpsecCryptoProfile(testlib.FwFlow):
    def setup_state_obj(self, fw, state):
        state.obj = network.IpsecCryptoProfile(
            testlib.random_name(),
            ah_authentication=["md5", "sha256"],
            dh_group="group1",
            lifetime_hours=4,
            lifesize_gb=2,
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.ah_authentication = None
        state.obj.esp_authentication = ["md5", "sha512"]
        state.obj.lifetime_hours = None
        state.obj.lifetime_days = 2
        state.obj.lifesize_gb = None
        state.obj.lifesize_tb = 1
        state.obj.set_esp_encryption(["aes128", "aes192", "aes256"])


class TestIkeGateway(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.lbi = network.LoopbackInterface(
            "loopback.{0}".format(random.randint(5, 20)),
            ip=[testlib.random_ip(), testlib.random_ip()],
        )
        fw.add(state.lbi)
        state.lbi.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.IkeGateway(
            testlib.random_name(),
            auth_type="pre-shared-key",
            enable_dead_peer_detection=True,
            enable_liveness_check=True,
            enable_passive_mode=True,
            ikev2_crypto_profile="default",
            interface=state.lbi.name,
            liveness_check_interval=5,
            local_id_type="ipaddr",
            local_id_value=testlib.random_ip(),
            local_ip_address_type="ip",
            local_ip_address=state.lbi.ip[0],
            peer_ip_type="ip",
            peer_ip_value=testlib.random_ip(),
            pre_shared_key="secret",
            version="ikev2-preferred",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.disabled = True
        state.obj.local_ip_address = state.lbi.ip[1]
        state.obj.local_id_type = "fqdn"
        state.obj.local_id_value = "example.com"
        state.obj.peer_id_type = "keyid"
        state.obj.peer_id_value = "{0:04x}".format(random.randint(1, 65535))

    def cleanup_dependencies(self, fw, state):
        try:
            state.lbi.delete()
        except Exception:
            pass


class TestIkeIpv6Gateway(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        if fw._version_info < (7, 0, 0):
            raise ValueError("IkeGateway not supported for version < 7.0")

        state.lbi = network.LoopbackInterface(
            "loopback.{0}".format(random.randint(5, 20)),
            ipv6_enabled=True,
        )
        state.lbi.add(network.IPv6Address(testlib.random_ipv6()))
        state.lbi.add(network.IPv6Address(testlib.random_ipv6()))
        fw.add(state.lbi)
        state.lbi.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.IkeGateway(
            testlib.random_name(),
            auth_type="pre-shared-key",
            enable_ipv6=True,
            enable_liveness_check=True,
            ikev2_crypto_profile="default",
            interface=state.lbi.name,
            liveness_check_interval=5,
            local_id_type="ufqdn",
            local_id_value="foo@bar.baz",
            local_ip_address_type="ip",
            local_ip_address=state.lbi.children[0].address,
            peer_id_type="keyid",
            peer_id_value="{0:04x}".format(random.randint(1, 65535)),
            peer_ip_type="dynamic",
            pre_shared_key="secret",
            version="ikev2",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.disabled = True
        state.obj.local_ip_address = state.lbi.children[1].address
        state.obj.enable_liveness_check = False

    def cleanup_dependencies(self, fw, state):
        try:
            state.lbi.delete()
        except Exception:
            pass


class TestIpv4IpsecTunnel(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.ti = network.TunnelInterface(
            "tunnel.{0}".format(random.randint(5, 50)),
            ip=[testlib.random_ip(), testlib.random_ip()],
        )
        fw.add(state.ti)

        state.lbi = network.LoopbackInterface(
            "loopback.{0}".format(random.randint(5, 20)),
            ip=[testlib.random_ip(), testlib.random_ip()],
        )
        fw.add(state.lbi)

        state.ike_gw = network.IkeGateway(
            testlib.random_name(),
            auth_type="pre-shared-key",
            enable_dead_peer_detection=True,
            enable_liveness_check=True,
            enable_passive_mode=True,
            ikev2_crypto_profile="default",
            interface=state.lbi.name,
            liveness_check_interval=5,
            local_id_type="ipaddr",
            local_id_value=testlib.random_ip(),
            local_ip_address_type="ip",
            local_ip_address=state.lbi.ip[0],
            peer_ip_type="ip",
            peer_ip_value=testlib.random_ip(),
            pre_shared_key="secret",
            version="ikev2-preferred",
        )
        fw.add(state.ike_gw)

        state.ti.create()
        state.lbi.create()
        state.ike_gw.create()

    def setup_state_obj(self, fw, state):
        state.obj = network.IpsecTunnel(
            testlib.random_name(),
            tunnel_interface=state.ti.name,
            type="auto-key",
            ak_ike_gateway=state.ike_gw.name,
            ak_ipsec_crypto_profile="default",
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.anti_replay = True
        state.obj.copy_tos = True
        state.obj.enable_tunnel_monitor = True
        state.obj.tunnel_monitor_dest_ip = testlib.random_ip()

    def test_05_add_ipv4_proxy_id(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.proxy_id = network.IpsecTunnelIpv4ProxyId(
            testlib.random_name(),
            local=testlib.random_netmask(),
            remote=testlib.random_netmask(),
            any_protocol=True,
        )
        state.obj.add(state.proxy_id)

        state.proxy_id.create()

    def cleanup_dependencies(self, fw, state):
        for o in (state.ike_gw, state.lbi, state.ti):
            try:
                o.delete()
            except Exception:
                pass

#!/usr/bin/env python

# Copyright (c) 2022, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


"""Prisma Access module contains objects that exist in the 'Plugins/Cloud Services' tab in the Panorama GUI"""

import xml.etree.ElementTree as ET

import panos.errors as err
from panos import getlogger
from panos.base import ENTRY, Root, VersionedPanObject, VersionedParamPath

logger = getlogger(__name__)


class CloudServicesPlugin(VersionedPanObject):
    """Prisma Access configuration base object

    Args:
        all_traffic_to_dc(bool): Send All Traffic to DC Option

    """

    ROOT = Root.DEVICE
    SUFFIX = None
    NAME = None
    CHILDTYPES = (
        "plugins.RemoteNetworks",
        "plugins.RoutingPreference",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/plugins/cloud_services")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "all_traffic_to_dc",
                vartype="yesno",
                path="traffic-steering/All-Traffic-To-DC",
            )
        )

        self._params = tuple(params)

    def _setup_opstate(self):
        self.opstate = CloudServicesPluginOpState(self)


class CloudServicesPluginOpState(object):
    """Operational state handling for Cloud Services plugin."""

    def __init__(self, obj):
        self.obj = obj
        self.jobs = CloudServicesJobsStatus(obj)
        self.jobsdetails = CloudServicesJobsStatusDetails(obj)


class CloudServicesJobsStatus(object):
    """Operational state handling for rulebase hit counts."""

    def __init__(self, obj):
        self.obj = obj
        self.status = {}

    def _get_jobs(self, jobtype, svc):
        """Get job ids for CloudServices

        Args:
            jobtype (str): failed-jobs, success-jobs, or pending-jobs
            svc (str): service type. Can be a string or list with values:
                mobile-users, remote-networks, clean-pipe, service-connection
        Returns:
            list:  A list of job ids
        """

        XML = """
        <request>
            <plugins>
                <cloud_services>
                    <prisma-access>
                        <job-status>
                            <{jobtype}/>
                            <servicetype>{svc}</servicetype>
                        </job-status>
                    </prisma-access>
                </cloud_services>
            </plugins>
        </request>
        """
        dev = self.obj.nearest_pandevice()
        res = dev.op(
            XML.format(jobtype=jobtype, svc=svc),
            cmd_xml=False,
        )
        logger.debug("%s jobs for %s: %s", jobtype, svc, ET.tostring(res))
        status = res.find("result").find("result").find("status").text
        if status != "pass":
            raise err.PanDeviceError(f"Status for {jobtype} - {svc}: {status}")
        return [x.text for x in res.find("result").find("result").findall("msg")]

    def refresh(self, service_type=None, failed=True, success=True, pending=True):
        """Retrieves the prisma commit jobs status

        Args:
            service_type (str/list): Service type of jobs to refresh. Can be a string or list with values:
                mobile-users, remote-networks, clean-pipe, service-connection,
                or None to get all jobs
            failed (bool): Default True. Retrieve failed jobs or not
            success (bool): Default True. Retrieve success jobs or not
            pending (bool): Default True. Retrieve pending jobs or not
        Returns:
            dict:  A dict where the key is the service type. each service type is a dict with failed, success, pending jobs

        """

        if service_type is None:
            svcs = [
                "mobile-users",
                "remote-networks",
                "clean-pipe",
                "service-connection",
            ]
        else:
            if isinstance(service_type, list):
                svcs = service_type
            else:
                svcs = [service_type]
        for svc in svcs:
            if svc not in self.status:
                self.status[svc] = {}
            if failed:
                self.status[svc]["failed"] = self._get_jobs("failed-jobs", svc)
            if success:
                self.status[svc]["success"] = self._get_jobs("success-jobs", svc)
            if pending:
                self.status[svc]["pending"] = self._get_jobs("pending-jobs", svc)

        return self.status


class CloudServicesJobsStatusDetails(object):
    """Operational state handling for rulebase hit counts."""

    def __init__(self, obj):
        self.obj = obj
        self.details = {}

    def _parse_response(self, xmlresponse):
        """Parse XML response from API

        Args:
            xmlresponse (Element): XML Element from API call.
        """

        response = (
            xmlresponse.find("result").find("result").find("msg").find("response")
        )

        r = {
            "status": response.find("status").text,
            "percentage_completion": response.find("percentageCompletion").text,
            "error_code": response.find("errorCode").text,
        }
        for nodetype in response.find("InstanceSummary"):
            node = nodetype.find("overview")
            nodetypename = nodetype.tag.lower().replace("-", "_")
            r[nodetypename] = {
                "total_instances": node.find("TotalInstances").text,
                "provisioning_in_progress": node.find("ProvisioningInProgress").text,
                "provisioning_failed": node.find("ProvisioningFailed").text,
                "provisioning_complete": node.find("ProvisioningComplete").text,
            }
        return r

    def refresh(self, job_id, service_type):
        """Retrieves a prisma commit jobs details

        Args:
            job_id (int): the job ID to get details from
            service_type (str/list): Service type of jobs to refresh. Can be a string or list with values:
                mobile-users, remote-networks, clean-pipe, service-connection.
        Returns:
            dict:  A dict with the details of job 'job_id'. See _parse_response for structure of the output dict.
                Note: for mobile-users, the details will contains both gpgateways and gpportals entries,
                for remote-networks it will have remote_networks, and for service-connection, it will have service_connection

        """

        XML = f"""
        <request>
            <plugins>
                <cloud_services>
                    <prisma-access>
                        <job-status>
                            <jobid>{job_id}</jobid>
                            <servicetype>{service_type}</servicetype>
                        </job-status>
                    </prisma-access>
                </cloud_services>
            </plugins>
        </request>
        """
        dev = self.obj.nearest_pandevice()
        res = dev.op(XML, cmd_xml=False)
        logger.debug("Details for job %s: %s", job_id, ET.tostring(res))
        status = res.find("result").find("result").find("status").text
        if status != "pass":
            raise err.PanDeviceError(
                f"Status for job {job_id} - {service_type}: {status}"
            )
        self.details[job_id] = self._parse_response(res)
        return self.details[job_id]


class AggBandwidth(VersionedPanObject):
    """Prisma Access remote networks Aggregated Bandwidth configuration base object

    Args:
        enabled(bool): Whether Aggregated BW mode is enabled or not
    """

    # TODO: Add support for QoS Here ?
    ROOT = Root.DEVICE
    SUFFIX = None
    NAME = None
    CHILDTYPES = ("plugins.Region",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/agg-bandwidth")

        # params
        params = []

        params.append(VersionedParamPath("enabled", vartype="yesno", path="enabled"))

        self._params = tuple(params)


class Region(VersionedPanObject):
    """Prisma Access remote networks Aggregated Bandwidth configuration base object

    Args:
        name(str): Region Name
        allocated_bw(int): Allocated BW in Mbps
        spn_name_list(list/str): Names of the SPN for the region
    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY
    CHILDTYPES = ()

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/region")

        # params
        params = []
        params.append(
            VersionedParamPath("allocated_bw", vartype="int", path="allocated-bw")
        )
        params.append(
            VersionedParamPath("spn_name_list", path="spn-name-list", vartype="member")
        )
        self._params = tuple(params)


class RemoteNetworks(VersionedPanObject):
    """Prisma Access Remote-Networks configuration base object

    Args:
        overlapped_subnets(bool): Whether or not overlapped subnets are enabled
        template_stack(str): Remote Networks Template stack
        device_group(str): Remote Networks device group
        trusted_zones(list/str): Remote Networks trusted zones
        udp_query_interval(int): DNS UDP Query interval
        udp_query_attempts(int): DNS UDP Query attempts
    """

    ROOT = Root.DEVICE
    NAME = None
    SUFFIX = None
    CHILDTYPES = (
        "plugins.RemoteNetwork",
        "plugins.AggBandwidth",
        "plugins.InternalDnsMatch",
        "plugins.PrimaryPublicDNSServer",
        "plugins.SecondaryPublicDNSServer",
    )
    # TODO Add support for inbound remote network later

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/remote-networks")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "overlapped_subnets", vartype="yesno", path="overlapped-subnets"
            )
        )
        params.append(VersionedParamPath("template_stack", path="template-stack"))
        params.append(VersionedParamPath("device_group", path="device-group"))
        params.append(
            VersionedParamPath("trusted_zones", vartype="member", path="trusted-zones")
        )
        params.append(
            VersionedParamPath(
                "udp_query_interval",
                vartype="int",
                path="udp-queries/retries/interval",
                default=2,
            )
        )
        params.append(
            VersionedParamPath(
                "udp_query_attempts",
                vartype="int",
                path="udp-queries/retries/attempts",
                default=5,
            )
        )
        self._params = tuple(params)


class InternalDnsMatch(VersionedPanObject):
    """Prisma Access remote-networks Internal DNS entry configuration base object

    Args:
        domain_list(list/str): Internal Domains names

    """

    ROOT = Root.DEVICE
    NAME = None
    SUFFIX = ENTRY
    CHILDTYPES = (
        "plugins.PrimaryInternalDNSServer",
        "plugins.SecondaryInternalDNSServer",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/internal-dns-match")

        # params
        params = []

        params.append(
            VersionedParamPath("domain_list", vartype="member", path="domain-list")
        )

        self._params = tuple(params)


class DNSServerBase(VersionedPanObject):
    """Abstract DNS Class, will be inherited for correct XPATH

    Args:
        dns_server(str): IP of DNS Server
        use-cloud-default(bool): Use cloud default DNS
        same_as_internal(bool): Use same DNS server as Internal
    """

    ROOT = Root.DEVICE
    NAME = None

    def __init__(self, *args, **kwargs):
        if type(self) == DNSServerBase:
            raise err.PanDeviceError("Do not instantiate class. Please use a subclass.")
        super(DNSServerBase, self).__init__(*args, **kwargs)

    def add_dns_params(self, same_as_internal):
        params = []

        params.append(VersionedParamPath("dns_server", path="dns-server"))
        params.append(
            VersionedParamPath(
                "use-cloud-default", vartype="exist", path="use_cloud_default"
            )
        )
        if same_as_internal:
            params.append(
                VersionedParamPath(
                    "same_as_internal", vartype="exist", path="same-as-internal"
                )
            )
        self._params = tuple(params)


class PrimaryInternalDNSServer(DNSServerBase):
    """A primary Internal DNS Server for remote networks

    Args:
        dns_server(str): IP of DNS Server
        use_cloud_default(bool): Use cloud default DNS
    """

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/primary")
        self.add_dns_params(False)


class SecondaryInternalDNSServer(DNSServerBase):
    """A Secondary Internal DNS Server for remote networks

    Args:
        dns_server(str): IP of DNS Server
        use_cloud_default(bool): Use cloud default DNS
    """

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/dns-servers/secondary")
        self.add_dns_params(False)


class PrimaryPublicDNSServer(DNSServerBase):
    """A primary Public DNS Server for remote networks

    Args:
        dns_server(str): IP of DNS Server
        use_cloud_default(bool): Use cloud default DNS
        same_as_internal(bool): Use same DNS server as Internal
    """

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/dns-servers/primary-public-dns")
        self.add_dns_params(True)


class SecondaryPublicDNSServer(DNSServerBase):
    """A secondary Internal DNS Server for remote networks

    Args:
        dns_server(str): IP of DNS Server
        use_cloud_default(bool): Use cloud default DNS
        same_as_internal(bool): Use same DNS server as Internal
    """

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/dns-servers/secondary-public-dns")
        self.add_dns_params(True)


class Bgp(VersionedPanObject):  # TODO : shoud it be protcol-bgp ?
    """Prisma Access BGP configuration object

    Args:
        enable(bool): Whether BGP is enabled or not.
        originate_default_route(bool): Originate default route
        summarize_mobile_user_routes(bool): Summarize mobile users routes or not
        do_not_export_routes(bool): Do not export routes
        peer_as(int): Peer AS
        peer_ip_address(str): Peer IP Address
        local_ip_address(str): Local IP Address
        secret(str): BGP Password
    """

    ROOT = Root.DEVICE
    SUFFIX = None
    CHILDTYPES = ()
    NAME = None

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/protocol/bgp")

        # params
        params = []

        params.append(VersionedParamPath("enable", vartype="yesno", path="enable"))

        params.append(
            VersionedParamPath(
                "originate_default_route",
                vartype="yesno",
                path="originate-default-route",
            )
        )
        params.append(
            VersionedParamPath(
                "summarize_mobile_user_routes",
                vartype="yesno",
                path="summarize-mobile-user-routes",
            )
        )
        params.append(
            VersionedParamPath(
                "do_not_export_routes", vartype="yesno", path="do-not-export-routes"
            )
        )

        params.append(VersionedParamPath("peer_as", vartype="int", path="peer-as"))
        params.append(VersionedParamPath("peer_ip_address", path="peer-ip-address"))
        params.append(VersionedParamPath("local_ip_address", path="local-ip-address"))
        params.append(VersionedParamPath("secret", vartype="encrypted", path="secret"))

        self._params = tuple(params)


class BgpPeer(VersionedPanObject):
    """Prisma Access BGP Peer configuration object

    Args:
        same_as_primary(bool) Same AS as primary WAN Peer.
        peer_ip_address(str): Peer IP Address
        local_ip_address(str): Local IP Address
        secret(str): BGP Password

    """

    ROOT = Root.DEVICE
    NAME = None
    SUFFIX = None
    CHILDTYPES = ()

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/bgp-peer")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "same_as_primary",
                vartype="yesno",
                path="same-as-primary",
            )
        )
        params.append(VersionedParamPath("peer_ip_address", path="peer-ip-address"))
        params.append(VersionedParamPath("local_ip_address", path="local-ip-address"))
        params.append(VersionedParamPath("secret", vartype="encrypted", path="secret"))
        self._params = tuple(params)


class RoutingPreference(VersionedPanObject):
    """Prisma Access routing-preference configuration base object

    Args:
        default(bool): Default Routing Mode
        hot_potato_routing(bool): Hot Potato Routing Mode

    """

    ROOT = Root.DEVICE
    NAME = None
    SUFFIX = None
    CHILDTYPES = ()

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/routing-preference")

        # params
        params = []

        params.append(
            VersionedParamPath("default", vartype="exist", path="default", default=True)
        )
        params.append(
            VersionedParamPath(
                "hot_potato_routing", vartype="exist", path="Hot-Potato-Routing"
            )
        )
        self._params = tuple(params)


class Link(VersionedPanObject):
    """Prisma Access ECMP Links config object

    Args:
        name(str): Link Name
        ipsec_tunnel(str): IPSEC Tunnel Name

    """

    # NAME = None #Not needed, default value
    ROOT = Root.DEVICE
    SUFFIX = ENTRY
    CHILDTYPES = ("plugins.Bgp",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/link")

        # params
        params = []

        params.append(VersionedParamPath("ipsec_tunnel", path="ipsec-tunnel"))

        # TODO QOS HERE
        self._params = tuple(params)


class RemoteNetwork(VersionedPanObject):
    """Prisma Access Remote-Networks Onboarding configuration base object

    Args:
        name(str): Remote Network Name
        static_routes(list/str): Static Routes
        region(str): Remote Network Region Name
        license_type(str): License Type
        ipsec_tunnel(str): IPSEC tunnel Name
        secondary_wan_enabled(bool): Secondary WAN Enabled ?
        ecmp_load_balancing(bool): Enabled ECMP or not
        secondary_ipsec_tunnel(str): Name of secondary IPSEC tunnel
        spn_name(str): SPN Name of the remote network
        inbound_flow_over_pa_backbone(bool): inbound flow over pa backbone
    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY
    CHILDTYPES = (
        "plugins.Bgp",
        "plugins.BgpPeer",
        "plugins.Link",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/onboarding")

        # params
        params = []

        params.append(
            VersionedParamPath("static_routes", vartype="member", path="subnets")
        )
        params.append(VersionedParamPath("region", path="region"))
        params.append(VersionedParamPath("license_type", path="license-type"))
        params.append(VersionedParamPath("ipsec_tunnel", path="ipsec-tunnel"))
        params.append(
            VersionedParamPath(
                "secondary_wan_enabled", vartype="yesno", path="secondary-wan-enabled"
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_load_balancing",
                path="ecmp-load-balancing",
                values=("enabled-with-symmetric-return", "disabled"),
            )
        )
        params.append(
            VersionedParamPath("secondary_ipsec_tunnel", path="secondary-ipsec-tunnel")
        )
        params.append(VersionedParamPath("spn_name", path="spn-name"))
        params.append(
            VersionedParamPath(
                "inbound_flow_over_pa_backbone",
                vartype="yesno",
                path="inbound-flow-over-pa-backbone",
            )
        )

        # TODO Add QoS Support

        self._params = tuple(params)

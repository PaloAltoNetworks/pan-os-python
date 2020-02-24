#!/usr/bin/env python

# Copyright (c) 2014, Palo Alto Networks
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

"""Device module contains objects that exist in the 'Device' tab in the firewall GUI"""

import pandevice.errors as err
from pandevice import getlogger
from pandevice.base import ENTRY, MEMBER, PanObject, Root, ValueEntry
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject, VersionedParamPath

logger = getlogger(__name__)


class VsysResources(VersionedPanObject):
    """Resource constraints for a Vsys

    Args:
        max_security_rules (int): Maximum security rules
        max_nat_rules (int): Maximum nat rules
        max_ssl_decryption_rules (int): Maximum ssl decryption rules
        max_qos_rules (int): Maximum QOS rules
        max_application_override_rules (int): Maximum application override rules
        max_pbf_rules (int): Maximum policy based forwarding rules
        max_cp_rules (int): Maximum captive portal rules
        max_dos_rules (int): Maximum DOS rules
        max_site_to_site_vpn_tunnels (int): Maximum site-to-site VPN tunnels
        max_concurrent_ssl_vpn_tunnels (int): Maximum ssl VPN tunnels
        max_sessions (int): Maximum sessions

    """

    NAME = None
    ROOT = Root.VSYS

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/import/resource")
        self._xpaths.add_profile(
            value="{0}/import/resource".format(self._TEMPLATE_VSYS_XPATH),
            parents=("Template",),
        )

        # params
        params = []

        int_params = (
            "max-security-rules",
            "max-nat-rules",
            "max-ssl-decryption-rules",
            "max-qos-rules",
            "max-application-override-rules",
            "max-pbf-rules",
            "max-cp-rules",
            "max-dos-rules",
            "max-site-to-site-vpn-tunnels",
            "max-concurrent-ssl-vpn-tunnels",
            "max-sessions",
        )
        for x in int_params:
            params.append(VersionedParamPath(x, path=x, vartype="int"))

        self._params = tuple(params)


class Vsys(VersionedPanObject):
    """Virtual System (VSYS)

    You can interact with virtual systems in two different ways:

    **Method 1**. Use a :class:`pandevice.firewall.Firewall` object with the 'vsys'
    variable set to a vsys identifier (eg. 'vsys2'). In this case,
    you don't need to use this Vsys class. Add other PanObject instances
    (like :class:`pandevice.objects.AddressObject`) to the Firewall instance

    **Method 2**. Add an instance of this Vsys class to a :class:`pandevice.firewall.Firewall`
    object. It is best practice to set the Firewall instance's 'shared'
    variable to True when using this method. Add other PanObject instances
    (like :class:`pandevice.objects.AddressObject`) to the Vsys instance.

    Args:
        name (str): Vsys identifier (eg. 'vsys1', 'vsys5', etc)
        display_name (str): Friendly name of the vsys
        interface (list): A list of strings with names of interfaces
            or a list of :class:`pandevice.network.Interface` objects
        vlans (list): A list of strings of VLANs
        virtual_wires (list): A list of strings of virtual wires
        virtual_routers (list): A list of strings of virtual routers
        visible_vsys (list): A list of strings of the vsys visible
        dns_proxy (str): DNS Proxy server
        decrypt_forwarding (bool): Allow forwarding of decrypted content

    """

    ROOT = Root.DEVICE
    VSYS_LABEL = "vsys"
    SUFFIX = ENTRY
    CHILDTYPES = (
        "device.VsysResources",
        "device.SnmpServerProfile",
        "device.EmailServerProfile",
        "device.SyslogServerProfile",
        "device.HttpServerProfile",
        "objects.AddressObject",
        "objects.AddressGroup",
        "objects.ServiceObject",
        "objects.ServiceGroup",
        "objects.ApplicationObject",
        "objects.ApplicationGroup",
        "objects.ApplicationFilter",
        "objects.ScheduleObject",
        "objects.SecurityProfileGroup",
        "objects.CustomUrlCategory",
        "objects.LogForwardingProfile",
        "objects.DynamicUserGroup",
        "objects.Region",
        "policies.Rulebase",
        "network.EthernetInterface",
        "network.AggregateInterface",
        "network.LoopbackInterface",
        "network.TunnelInterface",
        "network.VlanInterface",
        "network.Vlan",
        "network.VirtualRouter",
        "network.VirtualWire",
        "network.Zone",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/vsys")
        self._xpaths.add_profile(
            value="{0}/vsys".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(VersionedParamPath("display_name", path="display-name"))
        params.append(
            VersionedParamPath(
                "interface", vartype="member", path="import/network/interface"
            )
        )
        params.append(
            VersionedParamPath("vlans", vartype="member", path="import/network/vlan")
        )
        params.append(
            VersionedParamPath(
                "virtual_wires", vartype="member", path="import/network/virtual-wire"
            )
        )
        params.append(
            VersionedParamPath(
                "virtual_routers",
                vartype="member",
                path="import/network/virtual-router",
            )
        )
        params.append(
            VersionedParamPath(
                "visible_vsys", vartype="member", path="import/visible-vsys"
            )
        )
        params.append(VersionedParamPath("dns_proxy", path="import/dns-proxy"))
        params.append(
            VersionedParamPath(
                "decrypt_forwarding",
                vartype="yesno",
                path="setting/ssl-decrypt/allow-forward-decrypted-content",
            )
        )

        self._params = tuple(params)

    def xpath_vsys(self):
        return self.xpath()

    def _build_xpath(self, root, vsys):
        if self.parent is None:
            return ""
        return self.parent._build_xpath(root, self.name)

    @property
    def vsys(self):
        return self.name

    @vsys.setter
    def vsys(self, value):
        self.name = value


class NTPServer(PanObject):
    """A primary or secondary NTP server

    This is an abstract base class, do not instantiate it.

    Args:
        address (str): The IP address of the NTP server

    """

    # TODO: Add authentication
    # TODO: Add PAN-OS pre-7.0 support

    XPATH = "/ntp-servers/primary-ntp-server"

    def __init__(self, *args, **kwargs):
        if type(self) == NTPServer:
            raise err.PanDeviceError("Do not instantiate class. Please use a subclass.")
        super(NTPServer, self).__init__(*args, **kwargs)

    @classmethod
    def variables(cls):
        return (Var("ntp-server-address", "address"),)


class NTPServerPrimary(NTPServer):
    """A primary NTP server

    Add to a :class:`pandevice.device.SystemSettings` object

    Args:
        address (str): IP address or hostname of NTP server

    """

    XPATH = "/ntp-servers/primary-ntp-server"


class NTPServerSecondary(NTPServer):
    """A secondary NTP server

    Add to a :class:`pandevice.device.SystemSettings` object

    Args:
        address (str): IP address or hostname of NTP server

    """

    XPATH = "/ntp-servers/secondary-ntp-server"


class SystemSettings(VersionedPanObject):
    """Firewall or Panorama device system settings

    Add only one of these to a parent object.

    If you want to configure DHCP on the management interface, you should
    specify settings for `dhcp_send_hostname` and `dhcp_send_client_id`.

    Args:
        hostname (str): The hostname of the device
        domain (str): The domain of the device
        ip_address (str): Management interface IP address
        netmask (str): Management interface netmask
        default_gateway (str): Management interface default gateway
        ipv6_address (str): Management interface IPv6 address
        ipv6_default_gateway (str): Management interface IPv6 default gateway
        dns_primary (str): Primary DNS server IP address
        dns_secondary (str): Secondary DNS server IP address
        timezone (str): Device timezone
        panorama (str): IP address of primary Panorama
        panorama2 (str):  IP address of secondary Panorama
        login_banner (str): Login banner text
        update_server (str): IP or hostname of the update server
        verify_update_server (bool): Verify the update server identity
        dhcp_send_hostname (bool): (DHCP Mngt) Send Hostname
        dhcp_send_client_id (bool): (DHCP Mngt) Send Client ID
        accept_dhcp_hostname (bool): (DHCP Mngt) Accept DHCP hostname
        accept_dhcp_domain (bool): (DHCP Mngt) Accept DHCP domain name

    """

    NAME = None
    ROOT = Root.DEVICE
    HA_SYNC = False
    CHILDTYPES = (
        "device.NTPServerPrimary",
        "device.NTPServerSecondary",
        "device.Telemetry",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/deviceconfig/system")
        self._xpaths.add_profile(
            value="{0}/deviceconfig/system".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(VersionedParamPath("hostname", path="hostname"))
        params.append(VersionedParamPath("domain", path="domain"))
        params.append(VersionedParamPath("ip_address", path="ip-address"))
        params.append(VersionedParamPath("netmask", path="netmask"))
        params.append(VersionedParamPath("default_gateway", path="default-gateway"))
        params.append(VersionedParamPath("ipv6_address", path="ipv6-address"))
        params.append(
            VersionedParamPath("ipv6_default_gateway", path="ipv6-default-gateway")
        )
        params.append(
            VersionedParamPath("dns_primary", path="dns-setting/servers/primary")
        )
        params.append(
            VersionedParamPath("dns_secondary", path="dns-setting/servers/secondary")
        )
        params.append(VersionedParamPath("timezone", path="timezone"))
        params.append(VersionedParamPath("panorama", path="panorama-server"))
        params[-1].add_profile("9.1.0", path="panorama/local-panorama/panorama-server")
        params.append(VersionedParamPath("panorama2", path="panorama-server-2"))
        params[-1].add_profile(
            "9.1.0", path="panorama/local-panorama/panorama-server-2"
        )
        params.append(VersionedParamPath("login_banner", path="login-banner"))
        params.append(VersionedParamPath("update_server", path="update-server"))
        params.append(
            VersionedParamPath(
                "verify_update_server", vartype="yesno", path="server-verification"
            )
        )
        params.append(
            VersionedParamPath(
                "dhcp_send_hostname",
                vartype="yesno",
                path="type/dhcp-client/send-hostname",
            )
        )
        params.append(
            VersionedParamPath(
                "dhcp_send_client_id",
                vartype="yesno",
                path="type/dhcp-client/send-client-id",
            )
        )
        params.append(
            VersionedParamPath(
                "accept_dhcp_hostname",
                vartype="yesno",
                path="type/dhcp-client/accept-dhcp-hostname",
            )
        )
        params.append(
            VersionedParamPath(
                "accept_dhcp_domain",
                vartype="yesno",
                path="type/dhcp-client/accept-dhcp-domain",
            )
        )

        self._params = tuple(params)


class PasswordProfile(VersionedPanObject):
    """Password profile object

    Args:
        name (str): Password profile name
        expiration (int): Number of days until the password expires
        warning (int): Number of days warning before password expires
        login_count (int): Post expiration admin login count
        grace_period (int): Post expiration grace period

    """

    ROOT = Root.MGTCONFIG
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/password-profile")
        self._xpaths.add_profile(
            value="{0}/password-profile".format(self._TEMPLATE_MGTCONFIG_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath(
                "expiration", vartype="int", path="password-change/expiration-period"
            )
        )
        params.append(
            VersionedParamPath(
                "warning",
                vartype="int",
                path="password-change/expiration-warning-period",
            )
        )
        params.append(
            VersionedParamPath(
                "login_count",
                vartype="int",
                path="password-change/post-expiration-admin-login-count",
            )
        )
        params.append(
            VersionedParamPath(
                "grace_period",
                vartype="int",
                path="password-change/post-expiration-grace-period",
            )
        )

        self._params = tuple(params)


class Administrator(VersionedPanObject):
    """Administrator object

    Args:
        name (str): Admin name
        authentication_profile (str): The authentication profile
        web_client_cert_only (bool): Use only client certificate authentication (Web)
        superuser (bool): Admin type - superuser
        superuser_read_only (bool): Admin type - superuser, read only
        panorama_admin (bool): Panonrama - a panorama admin only
        device_admin (bool): Admin type - device admin
        device_admin_read_only (bool): Admin type - device admin, read only
        vsys (list/str): Physical firewalls: the vsys this admin should manage
        vsys_read_only (list/str): Physical firewalls: the vsys this read only admin should manage
        ssh_public_key (str): Use Public Key Authentication (SSH)
        role_profile (str): The role based profile
        password_hash (encrypted str): The encrypted password
        password_profile (str): The password profile for this user

    """

    ROOT = Root.MGTCONFIG
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/users")
        self._xpaths.add_profile(
            value="{0}/users".format(self._TEMPLATE_MGTCONFIG_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath("authentication_profile", path="authentication-profile")
        )
        params.append(
            VersionedParamPath(
                "web_client_cert_only", vartype="yesno", path="client-certificate-only"
            )
        )
        params.append(
            VersionedParamPath(
                "superuser", vartype="yesno", path="permissions/role-based/superuser"
            )
        )
        params.append(
            VersionedParamPath(
                "superuser_read_only",
                vartype="yesno",
                path="permissions/role-based/superreader",
            )
        )
        params.append(
            VersionedParamPath(
                "panorama_admin",
                vartype="yesno",
                path="permissions/role-based/panorama-admin",
            )
        )
        params.append(
            VersionedParamPath(
                "device_admin",
                vartype="exist",
                path="permissions/role-based/deviceadmin",
            )
        )
        params.append(
            VersionedParamPath(
                "device_admin_read_only",
                vartype="exist",
                path="permissions/role-based/devicereader",
            )
        )
        params.append(
            VersionedParamPath(
                "vsys",
                vartype="member",
                path="permissions/role-based/vsysadmin/entry vsys_device/vsys",
            )
        )
        params.append(
            VersionedParamPath(
                "vsys_read_only",
                vartype="member",
                path="permissions/role-based/vsysreader"
                + "/entry vsys_read_only_device/vsys",
            )
        )
        params.append(VersionedParamPath("ssh_public_key", path="public-key"))
        params.append(
            VersionedParamPath(
                "role_profile", path="permissions/role-based/custom/profile"
            )
        )
        params.append(
            VersionedParamPath("password_hash", path="phash", vartype="encrypted")
        )
        params.append(VersionedParamPath("password_profile", path="password-profile"))
        params.append(
            VersionedParamPath(
                "vsys_device",
                exclude=True,
                vartype="entry",
                path="permissions/role-based/vsysadmin",
                default="localhost.localdomain",
            )
        )
        params.append(
            VersionedParamPath(
                "vsys_read_only_device",
                exclude=True,
                vartype="entry",
                path="permissions/role-based/vsysreader",
                default="localhost.localdomain",
            )
        )

        self._params = tuple(params)

    def change_password(self, new_password):
        """Update the password.

        **Modifies the live device**

        Args:
            new_password (str): The new password for this user.

        """
        dev = self.nearest_pandevice()
        self.password_hash = dev.request_password_hash(new_password)
        self.update("password_hash")


class Telemetry(VersionedPanObject):
    """Share telemetry data with Palo Alto Networks.

    Join other Palo Alto Networks customers in a global sharing community,
    helping to raise the bar against the latest attack techniques. Your
    participation allows us to deliver new threat prevention controls across
    the attack lifecycle. Choose the type of data you share across
    applications, threat intelligence, and device health information to improve
    the fidelity of the protections we deliver. This is an opt-in feature
    controlled with granular policy, and we encourage you to join the
    community.

    Add only one of these to a firewall.

    Args:
        app_reports (bool): Application reports
        threat_reports (bool): Threat preventioin reports
        url_reports (bool): URL reports
        file_type_reports (bool): File type identification reports
        threat_data (bool): Threat prevention data
        threat_pcaps (bool): Enable sending packet captures with threat
            prevention information.  This requires that "threat_data" also be
            enabled.
        product_usage_stats (bool): Health and performance reports
        passive_dns_monitoring (bool): Passive DNS monitoring

    """

    NAME = None
    ROOT = Root.DEVICE

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/update-schedule/statistics-service")

        bool_params = (
            ("app_reports", "application-reports"),
            ("threat_reports", "threat-prevention-reports"),
            ("url_reports", "url-reports"),
            ("file_type_reports", "file-identification-reports"),
            ("threat_data", "threat-prevention-information"),
            ("threat_pcaps", "threat-prevention-pcap"),
            ("product_usage_stats", "health-performance-reports"),
            ("passive_dns_monitoring", "passive-dns-monitoring"),
        )

        self._params = tuple(
            VersionedParamPath(param, vartype="yesno", path=path)
            for param, path in bool_params
        )


class SnmpServerProfile(VersionedPanObject):
    """SNMP server profile.

    Args:
        name (str): The name
        version (str): SNMP version.  Valid values are v2c (default) or
            v3.

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = (
        "device.SnmpV2cServer",
        "device.SnmpV3Server",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/log-settings/snmptrap")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "version", default="v2c", values=["v2c", "v3"], path="version/{version}"
            )
        )

        self._params = tuple(params)


class SnmpV2cServer(VersionedPanObject):
    """SNMP V2C server in a server.

    Args:
        name (str): The name
        manager (str): IP address or FQDN of SNMP manager to use
        community (str): SNMP community

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/version/v2c/server")

        # params
        params = []

        params.append(VersionedParamPath("manager", path="manager"))
        params.append(VersionedParamPath("community", path="community"))

        self._params = tuple(params)


class SnmpV3Server(VersionedPanObject):
    """SNMP V3 server.

    Args:
        name (str): The name
        manager (str): IP address or FQDN of SNMP manager to use
        user (str): User
        engine_id (str): A hex number
        auth_password (str): Authentication protocol password
        priv_password (str): Privacy protocol password

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/version/v3/server")

        # params
        params = []

        params.append(VersionedParamPath("manager", path="manager"))
        params.append(VersionedParamPath("user", path="user"))
        params.append(VersionedParamPath("engine_id", path="engineid"))
        params.append(
            VersionedParamPath("auth_password", vartype="encrypted", path="authpwd")
        )
        params.append(
            VersionedParamPath("priv_password", vartype="encrypted", path="privpwd")
        )

        self._params = tuple(params)


class EmailServerProfile(VersionedPanObject):
    """An email server profile.

    Args:
        name (str): The name
        config (str): Custom config log format
        system (str): Custom system log format
        threat (str): Custom threat log format
        traffic (str): Custom traffic log format
        hip_match (str): Custom HIP match log format
        url (str): (PAN-OS 8.0+) Custom URL log format
        data (str): (PAN-OS 8.0+) Custom data log format
        wildfire (str): (PAN-OS 8.0+) Custom WildFire log format
        tunnel (str): (PAN-OS 8.0+) Custom tunnel log format
        user_id (str): (PAN-OS 8.0+) Custom user-ID log format
        gtp (str): (PAN-OS 8.0+) Custom GTP log format
        auth (str): (PAN-OS 8.0+) Custom authentication log format
        sctp (str): (PAN-OS 8.1+) Custom SCTP log format
        iptag (str): (PAN-OS 9.0+) Custom Iptag log format
        escaped_characters (str): Characters to be escaped
        escape_character (str): Escape character

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = ("device.EmailServer",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/log-settings/email")

        # params
        params = []

        params.append(VersionedParamPath("config", path="format/config"))
        params.append(VersionedParamPath("system", path="format/system"))
        params.append(VersionedParamPath("threat", path="format/threat"))
        params.append(VersionedParamPath("traffic", path="format/traffic"))
        params.append(VersionedParamPath("hip_match", path="format/hip-match"))
        params.append(VersionedParamPath("url", exclude=True))
        params[-1].add_profile("8.0.0", path="format/url")
        params.append(VersionedParamPath("data", exclude=True))
        params[-1].add_profile("8.0.0", path="format/data")
        params.append(VersionedParamPath("wildfire", exclude=True))
        params[-1].add_profile("8.0.0", path="format/wildfire")
        params.append(VersionedParamPath("tunnel", exclude=True))
        params[-1].add_profile("8.0.0", path="format/tunnel")
        params.append(VersionedParamPath("user_id", exclude=True))
        params[-1].add_profile("8.0.0", path="format/userid")
        params.append(VersionedParamPath("gtp", exclude=True))
        params[-1].add_profile("8.0.0", path="format/gtp")
        params.append(VersionedParamPath("auth", exclude=True))
        params[-1].add_profile("8.0.0", path="format/auth")
        params.append(VersionedParamPath("sctp", exclude=True))
        params[-1].add_profile("8.1.0", path="format/sctp")
        params.append(VersionedParamPath("iptag", exclude=True))
        params[-1].add_profile("9.0.0", path="format/iptag")
        params.append(
            VersionedParamPath("escaped_characters", path="escaping/escaped-characters")
        )
        params.append(
            VersionedParamPath("escape_character", path="escaping/escape_character")
        )

        self._params = tuple(params)


class EmailServer(VersionedPanObject):
    """An email server in a email server profile.

    Args:
        name (str): The name
        display_name (str): Display name
        from (str): From email address
        to (str): To email address
        also_to (str): Additional destination email address
        email_gateway (str): IP address or FQDN of email gateway to use

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/server")

        # params
        params = []

        params.append(VersionedParamPath("display_name", path="display-name"))
        params.append(VersionedParamPath("from", path="from"))
        params.append(VersionedParamPath("to", path="to"))
        params.append(VersionedParamPath("also_to", path="and-also-to"))
        params.append(VersionedParamPath("email_gateway", path="gateway"))

        self._params = tuple(params)


class SyslogServerProfile(VersionedPanObject):
    """A syslog server profile.

    Args:
        name (str): The name
        config (str): Custom config log format
        system (str): Custom system log format
        threat (str): Custom threat log format
        traffic (str): Custom traffic log format
        hip_match (str): Custom HIP match log format
        url (str): (PAN-OS 8.0+) Custom URL log format
        data (str): (PAN-OS 8.0+) Custom data log format
        wildfire (str): (PAN-OS 8.0+) Custom WildFire log format
        tunnel (str): (PAN-OS 8.0+) Custom tunnel log format
        user_id (str): (PAN-OS 8.0+) Custom user-ID log format
        gtp (str): (PAN-OS 8.0+) Custom GTP log format
        auth (str): (PAN-OS 8.0+) Custom authentication log format
        sctp (str): (PAN-OS 8.1+) Custom SCTP log format
        iptag (str): (PAN-OS 9.0+) Custom Iptag log format
        escaped_characters (str): Characters to be escaped
        escape_character (str): Escape character

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = ("device.SyslogServer",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/log-settings/syslog")

        # params
        params = []

        params.append(VersionedParamPath("config", path="format/config"))
        params.append(VersionedParamPath("system", path="format/system"))
        params.append(VersionedParamPath("threat", path="format/threat"))
        params.append(VersionedParamPath("traffic", path="format/traffic"))
        params.append(VersionedParamPath("hip_match", path="format/hip-match"))
        params.append(VersionedParamPath("url", exclude=True))
        params[-1].add_profile("8.0.0", path="format/url")
        params.append(VersionedParamPath("data", exclude=True))
        params[-1].add_profile("8.0.0", path="format/data")
        params.append(VersionedParamPath("wildfire", exclude=True))
        params[-1].add_profile("8.0.0", path="format/wildfire")
        params.append(VersionedParamPath("tunnel", exclude=True))
        params[-1].add_profile("8.0.0", path="format/tunnel")
        params.append(VersionedParamPath("user_id", exclude=True))
        params[-1].add_profile("8.0.0", path="format/userid")
        params.append(VersionedParamPath("gtp", exclude=True))
        params[-1].add_profile("8.0.0", path="format/gtp")
        params.append(VersionedParamPath("auth", exclude=True))
        params[-1].add_profile("8.0.0", path="format/auth")
        params.append(VersionedParamPath("sctp", exclude=True))
        params[-1].add_profile("8.1.0", path="format/sctp")
        params.append(VersionedParamPath("iptag", exclude=True))
        params[-1].add_profile("9.0.0", path="format/iptag")
        params.append(
            VersionedParamPath("escaped_characters", path="escaping/escaped-characters")
        )
        params.append(
            VersionedParamPath("escape_character", path="escaping/escape_character")
        )

        self._params = tuple(params)


class SyslogServer(VersionedPanObject):
    """A single syslog server in a syslog server profile.

    Args:
        name (str): The name
        server (str): IP address or FQDN of the syslog server
        transport (str): Syslog transport.  Valid values are UDP (default),
            TCP, or SSL.
        port (int): Syslog port number.
        format (str): Format of the syslog message.  Valid values are BSD
            (default) or IETF.
        facility (str): Syslog facility.  Valid values are LOG_USER (default),
            or LOG_LOCAL0 through LOG_LOCAL7.

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/server")

        # params
        params = []

        params.append(VersionedParamPath("server", path="server"))
        params.append(
            VersionedParamPath(
                "transport",
                default="UDP",
                values=["UDP", "TCP", "SSL"],
                path="transport",
            )
        )
        params.append(VersionedParamPath("port", vartype="int", path="port"))
        params.append(
            VersionedParamPath(
                "format", default="BSD", values=["BSD", "IETF"], path="format"
            )
        )
        params.append(
            VersionedParamPath(
                "facility",
                default="LOG_USER",
                path="facility",
                values=["LOG_USER",] + ["LOG_LOCAL{0}".format(x) for x in range(8)],
            )
        )

        self._params = tuple(params)


class HttpServerProfile(VersionedPanObject):
    """A HTTP server profile.

    Note:  This is valid for PAN-OS 8.0+.

    Args:
        name (str): The name
        tag_registration (bool): The server should have User-ID agent running
            in order for tag registration to work
        config_name (str): Name for custom config format
        config_uri_format (str): URI format for custom config format
        config_payload (str): Payload for custom config format
        system_name (str): Name for custom system format
        system_uri_format (str): URI format for custom system format
        system_payload (str): Payload for custom system format
        threat_name (str): Name for custom threat format
        threat_uri_format (str): URI format for custom threat format
        threat_payload (str): Payload for custom threat format
        traffic_name (str): Name for custom traffic format
        traffic_uri_format (str): URI format for custom traffic format
        traffic_payload (str): Payload for custom traffic format
        hip_match_name (str): Name for custom HIP match format
        hip_match_uri_format (str): URI format for custom HIP match format
        hip_match_payload (str): Payload for custom HIP match format
        url_name (str): Name for custom url format
        url_uri_format (str): URI format for custom url format
        url_payload (str): Payload for custom url format
        data_name (str): Name for custom data format
        data_uri_format (str): URI format for custom data format
        data_payload (str): Payload for custom data format
        wildfire_name (str): Name for custom wildfire format
        wildfire_uri_format (str): URI format for custom wildfire format
        wildfire_payload (str): Payload for custom wildfire format
        tunnel_name (str): Name for custom tunnel format
        tunnel_uri_format (str): URI format for custom tunnel format
        tunnel_payload (str): Payload for custom tunnel format
        user_id_name (str): Name for custom User-ID format
        user_id_uri_format (str): URI format for custom User-ID format
        user_id_payload (str): Payload for custom User-ID format
        gtp_name (str): Name for custom GTP format
        gtp_uri_format (str): URI format for custom GTP format
        gtp_payload (str): Payload for custom GTP format
        auth_name (str): Name for custom auth format
        auth_uri_format (str): URI format for custom auth format
        auth_payload (str): Payload for custom auth format
        sctp_name (str): (PAN-OS 8.1+) Name for custom SCTP format
        sctp_uri_format (str): (PAN-OS 8.1+) URI format for custom SCTP format
        sctp_payload (str): (PAN-OS 8.1+) Payload for custom SCTP format
        iptag_name (str): (PAN-OS 9.0+) Name for custom IP tag format
        iptag_uri_format (str): (PAN-OS 9.0+) URI format for custom IP tag format
        iptag_payload (str): (PAN-OS 9.0+) Payload for custom IP tag format

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = (
        "device.HttpServer",
        "device.HttpConfigHeader",
        "device.HttpConfigParam",
        "device.HttpSystemHeader",
        "device.HttpSystemParam",
        "device.HttpThreatHeader",
        "device.HttpThreatParam",
        "device.HttpTrafficHeader",
        "device.HttpTrafficParam",
        "device.HttpHipMatchHeader",
        "device.HttpHipMatchParam",
        "device.HttpUrlHeader",
        "device.HttpUrlParam",
        "device.HttpDataHeader",
        "device.HttpDataParam",
        "device.HttpWildfireHeader",
        "device.HttpWildfireParam",
        "device.HttpTunnelHeader",
        "device.HttpTunnelParam",
        "device.HttpUserIdHeader",
        "device.HttpUserIdParam",
        "device.HttpGtpHeader",
        "device.HttpGtpParam",
        "device.HttpAuthHeader",
        "device.HttpAuthParam",
        "device.HttpSctpHeader",
        "device.HttpSctpParam",
        "device.HttpIpTagHeader",
        "device.HttpIpTagParam",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/log-settings/http")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "tag_registration", vartype="yesno", path="tag-registration"
            )
        )
        params.append(VersionedParamPath("config_name", path="format/config/name"))
        params.append(
            VersionedParamPath("config_uri_format", path="format/config/url-format")
        )
        params.append(
            VersionedParamPath("config_payload", path="format/config/payload")
        )
        params.append(VersionedParamPath("system_name", path="format/system/name"))
        params.append(
            VersionedParamPath("system_uri_format", path="format/system/url-format")
        )
        params.append(
            VersionedParamPath("system_payload", path="format/system/payload")
        )
        params.append(VersionedParamPath("threat_name", path="format/threat/name"))
        params.append(
            VersionedParamPath("threat_uri_format", path="format/threat/url-format")
        )
        params.append(
            VersionedParamPath("threat_payload", path="format/threat/payload")
        )
        params.append(VersionedParamPath("traffic_name", path="format/traffic/name"))
        params.append(
            VersionedParamPath("traffic_uri_format", path="format/traffic/url-format")
        )
        params.append(
            VersionedParamPath("traffic_payload", path="format/traffic/payload")
        )
        params.append(
            VersionedParamPath("hip_match_name", path="format/hip-match/name")
        )
        params.append(
            VersionedParamPath(
                "hip_match_uri_format", path="format/hip-match/url-format"
            )
        )
        params.append(
            VersionedParamPath("hip_match_payload", path="format/hip-match/payload")
        )
        params.append(VersionedParamPath("url_name", path="format/url/name"))
        params.append(
            VersionedParamPath("url_uri_format", path="format/url/url-format")
        )
        params.append(VersionedParamPath("url_payload", path="format/url/payload"))
        params.append(VersionedParamPath("data_name", path="format/data/name"))
        params.append(
            VersionedParamPath("data_uri_format", path="format/data/url-format")
        )
        params.append(VersionedParamPath("data_payload", path="format/data/payload"))
        params.append(VersionedParamPath("wildfire_name", path="format/wildfire/name"))
        params.append(
            VersionedParamPath("wildfire_uri_format", path="format/wildfire/url-format")
        )
        params.append(
            VersionedParamPath("wildfire_payload", path="format/wildfire/payload")
        )
        params.append(VersionedParamPath("tunnel_name", path="format/tunnel/name"))
        params.append(
            VersionedParamPath("tunnel_uri_format", path="format/tunnel/url-format")
        )
        params.append(
            VersionedParamPath("tunnel_payload", path="format/tunnel/payload")
        )
        params.append(VersionedParamPath("user_id_name", path="format/userid/name"))
        params.append(
            VersionedParamPath("user_id_uri_format", path="format/userid/url-format")
        )
        params.append(
            VersionedParamPath("user_id_payload", path="format/userid/payload")
        )
        params.append(VersionedParamPath("gtp_name", path="format/gtp/name"))
        params.append(
            VersionedParamPath("gtp_uri_format", path="format/gtp/url-format")
        )
        params.append(VersionedParamPath("gtp_payload", path="format/gtp/payload"))
        params.append(VersionedParamPath("auth_name", path="format/auth/name"))
        params.append(
            VersionedParamPath("auth_uri_format", path="format/auth/url-format")
        )
        params.append(VersionedParamPath("auth_payload", path="format/auth/payload"))
        params.append(VersionedParamPath("sctp_name", exclude=True))
        params[-1].add_profile("8.1.0", path="format/sctp/name")
        params.append(VersionedParamPath("sctp_uri_format", exclude=True))
        params[-1].add_profile("8.1.0", path="format/sctp/url-format")
        params.append(VersionedParamPath("sctp_payload", exclude=True))
        params[-1].add_profile("8.1.0", path="format/sctp/payload")
        params.append(VersionedParamPath("iptag_name", exclude=True))
        params[-1].add_profile("9.0.0", path="format/iptag/name")
        params.append(VersionedParamPath("iptag_uri_format", exclude=True))
        params[-1].add_profile("9.0.0", path="format/iptag/url-format")
        params.append(VersionedParamPath("iptag_payload", exclude=True))
        params[-1].add_profile("9.0.0", path="format/iptag/payload")

        self._params = tuple(params)


class HttpServer(VersionedPanObject):
    """A single HTTP server in a HTTP server profile.

    Args:
        name (str): The name
        address (str): IP address or FQDN of HTTP server to use
        protocol (str): HTTPS (default) or HTTP
        port (int): Port number (default: 443).
        tls_version (str): (PAN-OS 9.0+) TLS handshake protocol version.  Valid
            values are 1.0, 1.1, or 1.2.
        certificate_profile (str): (PAN-OS 9.0+) Certificate profile for
            validating server certificate
        http_method (str): HTTP method to use (default: POST).
        username (str): Username for basic HTTP auth
        password (str): Password for basic HTTP auth

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/server")

        # params
        params = []

        params.append(VersionedParamPath("address", path="address"))
        params.append(
            VersionedParamPath(
                "protocol", default="HTTPS", values=["HTTP", "HTTPS"], path="protocol"
            )
        )
        params.append(
            VersionedParamPath("port", default=443, vartype="int", path="port")
        )
        params.append(VersionedParamPath("tls_version", exclude=True))
        params[-1].add_profile(
            "9.0.0", values=["1.0", "1.1", "1.2"], path="tls-version"
        )
        params.append(VersionedParamPath("certificate_profile", exclude=True))
        params[-1].add_profile("9.0.0", path="certificate-profile")
        params.append(
            VersionedParamPath("http_method", default="POST", path="http-method")
        )
        params.append(VersionedParamPath("username", path="username"))
        params.append(
            VersionedParamPath("password", vartype="encrypted", path="password")
        )

        self._params = tuple(params)


class HttpConfigHeader(ValueEntry):
    """HTTP header for config.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/config/headers"


class HttpConfigParam(ValueEntry):
    """HTTP param for config.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/config/params"


class HttpSystemHeader(ValueEntry):
    """HTTP header for system.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/system/headers"


class HttpSystemParam(ValueEntry):
    """HTTP param for system.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/system/params"


class HttpThreatHeader(ValueEntry):
    """HTTP header for threat.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/threat/headers"


class HttpThreatParam(ValueEntry):
    """HTTP param for threat.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/threat/params"


class HttpTrafficHeader(ValueEntry):
    """HTTP header for traffic.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/traffic/headers"


class HttpTrafficParam(ValueEntry):
    """HTTP param for traffic.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/traffic/params"


class HttpHipMatchHeader(ValueEntry):
    """HTTP header for HIP match.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/hip-match/headers"


class HttpHipMatchParam(ValueEntry):
    """HTTP param for HIP match.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/hip-match/params"


class HttpUrlHeader(ValueEntry):
    """HTTP header for URL.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/url/headers"


class HttpUrlParam(ValueEntry):
    """HTTP param for URL.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/url/params"


class HttpDataHeader(ValueEntry):
    """HTTP header for data.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/data/headers"


class HttpDataParam(ValueEntry):
    """HTTP param for data.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/data/params"


class HttpWildfireHeader(ValueEntry):
    """HTTP header for WildFire.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/wildfire/headers"


class HttpWildfireParam(ValueEntry):
    """HTTP param for WildFire.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/wildfire/params"


class HttpTunnelHeader(ValueEntry):
    """HTTP header for tunnel.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/tunnel/headers"


class HttpTunnelParam(ValueEntry):
    """HTTP param for tunnel.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/tunnel/params"


class HttpUserIdHeader(ValueEntry):
    """HTTP header for user-ID.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/userid/headers"


class HttpUserIdParam(ValueEntry):
    """HTTP param for user-ID.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/userid/params"


class HttpGtpHeader(ValueEntry):
    """HTTP header for GTP.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/gtp/headers"


class HttpGtpParam(ValueEntry):
    """HTTP param for GTP.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/gtp/params"


class HttpAuthHeader(ValueEntry):
    """HTTP header for auth.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/auth/headers"


class HttpAuthParam(ValueEntry):
    """HTTP param for auth.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/auth/params"


class HttpSctpHeader(ValueEntry):
    """HTTP header for SCTP.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/sctp/headers"


class HttpSctpParam(ValueEntry):
    """HTTP param for SCTP.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/sctp/params"


class HttpIpTagHeader(ValueEntry):
    """HTTP header for IP tag.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The header name
        value (str): The header value

    """

    LOCATION = "/format/iptag/headers"


class HttpIpTagParam(ValueEntry):
    """HTTP param for IP tag.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The param name
        value (str): The param value

    """

    LOCATION = "/format/iptag/params"

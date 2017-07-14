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

from pandevice.base import PanObject, Root, MEMBER, ENTRY
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath

# import other parts of this pandevice package
from pandevice import getlogger
import pandevice.errors as err

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
        self._xpaths.add_profile(value='/import/resource')

        # params
        params = []

        int_params = ("max-security-rules", "max-nat-rules",
            "max-ssl-decryption-rules", "max-qos-rules",
            "max-application-override-rules", "max-pbf-rules",
            "max-cp-rules", "max-dos-rules", "max-site-to-site-vpn-tunnels",
            "max-concurrent-ssl-vpn-tunnels", "max-sessions",
        )
        for x in int_params:
            params.append(VersionedParamPath(x, path=x, vartype='int'))

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
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/vsys')

        # params
        params = []

        params.append(VersionedParamPath(
            'display_name', path='display-name'))
        params.append(VersionedParamPath(
            'interface', vartype='member',
            path='import/network/interface'))
        params.append(VersionedParamPath(
            'vlans', vartype='member',
            path='import/network/vlan'))
        params.append(VersionedParamPath(
            'virtual_wires', vartype='member',
            path='import/network/virtual-wire'))
        params.append(VersionedParamPath(
            'virtual_routers', vartype='member',
            path='import/network/virtual-router'))
        params.append(VersionedParamPath(
            'visible_vsys', vartype='member',
            path='import/visible-vsys'))
        params.append(VersionedParamPath(
            'dns_proxy', path='import/dns-proxy'))
        params.append(VersionedParamPath(
            'decrypt_forwarding', vartype='yesno',
            path='setting/ssl-decrypt/allow-forward-decrypted-content'))

        self._params = tuple(params)

    def xpath_vsys(self):
        if self.name == "shared":
            return "/config/shared"
        elif self.name is None:
            return self._root_xpath_vsys('vsys1')
        else:
            return self._root_xpath_vsys(self.name)

    def _build_xpath(self, root):
        if root == Root.VSYS:
            return super(Vsys, self)._build_xpath(root)
        else:
            # If original object is not a VSYS Root, then bypass the vsys part of the xpath
            if self.parent is None:
                return ""
            else:
                return self.parent._build_xpath(root)

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
        return (
            Var("ntp-server-address", "address"),
        )


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


class SystemSettings(PanObject):
    """Firewall or Panorama device system settings

    Add only one of these to a parent object.

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

    """
    NAME = None
    ROOT = Root.DEVICE
    XPATH = "/deviceconfig/system"
    HA_SYNC = False
    CHILDTYPES = (
        "device.NTPServerPrimary",
        "device.NTPServerSecondary",
    )

    @classmethod
    def variables(cls):
        return (
            Var("hostname"),
            Var("domain"),
            Var("ip-address"),
            Var("netmask"),
            Var("default-gateway"),
            Var("ipv6-address"),
            Var("ipv6-default-gateway"),
            Var("dns-setting/servers/primary", "dns_primary"),
            Var("dns-setting/servers/secondary", "dns_secondary"),
            Var("timezone"),
            Var("panorama-server", "panorama"),
            Var("panorama-server-2", "panorama2"),
            Var("login-banner"),
            Var("update-server"),
        )


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
        self._xpaths.add_profile(value='/password-profile')

        # params
        params = []

        params.append(VersionedParamPath(
            'expiration', vartype='int',
            path='password-change/expiration-period'))
        params.append(VersionedParamPath(
            'warning', vartype='int',
            path='password-change/expiration-warning-period'))
        params.append(VersionedParamPath(
            'login_count', vartype='int',
            path='password-change/post-expiration-admin-login-count'))
        params.append(VersionedParamPath(
            'grace_period', vartype='int',
            path='password-change/post-expiration-grace-period'))

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
        self._xpaths.add_profile(value='/users')

        # params
        params = []

        params.append(VersionedParamPath(
            'authentication_profile', path='authentication-profile'))
        params.append(VersionedParamPath(
            'web_client_cert_only', vartype='yesno',
            path='client-certificate-only'))
        params.append(VersionedParamPath(
            'superuser', vartype='yesno',
            path='permissions/role-based/superuser'))
        params.append(VersionedParamPath(
            'superuser_read_only', vartype='yesno',
            path='permissions/role-based/superreader'))
        params.append(VersionedParamPath(
            'panorama_admin', vartype='yesno',
            path='permissions/role-based/panorama-admin'))
        params.append(VersionedParamPath(
            'device_admin', vartype='exist',
            path='permissions/role-based/deviceadmin'))
        params.append(VersionedParamPath(
            'device_admin_read_only', vartype='exist',
            path='permissions/role-based/devicereader'))
        params.append(VersionedParamPath(
            'vsys', vartype='member',
            path='permissions/role-based/vsysadmin/entry vsys_device/vsys'))
        params.append(VersionedParamPath(
            'vsys_read_only', vartype='member',
            path='permissions/role-based/vsysreader' +
                 '/entry vsys_read_only_device/vsys'))
        params.append(VersionedParamPath(
            'ssh_public_key', path='public-key'))
        params.append(VersionedParamPath(
            'role_profile', path='permissions/role-based/custom/profile'))
        params.append(VersionedParamPath(
            'password_hash', path='phash', vartype='encrypted'))
        params.append(VersionedParamPath(
            'password_profile', path='password-profile'))
        params.append(VersionedParamPath(
            'vsys_device', exclude=True, vartype='entry',
            path='permissions/role-based/vsysadmin',
            default='localhost.localdomain'))
        params.append(VersionedParamPath(
            'vsys_read_only_device', exclude=True, vartype='entry',
            path='permissions/role-based/vsysreader',
            default='localhost.localdomain'))

        self._params = tuple(params)

    def change_password(self, new_password):
        """Update the password.

        **Modifies the live device**

        Args:
            new_password (str): The new password for this user.

        """
        dev = self.nearest_pandevice()
        self.password_hash = dev.request_password_hash(new_password)
        self.update('password_hash')

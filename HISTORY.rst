.. :changelog:

Release Notes
=============

0.14.0
------

Released: 2020-01-14

Status: Alpha

New Classes:

- `objects.DynamicUserGroup`
- `policies.PolicyBasedForwarding`

Other Updates:

- Added dynamic user group (DUG) support to the userid namespace
- Fixes to `network.AggregateInterface`
- Removed default value from `network.IkeGateway.peer_id_check`
- Docstring updates

0.13.0
------

Released: 2019-10-29

Status: Alpha

- New flag added to examples/dyn_address_group.py to specify the vsys
- Fixes to `network.AggregateInterface`
- Update to version parsing to handle xfr PAN-OS releases
- Fixes to Panorama commit functions
- Various enhancements to HA support

0.12.0
------

Released: 2019-09-24

Status: Alpha

New Classes:

- `panorama.TemplateVariable`

Other updates:

- New params added to ethernet interfaces
- Fixed `show_system_resources()` for PAN-OS 9.0+
- Added `.rename()` to rename objects.
- Documentation fixes
- Various bug fixes

0.11.1
------

Released: 2019-06-10

Status: Alpha

- Changed various log forwarding class names
- Fixed numerous docstrings
- Fixed some parameter paths

0.11.0
------

Released: 2019-06-06

Status: Alpha

- Added `network.GreTunnel`
- Added `uuid` params for security and NAT rules
- Fixed User-ID's `get_registered_ip()`
- Added `objects.LogForwardingProfile` and related sub-objects
- Added `device.SnmpServerProfile` and related sub-objects
- Added `device.EmailServerProfile` and related sub-objects
- Added `device.SyslogServerProfile` and related sub-objects
- Added `device.HttpServerProfile` and related sub-objects

0.10.0
------

Released: 2019-05-07

Status: Alpha

- Added `device.Telemetry`

0.9.1
-----

Released: 2019-04-24

Status: Alpha

- Added additional handling for authcode activation responses from PAN-OS.

0.9.0
-----

Released: 2019-04-22

Status: Alpha

- Added `VlanInterface.set_vlan_interface()`
- Minor bug fix

0.8.0
-----

Released: 2019-03-25

Status: Alpha

- Added flag to control VsysOperation's filtering on `refreshall()`
- Fixed virtual router's childtypes - `RedistributionProfileIPv6` now shows up

0.7.0
-----

Released: 2019-03-15

Status: Alpha

- Added `next-vr` as an option for static route next hop types
- Updated `set_vsys()` / `set_virtual_router()` / `set_vlan()` / `set_zone()` work with templates and template stacks
- Added panorama functions for VM auth keys
- Added child object support for template stacks
- Added `objects.CustomUrlCategory`
- Added `network.Bgp`
- Added `network.RedistributionProfile`
- Added `network.RedistributionProfileIPv6`
- Added `network.BgpRoutingOptions`
- Added `network.BgpOutboundRouteFilter`
- Added `network.BgpDampeningProfile`
- Added `network.BgpAuthProfile`
- Added `network.BgpPeerGroup`
- Added `network.BgpPeer`
- Added `network.BgpPolicyFilter`
- Added `network.BgpPolicyNonExistFilter`
- Added `network.BgpPolicyAdvertiseFilter`
- Added `network.BgpPolicySuppressFilter`
- Added `network.BgpPolicyConditionalAdvertisement`
- Added `network.BgpPolicyRule`
- Added `network.BgpPolicyImportRule`
- Added `network.BgpPolicyExportRule`
- Added `network.BgpPolicyAddressPrefix`
- Added `network.BgpPolicyAggregationAddress`
- Added `network.BgpRedistributionRule`
- Minor bug fixes

0.6.6
-----

Released: 2018-10-16

Status: Alpha

- Added `test_security_policy_match()` to PanDevice objects

0.6.5
-----

Released: 2018-10-07

Status: Alpha

- Fixed: ICMP Unreachable param type in security rules
- Fixed: Content upgrade error
- Fixed: (Python3) The comparison of encrypted types
- Various documentation fixes

0.6.4
-----

Released: 2018-07-10

Status: Alpha

- Added .move() function to move config elements
- Added objects.SecurityProfileGroup
- Added "devices" param to panorama.TemplateStack
- Added dynamic NAT translation support for PAN-OS 8.1+
- Fixed ha.HighAvailability for PAN-OS 8.1+

0.6.3
-----

Released: 2018-05-15

Status: Alpha

- Fixed: uid always returns a string

0.6.2
-----

Released: 2018-05-03

Status: Alpha

- Fixed: issue in error checking

0.6.1
-----

Released: 2018-03-27

Status: Alpha

- Added: visualize configuration tree in Jupyter Notebooks and graphviz
- Fixed: small xpath generation issue
- Fixed: uid is equal to id when id exists


0.6.0
-----

Released: 2018-03-16

Status: Alpha

- Added initial support for templates and template stacks
- Added: Support for timeouts for logins in user-id module
- Added: `panorama.Template`
- Added: `panorama.TemplateStack`
- Fix: Vsys native objects added under a Panorama will be put in `shared` scope


0.5.3
-----

Released: 2018-01-30

Status: Alpha

- Added: `network.IkeGateway`
- Added: `network.IpsecTunnel`
- Added: `network.IpsecTunnelIpv4ProxyId`
- Added: `network.IpsecTunnelIpv6ProxyId`
- Added: `network.IpsecCryptoProfile`
- Added: `network.IkeCryptoProfile`
- Fix: `enable_ipv6` XPath for various network interface has been corrected


0.5.2
-----

Released: 2017-11-30

Status: Alpha

- Adding DHCP management interface options to `device.SystemSettings`
- Various bug fixes


0.5.1
-----

Released: 2017-09-12

Status: Alpha

- Fix: Security and NAT policy XPATH problems
- Fix: `base.PanDevice.create_from_device()`'s check for certain Panorama devices
- Fix: `firewall.Firewall.organize_into_vsys()`'s behavior with importables that aren't imported
- Fix: `refreshall()`'s behavior when it has a `device.Vsys` parent


0.5.0
-----

Released: 2017-07-14

Status: Alpha

- Add: Support for python3 (3.5+)
- Add: Support for predefined tags
- Add: Support for bulk operations (e.g. - `create_similar()`)
- Add: DHCP support for various data interface objects
- Add: `request_password_hash()` to firewall / panorama devices
- Change: Layer2Subinterface/Layer3Subinterface can be children of vsys or firewalls now
- Fix: `equals()` for objects with list params


Potentially breaking-changes in this version, please update your scripts to account for the following:

- The default vsys for firewalls is changed from "vsys1" to None.  This has no effect for scripts that set the vsys on the firewall object directly (vsys is still treated as vsys1 in this situation).  This specific change was to better align pandevice with the default behavior of the firewall, which only imports interfaces by default (vsys1 if otherwise unspecified).  Thus, virtual wire, virtual routers, and VLANs will only be imported if they are attached to a Vsys object *or* the firewall has a vsys set.
- VsysResources and SystemSettings now have a name of None
- SubinterfaceArp and EthernetInterfaceArp have been replaced with Arp


List of PanObject changes:

- Added: PasswordProfile
- Added: Administrator
- Added: Arp
- Updated: Zone
- Updated: Vsys
- Fixed: StaticRouteV6
- Fixed: OspfNsaaExternalRange


- New example scripts:

  - bulk_address_objects.py
  - bulk_subinterfaces.py


0.4.1
-----

Released: 2017-05-12

Status: Alpha

- Add: Support new HA error added in PAN-OS 7.1
- Fix: Issue where existing references are sometimes removed when adding a new reference
- Fix: AttributeError on None when refreshing device-groups and none exist yet

0.4.0
-----

Released: 2017-03-17

Status: Alpha

- Now supports PAN-OS 7.0, 7.1, and 8.0
- Support added for the following Firewall/Panorama features:

  - NAT
  - OSPF
  - Applications
  - Services
  - Interface Management Profiles

- Support for some predefined objects (such as applications from content packs)
- Convenience methods for common licensing functions
- New introspective method to describe current state of object: about()


Breaking-changes in this version, please update your scripts to account for the following:

- `pandevice()` method changed to `nearest_pandevice()`
- Arguments of `refresh()` method are in a different order for better consistency


Full list of new PanObjects:

- NatRule
- ServiceObject
- ServiceGroup
- ApplicationObject
- ApplicationGroup
- ApplicationFilter
- ApplicationContainer
- RedistributionProfile
- Ospf
- OspfArea
- OspfRange
- OspfNssaExternalRange
- OspfAreaInterface
- OspfNeighbor
- OspfAuthProfile
- OspfAuthProfileMd5
- OspfExportRules
- ManagementProfile


0.3.5
-----

Released: 2016-07-25

Status: Alpha

Bug fixes and documentation updates

0.3.4
-----

Released: 2016-04-18

Status: Alpha

Added tag variable to the following objects:

* objects.AddressObject
* objects.AddressGroup

0.3.3
-----

Released: 2016-04-15

Status: Alpha

New objects:

* objects.Tag

Updated objects:

* policies.Rulebase

0.3.2
-----

Released: 2016-04-13

Status: Alpha

New objects:

* policies.Rulebase
* policies.PreRulebase
* policies.PostRulebase

0.3.1
-----

Released: 2016-04-12

Status: Alpha

New objects:

* policies.SecurityRule
* objects.AddressGroup

API changes:

* Changed refresh_all to refreshall and apply_all to applyall
* Added insert() method to PanObject base class

Fixes:

* Objects can now be added as children of Panorama which will make them 'shared'
* Fixes for tracebacks
* Minor fixes to documentation and docstrings

0.3.0
-----

Released: 2016-03-30

Status: Alpha

* First release on pypi
* Significant redesign from 0.2.0
* Configuration tree model

0.2.0
-----

Released: 2014-09-17

Status: Pre-alpha

* First release on github

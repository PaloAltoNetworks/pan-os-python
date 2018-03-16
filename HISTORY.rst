.. :changelog:

History
=======

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

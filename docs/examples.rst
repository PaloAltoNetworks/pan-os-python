.. _examples:

Examples
========

Example scripts
---------------

There are several example scripts written as CLI programs in the [examples
directory](https://github.com/PaloAltoNetworks/pan-os-python/tree/develop/examples).

Cookbook examples
-----------------

Get the version of a firewall
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  from panos.firewall import Firewall

  fw = Firewall("10.0.0.1", "admin", "mypassword")
  version = fw.refresh_system_info().version
  print version

Example output::

  10.0.3
  

We use ``refresh_system_info()`` here instead of an op commands because this
method saves the version information to the Firewall object which tells all
future API calls what format to use to be compatible with this version.

Print a firewall rule
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  from panos.firewall import Firewall
  from panos.policies import Rulebase, SecurityRule

  # Create a config tree for the rule
  fw = Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys1")
  rulebase = fw.add(Rulebase())
  rule = rulebase.add(SecurityRule("my-rule"))

  # Refresh the rule from the live device and print it
  rule.refresh()
  print(rule.about())

List of firewall rules by name
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  from panos.firewall import Firewall
  from panos.policies import Rulebase, SecurityRule

  # Create config tree and refresh rules from live device
  fw = Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys1")
  rulebase = fw.add(Rulebase())
  rules = SecurityRule.refreshall(rulebase)

  for rule in rules:
      print(rule.name)
  
List of pre-rules on Panorama
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

  from panos.panorama import Panorama
  from panos.policies import PreRulebase, SecurityRule

  # Create config tree and refresh rules from live device
  pano = Panorama("10.0.0.1", "admin", "mypassword")
  pre_rulebase = pano.add(PreRulebase())
  rules = SecurityRule.refreshall(pre_rulebase)

  for rule in rules:
      print(rule.name)

List firewall devices in Panorama
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Print the serial, hostname, and management IP of all firewalls
that Panorama knows about.

.. code-block:: python

  from panos.panorama import Panorama
  from panos.device import SystemSettings

  # Create config tree root
  pano = Panorama("10.0.0.1", "admin", "mypassword")

  # Refresh firewalls from live Panorama
  devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)

  # Print each firewall's serial and management IP
  for device in devices:
      system_settings = device.find("", SystemSettings)
      print(f"{device.serial} {system_settings.hostname} {system_settings.ip_address}")

Example output::

  310353000003333 PA-VM-1 10.1.1.1
  310353000003334 PA-VM-2 10.1.1.2

Upgrade a firewall
~~~~~~~~~~~~~~~~~~

.. code-block:: python

  from panos.firewall import Firewall

  fw = Firewall("10.0.0.1", "admin", "mypassword")
  fw.software.upgrade_to_version("10.1.5")

This simple example will upgrade from any previous version to the target version
and handle all intermediate upgrades and reboots.

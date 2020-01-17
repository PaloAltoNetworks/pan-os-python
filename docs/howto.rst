.. _howto:

How-to Guides
=============

Connect via Panorama
--------------------

Making changes to Panorama is always done the same way, with a connection to Panorama.
But, there are a different options to make local changes to a Firewall.

**Option 1: Connect to the Firewall and Panorama directly**

When making changes to Panorama, connect to Panorama.
When making changes to the Firewall, connect directly to the Firewall.

.. graphviz::

   digraph directconnect {
      graph [rankdir=LR, fontsize=10, margin=0.001];
      node [shape=box, fontsize=10, height=0.001, margin=0.1, ordering=out];
      "python script" -> "Panorama";
      "python script" -> "Firewall";
      Panorama [style=filled];
      Firewall [style=filled];
   }

This method is best in the following cases:

- Firewall managment IP is accessible to the script
- The credentials for both devices are known
- The permissions/role for the user are set on both devices
- The serial of the firewall is unknown, but the management IP is known

To use this method:

1. Create a :class:`pandevice.firewall.Firewall` instance and a
   :class:`pandevice.panorama.Panorama` instance.
2. In both instances, set the 'hostname' attribute and either the
   'api_key' or the 'api_username' and 'api_password' attributes.

Example::

    # Instantiate a Firewall with hostname and credentials
    fw = firewall.Firewall("10.0.0.1", "admin", "mypassword")
    # Instantiate a Panorama with hostname and credentials
    pano = panorama.Panorama("10.0.0.5", "admin", "mypassword")
    # Change to Firewall
    fw.add(objects.AddressObject("Server", "2.2.2.2")).create()
    # Change to Panorama
    pano.add(panorama.DeviceGroup("CustomerA")).create()

In this example, the address object is added to the Firewall directly, without
any connection to Panorama. Then a device-group is created on Panorama directly,
without any connection to the Firewall.

**Option 2: Connect to Firewall via Panorama**

When making changes to the Firewall, connect to Panorama which
will proxy the connection to the Firewall. Meaning all connections
are to Panorama.

.. graphviz::

   digraph directconnect {
      graph [rankdir=LR, fontsize=10, margin=0.001];
      node [shape=box, fontsize=10, height=0.001, margin=0.1, ordering=out];
      "pandevice script" -> "Panorama" -> "Firewall";
      Panorama [style=filled];
      Firewall [style=filled];
   }

This method is best in the following cases:

- The Firewall management IP is unknown or not reachable from the script
- You only store one set of credentials (Panorama)
- The serial of the firewall is known or can be determined from Panorama

To use this method:

1. Create a :class:`pandevice.firewall.Firewall` instance and a
   :class:`pandevice.panorama.Panorama` instance.
2. In the Panorama instance, set the 'hostname' attribute and either the
   'api_key' or the 'api_username' and 'api_password' attributes.
3. In the Firewall instance, set the 'serial' attribute.
4. Add the Firewall as a child of Panorama, or as a child of a DeviceGroup under Panorama.

Example::

    # Instantiate a Firewall with serial
    fw = firewall.Firewall(serial="0002487YR3880")
    # Instantiate a Panorama with hostname and credentials
    pano = panorama.Panorama("10.0.0.5", "admin", "mypassword")
    # Add the Firewall as a child of Panorama
    pano.add(fw)
    # Change to Firewall via Panorama
    fw.add(objects.AddressObject("Server", "2.2.2.2")).create()
    # Change to Panorama directly
    pano.add(panorama.DeviceGroup("CustomerA")).create()

In this example, both changes are made with connections to Panorama. First, the
address object is added to the Firewall by connecting to Panorama which proxies the
API call to the Firewall. Then a device-group is created on Panorama directly.

Work with Virtual Systems (VSYS)
--------------------------------

There's a great blog post by the Developer Relations team on how to work with
vsys in python. You can read it here:

https://medium.com/palo-alto-networks-developer-blog/handling-pan-os-vsys-in-pandevice-212fe892d303

A Firewall PanDevice can represent a firewall or a virtual system (vsys). By default, a Firewall
instance represents a single context firewall, or 'vsys1' on a multi-vsys firewall.

When working with a firewall with multi-vsys mode enabled, there are two methods to work with vsys:

**Method 1: A different Firewall instance for each vsys**

Each Firewall object has a 'vsys' attribute which is assigned the vsys id.  For example::

    fw_vsys2 = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys2")
    fw_vsys3 = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys3")

When using this method, non-vsys-specific configuration should be modified using a 'shared' PanDevice::

    fw = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="shared")

To create or delete an entire vsys, use the create_vsys() and delete_vsys() methods::

    fw_vsys2.create_vsys()
    fw_vsys3.delete_vsys()

**Method 2: A single Firewall instance with Vsys child instances**

Create Vsys instances and add them to a 'shared' PanDevice::

    fw = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="shared")
    vsys2 = device.Vsys("vsys2")
    vsys3 = device.Vsys("vsys3")
    fw.add(vsys2)
    fw.add(vsys3)

Configuration objects are added to the Vsys instances instead of the Firewall instance::

    ao = vsys2.add(objects.AddressObject("MyIP", "2.2.2.2"))
    ao.create()

The vsys itself can be created and deleted using the standard configuration tree methods::

    vsys2.create()
    vsys3.delete()

High Availability Pairs
-----------------------

This library tries to handle High Availability (HA) pairs of devices as
elegantly as possible. Having two devices can pose challenges because some
configuration needs to be applied to both firewalls, while other configuration
should be applied only to the active firewall. Also, two devices implies two
pandevice configuration trees. But, pandevice offers a few features to make
working with HA pairs easier:

- Only one configuration tree to manage for an HA pair
- Automatically knows which firewall to talk to
- Detects when a firewall is not reachable and automatically switches to the other firewall
- Knows which configuration should be applied to the active firewall and which
  should be made on both firewalls, and handles this for you under the hood

There's just a couple extra steps to ensure your HA experience is smooth. While
not strictly necessary, it's a good idea to verify the state of the HA before
making configuration changes, so you know configuration will sync properly to
the standby device.

Here's an example of configuration with an HA pair of firewalls::

    from pandevice.firewall import Firewall
    from pandevice.objects import AddressObject

    # Don't assume either firewall is primary or active.
    # Just start by telling pandevice they are an HA pair
    # and how to connect to them.
    fw = Firewall('10.0.0.1', 'admin', 'password')
    fw.set_ha_peers(Firewall('10.0.0.2', 'admin', 'password'))

    # Notice I didn't save the second firewall to a variable, because I don't need it.
    # The point is to treat the HA pair as one firewall, so we only need one variable.
    # This way, we have only one pandevice configuration tree to manage,
    # NOT one tree for each fw in the pair.

    # At this point, it's a good idea to collect the active/passive state from
    # the live devices. This stores which firewall is active to an internal
    # state machine in the Firewall object.
    fw.refresh_ha_active()

    # Now, verify the config is synced between the devices.
    # If it's not synced, force config synchronization from active to standby
    if not fw.config_synced():
        fw.synchronize_config()  # blocks until synced or error

    # Now, it's completely safe to use all the configuration methods as usual
    # on the one fw variable.
    obj = AddressObject('test', '10.0.1.1')
    fw.add(obj)
    obj.create()

In the above code, we added the AddressObject to the ``fw`` variable. Even
though we created this above with the IP of 10.0.0.1, it represents both
firewalls in the pair. So when we create the AddressObject on the live device,
pandevice will reach out to the active firewall in the pair. It will
automatically detect if the active failed and switch to standby.

Note: We didn't save the second firewall to a variable, because our ``fw`` variable
represents both firewalls, but if you need to access the second firewall as a
variable, it's available to you at ``fw.ha_peer``.

Optimize with Bulk Operations
-----------------------------

Each API call takes time and consumes management plane resources on the
firewall or Panorama. While this won't affect traffic, it does limit the number
of changes that can take place in a time period.

**Example:** if you're adding policy for all your branch offices and need to add
200 address groups with 20 address objects each, creating them individually
would be 200 x 20 + 200 = 4200 API calls. If your device can process an API call in 1
second, then this operation would take *over an hour* to complete. Even if you
applied concurrency up to 5 API calls simultaneously, it's still over 10 minutes
of waiting.

We can do this faster with **bulk operations**.

The methods used to push these objects to a live device individually are ``create()``,
``apply()``, and ``delete()``. Each of these has a bulk counterpart:
``create_similar()``, ``apply_similar()``, and ``delete_similar()``.

The bulk version of the method is called exactly the same way as the individual
version, but the behavior is different. Instead of sending this single object to
the device, all objects in the configuration tree with this type and location in
the tree are pushed to the live device in a single API call.

Here's code for the above example using individual API calls and using bulk operations::

    from pandevice.firewall import Firewall
    from pandevice.objects import AddressObject, AddressGroup

    # Build out the configuration tree with a Firewall object at the root and an
    # array of AddressObjects and AddressGroups as children of the Firewall
    fw1 = Firewall('10.0.0.1', 'admin', 'password')
    # Create 200 AddressGroups with 20 AddressObjects each
    for i in range(0, 200):
        addr_objects = [AddressObject('object{}'.format(i*20+j), '192.168.{0}.{1}'.format(i, j)) for j in range(0, 20)]
        fw.extend(addr_objects)
        grp = AddressGroup('group{}'.format(i), addr_objects)
        fw.add(grp)

    # The config tree is built, now we need to push it to the live device.

    # Option 1: Push each address object and group one at a time
    #           (takes over 1 hour)
    for obj in fw.findall(AddressObject):
        obj.create()
    for grp in fw.findall(AddressGroup):
        grp.create()

    # Option 2: Push all the address objects at once, then all the address groups at once
    #           (takes 2-3 seconds)
    fw.find('object1').create_similar()
    fw.find('group1').create_similar()

Bulk operations for the win!

One thing to keep in mind when using bulk operations is that the methods will
push any objects that share the same type and **location**. This means if you
call a bulk operation method on an AddressObject in vsys2, pandevice will NOT
push the AddressObjects in vsys3, or Device Group 7, or the shared scope. Under
the hood, it verifies that the objects share the same XPath and type before they
are pushed to the live device.

Connect to PAN-OS 8.0 and higher
--------------------------------

Starting in PAN-OS 8.0, the default TLS version has changed from 1.0 to 1.1 to enhance the security of
the management connection. This can cause connection problems for systems with older OpenSSL versions
that don't support TLS 1.1, such as MacOSX Sierra. TLS 1.1 is supported in OpenSSL 1.0.1 and higher.

**Suggestions for connecting to PAN-OS 8.0**

**Options 1:**

If using OSX, install `homebrew`_, then use homebrew to install python.  Python from homebrew will come with an updated
OpenSSL version, and it is best practice to install it anyway to prevent pollution of your system python.

After installing homebrew using the `instructions`_ on their website, type the following in an OSX termainal
to install python::

    brew install python

**Option 2:**

Upgrade OpenSSL using your OS package manager. For example, in Ubuntu you would type `apt-get install openssl`.
If a newer OpenSSL is not available, upgrade the OS distribution to a newer version. The procedure will differ
depending on your OS distro. Please refer to the instructions for upgrading your OS.

**Option 3:**

Set the firewall minimum TLS version back to TLS 1.0. To do this, in the Device tab, create a self-signed CA certificate
on the firewall and assign it to a new SSL/TLS Service Profile with the Minimum TLS version set to TLS 1.0. Then,
assign the SSL/TLS Server Profile to the management interface at Device tab -> Setup -> Management -> General Settings.

.. _homebrew: https://brew.sh
.. _instructions: https://brew.sh

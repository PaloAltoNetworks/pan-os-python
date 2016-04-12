.. _usage:

Usage
=====

Import the package
------------------

To use Palo Alto Networks Device Framework in a project::

    import pandevice

You can also be more specific about which modules you want to import. These import statements
apply for all the examples on this page::

    from pandevice import base
    from pandevice import firewall
    from pandevice import panorama
    from pandevice import policies
    from pandevice import objects
    from pandevice import network
    from pandevice import device

Create a PanDevice
------------------

A PanDevice is a Firewall or a Panorama. It's called a PanDevice because that is the class
that Firewall and Panorama inherit from. Everything connects back to a PanDevice, so
creating one is often the first step.

Create a Firewall::

    fw = firewall.Firewall('10.0.0.1', 'admin', 'mypassword')

Create a Panorama::

    pano = panorama.Panorama('10.0.0.5', 'admin', 'mypassword')

You can also create a PanDevice object from a live device. In this example, 10.0.0.1 is
a firewall and 10.0.0.5 is a Panorama. The device type is determined by checking the live
device.::

    >>> device1 = base.PanDevice.create_from_device('10.0.0.1', 'admin', 'mypassword')
    >>> type(device1)
    <class 'pandevice.firewall.Firewall'>

    >>> device2 = base.PanDevice.create_from_device('10.0.0.5', 'admin', 'mypassword')
    >>> type(device2)
    <class 'pandevice.panorama.Panorama'>

Operational commands
--------------------

Perform operational commands using the ``op`` method on a PanDevice. The return value is
an xml.etree.ElementTree object::

    element_response = fw.op('show system info')

Use the ``xml`` argument to return a string with xml::

    xml_response = fw.op('show system info', xml=True)

Configuration
-------------

Configuration changes are made by building a configuration tree using PanObjects.
There are many methods available to work with the configuration tree. These methods
are documented in the :class:`pandevice.base.PanObject` API reference.

**Common configuration methods of PanObject**

Build the configuration tree: ``add()``, ``remove()``, ``find()``, and ``findall()``

Push changed configuration to the live device: ``apply()``, ``create()``,
and ``delete()``

Pull configuration from the live device: ``refresh()``, ``refreshall()``

There are other useful methods besides these. See :class:`pandevice.base.PanObject` for
more information.

**Configuration examples**

In each of these examples, assume a Firewall and Panorama object have been instantiated::

    fw = firewall.Firewall('10.0.0.1', 'admin', 'mypassword')
    pano = panorama.Panorama('10.0.0.5', 'admin', 'mypassword')

Create an address object on a firewall::

    webserver = objects.AddressObject("Apache-webserver", "5.5.5.5", description="Company web server")
    fw.add(webapache)
    webserver.create()

In this example, add() makes the AddressObject a child of the Firewall. This does not make any change to
the live device. The create() method pushes the new AddressObject to the live device represented by 'fw'.

If you lose the handle to the AddressObject, you can always retreive it from a parent node with one of
the `find` methods. For example::

    webserver = fw.find("Apache-webserver", objects.AddressObject)

Remove the description of that same address object::

    webserver.description = None
    webserver.apply()

The apply() method is used instead of create() because it is destructive.  The create() method will never
remove a variable or object, only add or change it.

Delete the entire address object::

    webserver.delete()

The delete() method removes the object from the live device `and` the configuration tree. In this example,
after delete() is called, 'webserver' is no longer a child of 'fw'.

**Retrieve configuration**

The previous section describes how to build a configuration tree yourself. But many cases require you to
pull configuration from the firewall to populate a PanDevice configuration tree. This technique allows many
advantages including tracking current state of the device, and checking if the configuration change is
already on the firewall to prevent an unnecessary commit.

In this example, the live device has 3 address objects. Pull the address objects from the live
device and add them into the configuration tree::

    >>> fw.children
    []
    >>> objects.AddressObject.refreshall(fw, add=True)
    >>> fw.children
    [<pandevice.objects.AddressObject object at 0x108080e90>,
     <pandevice.objects.AddressObject object at 0x108080f50>,
     <pandevice.objects.AddressObject object at 0x108080ed0>]

It's also possible to refresh the variables of an existing object::

    >>> adserver = objects.AddressObject("ADServer")
    >>> fw.add(adserver)
    >>> adserver.value
    None
    >>> adserver.refresh()
    >>> adserver.value
    "4.4.4.4"

Connecting with Panorama
------------------------

Making changes to Panorama is always done the same way, with a connection to Panorama.
But, there are a different methods to make local changes to a Firewall.

**Method 1: Connect to the Firewall and Panorama directly**

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

**Method 2: Connect to Firewall via Panorama**

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

- The Firewall management IP is unknown or not rechable from the script
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

Working with virtual systems
----------------------------

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

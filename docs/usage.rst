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
    from pandevice import network
    from pandevice import device
    from pandevice import objects

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

Pull configuration from the live device: ``refresh()``, ``refresh_all_from_device()``

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
    >>> objects.AddressObject.refresh_all_from_device(fw, add=True)
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

Working with virtual systems
----------------------------

A Firewall PanDevice can represent a firewall or a virtual system (vsys). By default, a Firewall
instance represents a single context firewall, or 'vsys1' on a multi-vsys firewall.

When working with a firewall with multi-vsys mode enabled, there are two methods to work with vsys:

**Method 1**: A different Firewall instance for each vsys

Each Firewall object has a 'vsys' attribute which is assigned the vsys id.  For example::

    fw_vsys2 = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys2")
    fw_vsys3 = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="vsys3")

When using this method, non-vsys-specific configuration should be modified using a 'shared' PanDevice::

    fw = firewall.Firewall("10.0.0.1", "admin", "mypassword", vsys="shared")

To create or delete an entire vsys, use the create_vsys() and delete_vsys() methods::

    fw_vsys2.create_vsys()
    fw_vsys3.delete_vsys()

**Method 2**: A single Firewall instance with Vsys child instances

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

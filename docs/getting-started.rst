Getting Started
===============

Install
-------

Install using pip::

    pip install pandevice

Upgrade to the latest version::

    pip install --upgrade pandevice

If you have poetry installed, you can also add pandevice to your project::

    poetry add pandevice

Import the classes
------------------

To use Palo Alto Networks Device Framework in a project::

    import pandevice

You can also be more specific about which modules you want to import::

    from pandevice import base
    from pandevice import firewall
    from pandevice import panorama
    from pandevice import policies
    from pandevice import objects
    from pandevice import network
    from pandevice import device

Or, even *more* specific by importing a specific class::

    from pandevice.firewall import Firewall

Connect to a Firewall or Panorama
---------------------------------

A PanDevice is a Firewall or a Panorama. It's called a PanDevice because that is the class
that Firewall and Panorama inherit from. Everything connects back to a PanDevice, so
creating one is often the first step::

    from pandevice.firewall import Firewall
    from pandevice.panorama import Panorama
    fw = Firewall('10.0.0.1', 'admin', 'mypassword')  # Create a firewall object
    pano = Panorama('10.0.0.5', 'admin', 'mypassword')  # Create a panorama object

You can also create a Firewall or Panorama object from a live device. In this
example, 10.0.0.1 is a firewall and 10.0.0.5 is a Panorama. The device type is
determined by checking the live device.::

    >>> from pandevice.base import PanDevice

    >>> device1 = PanDevice.create_from_device('10.0.0.1', 'admin', 'mypassword')
    >>> type(device1)
    <class 'pandevice.firewall.Firewall'>

    >>> device2 = PanDevice.create_from_device('10.0.0.5', 'admin', 'mypassword')
    >>> type(device2)
    <class 'pandevice.panorama.Panorama'>

Operational commands
--------------------

Perform operational commands using the ``op`` method on a PanDevice. The return value is
an xml.etree.ElementTree object::

    from pandevice import firewall
    fw = firewall.Firewall('10.0.0.1', 'admin', 'mypassword')
    element_response = fw.op('show system info')

Use the ``xml`` argument to return a string with xml::

    xml_response = fw.op('show system info', xml=True)

Configure your device
---------------------

You can configure your firewall or Panorama with a configuration tree using PanObjects.
Everything in pandevice is a PanObject. They are like building blocks to build
out a configuration. There are many methods available to build up the
configuration tree and interact with the live device:

**Common configuration methods of PanObject**

Build the configuration tree: ``add()``, ``remove()``, ``find()``, and ``findall()``

Push changed configuration to the live device: ``apply()``, ``create()``,
and ``delete()``

Pull configuration from the live device: ``refresh()``, ``refreshall()``

There are other useful methods besides these. See :ref:`useful_methods` for a table of all the
methods and what they do. All methods are also documented in the
:class:`pandevice.base.PanObject` API reference.

**Configuration examples**

In each of these examples, assume a Firewall and Panorama object have been instantiated::

    from pandevice.firewall import Firewall
    from pandevice.panorama import Panorama
    from pandevice.objects import AddressObject

    fw = Firewall("10.0.0.1", "admin", "mypassword")
    pano = Panorama("10.0.0.5", "admin", "mypassword")

Create an address object on a firewall::

    webserver = AddressObject("Apache-webserver", "5.5.5.5", description="Company web server")
    fw.add(webserver)
    webserver.create()

In this example, add() makes the AddressObject a child of the Firewall. This does not make any change to
the live device. The create() method pushes the new AddressObject to the live device represented by 'fw'.

If you lose the handle to the AddressObject, you can always retreive it from a parent node with one of
the `find` methods. For example::

    webserver = fw.find("Apache-webserver", AddressObject)

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
    >>> AddressObject.refreshall(fw, add=True)
    >>> fw.children
    [<pandevice.objects.AddressObject object at 0x108080e90>,
     <pandevice.objects.AddressObject object at 0x108080f50>,
     <pandevice.objects.AddressObject object at 0x108080ed0>]

It's also possible to refresh the variables of an existing object::

    >>> adserver = AddressObject("ADServer")
    >>> fw.add(adserver)
    >>> adserver.value
    None
    >>> adserver.refresh()
    >>> adserver.value
    "4.4.4.4"

Getting Started
===============

Install
-------

Install using pip::

    pip install pan-os-python

Upgrade to the latest version::

    pip install --upgrade pan-os-python

If you have poetry installed, you can also add pan-os-python to your project::

    poetry add pan-os-python

Import the classes
------------------

To use pan-os-python in a project::

    import panos

You can also be more specific about which modules you want to import::

    from panos import base
    from panos import firewall
    from panos import panorama
    from panos import policies
    from panos import objects
    from panos import network
    from panos import device

Or, even *more* specific by importing a specific class::

    from panos.firewall import Firewall

Connect to a Firewall or Panorama
---------------------------------

A PanDevice is a Firewall or a Panorama. It's called a PanDevice because that is the class
that Firewall and Panorama inherit from. Everything connects back to a PanDevice, so
creating one is often the first step::

    from panos.firewall import Firewall
    from panos.panorama import Panorama
    fw = Firewall('10.0.0.1', 'admin', 'mypassword')  # Create a firewall object
    pano = Panorama('10.0.0.5', 'admin', 'mypassword')  # Create a panorama object

You can also create a Firewall or Panorama object from a live device. In this
example, 10.0.0.1 is a firewall and 10.0.0.5 is a Panorama. The device type is
determined by checking the live device.::

    >>> from panos.base import PanDevice

    >>> device1 = PanDevice.create_from_device('10.0.0.1', 'admin', 'mypassword')
    >>> type(device1)
    <class 'panos.firewall.Firewall'>

    >>> device2 = PanDevice.create_from_device('10.0.0.5', 'admin', 'mypassword')
    >>> type(device2)
    <class 'panos.panorama.Panorama'>

Operational commands
--------------------

Operational commands are used to get or clear the current operational state of
the device or make operational requests such as content upgrades. Most any
command that is not a config mode or debug command is an operational command.
These include many 'show' commands such as ``show system info`` and ``show
interface ethernet1/1`` and 'request' commands. You cannot use operational
commands to change the running configuration of the firewall or Panorama. See
`Configure your device`_ below to configure your firewall by changing the
running configuration.

Perform operational commands using the ``op`` method on a PanDevice instance.
By default, the return value is an xml.etree.ElementTree object which can be
easily parsed::

    from panos import firewall
    fw = firewall.Firewall('10.0.0.1', 'admin', 'mypassword')
    element_response = fw.op('show system info')

Use the ``xml`` argument to return a string of xml. This is harder to parse, but
sometimes a string is needed such as when saving to a file.::

    xml_str_response = fw.op('show system info', xml=True)

**Important:** When passing the cmd as a command string (not XML) you must include any
non-keyword strings in the command inside double quotes (``"``). Here's some
examples::

    fw.op('clear session all filter application "facebook-base"')
    # The string "facebook-base" must be in quotes because it is not a keyword

    fw.op('show interface "ethernet1/1"')
    # The string "ethernet1/1" must be in quotes because it is not a keyword

This works by converting all unquoted arguments in cmd to XML elements and
double quoted arguments as text after removing the quotes. For example:

* ``show system info`` -> ``<show><system><info></info></system></show>``
* ``show interface "ethernet1/1"`` -> ``<show><interface>ethernet1/1</interface></show>``

The command's XML is then sent to the firewall.

**Parse the result**

You can parse an ElementTree using the `python ElementTree library`_.

Assuming the first ``op()`` call returns a response with this XML (output
simplified for example purposes)::

    <response status="success">
        <result>
            <ifnet>
                <counters>
                    <ifnet>
                        <entry>
                            <name>ethernet1/1</name>
                            <ipackets>329744</ipackets>
                            <opackets>508805</opackets>
                            <ierrors>0</ierrors>
                        </entry>
                    </ifnet>
                </counters>
                <name>ethernet1/1</name>
                <zone>DMZ</zone>
            </ifnet>
            <hw>
                <name>ethernet1/1</name>
                <mac>08:30:6b:1e:55:42</mac>
                <state>up</state>
            </hw>
        </result>
    </response>

Then this example collects the zone, mac address, and packet output for
ethernet1/1::

    response = fw.op('show interface "ethernet1/1"')

    name = response.find(".//zone").text
    # name = "DMZ"

    mac_address = response.find("./result/hw/mac").text
    # mac_address = "08:30:6b:1e:55:42"

    counter_entries = response.findall(".//counters/ifnet/entry")
    packets_out = [(counters.find("./name").text, int(counters.find("./opackets").text)) for counters in counter_entries]
    # packets_out = [("ethernet1/1", 508805)]

In the example above, we use a deep search to find the ``<zone>`` element, an
absolute path to get the ``<mac>`` element, and a findall with both deep search and
relative path to get packets out for every subinterface. In this example there
are no subinterfaces, so it returns one list item.

.. _python ElementTree library: https://docs.python.org/3/library/xml.etree.elementtree.html

Configure your device
---------------------

You can configure your firewall or Panorama with a configuration tree using PanObjects.
Everything in pan-os-python is a PanObject. They are like building blocks to build
out a configuration. There are many methods available to build up the
configuration tree and interact with the live device:

**Common configuration methods of PanObject**

Build the configuration tree: ``add()``, ``remove()``, ``find()``, and ``findall()``

Push changed configuration to the live device: ``apply()``, ``create()``,
and ``delete()``

Pull configuration from the live device: ``refresh()``, ``refreshall()``

There are other useful methods besides these. See :ref:`useful_methods` for a table of all the
methods and what they do. All methods are also documented in the
:class:`panos.base.PanObject` API reference.

**Configuration examples**

In each of these examples, assume a Firewall and Panorama object have been instantiated::

    from panos.firewall import Firewall
    from panos.panorama import Panorama
    from panos.objects import AddressObject

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
    [<panos.objects.AddressObject object at 0x108080e90>,
     <panos.objects.AddressObject object at 0x108080f50>,
     <panos.objects.AddressObject object at 0x108080ed0>]

It's also possible to refresh the variables of an existing object::

    >>> adserver = AddressObject("ADServer")
    >>> fw.add(adserver)
    >>> adserver.value
    None
    >>> adserver.refresh()
    >>> adserver.value
    "4.4.4.4"

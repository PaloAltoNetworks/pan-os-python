===================================
Palo Alto Networks Device Framework
===================================

The Palo Alto Networks Device Framework is a way to interact with Palo Alto
Networks devices (including Next-generation Firewalls and Panorama) using the
device API that is object oriented and conceptually similar to interaction
with the device via the GUI or CLI.

* Free software: ISC License
* Documentation: http://pandevice.readthedocs.org

-----

|pypi| |travis| |rtd| |gitter|

-----

Features
--------

- Object model of Firewall and Panorama configuration
- Multiple connection methods including Panorama as a proxy
- All operations natively vsys-aware
- Support for high availability pairs and retry/recovery during node failure
- Batch User-ID operations
- Device API exception classification

Status
------

Palo Alto Networks Device Framework is considered **alpha**. It is fully tested
and used in many production environments, but it maintains alpha status because
the API interface could change at any time without notification. Please be
prepared to modify your scripts to work with each subsequent version of this
package because backward compatibility is not guaranteed.

Installation
------------

The easiest method to install pandevice is using pip::

    pip install pandevice

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv pandevice
    $ pip install pandevice

Pip will install the pan-python_ library as a dependency.

Upgrade to the latest version::

    pip install --upgrade pandevice

How to import
-------------

To use Palo Alto Networks Device Framework in a project::

    import pandevice

You can also be more specific about which modules you want to import::

    from pandevice import firewall
    from pandevice import network


A few examples
--------------

For configuration tasks, create a tree structure using the classes in
each module. Nodes hierarchy must follow the model in the
`Configuration Tree`_.

The following examples assume the modules were imported as such::

    from pandevice import firewall
    from pandevice import network

Create a subinterface and commit::

    fw = firewall.Firewall("10.0.0.1", username="admin", password="admin")
    eth = fw.add(network.EthernetInterface("ethernet1/1", mode="layer3"))
    subeth = eth.add(network.Layer3Subinterface("ethernet1/1.30", ip="4.4.4.4/24", tag=30))
    subeth.create()
    fw.commit()

Operational commands leverage the 'op' method of the device::

    fw = firewall.Firewall("10.0.0.1", username="admin", password="admin")
    print fw.op("show system info", xml=True)

Some operational commands have methods to refresh the variables in an object::

    # populates the version, serial, and model variables from the live device
    fw.refresh_system_info()


.. _pan-python: http://github.com/kevinsteves/pan-python
.. _Configuration Tree: http://pandevice.readthedocs.org/en/latest/configtree.html

.. |pypi| image:: https://img.shields.io/pypi/v/pandevice.svg
    :target: https://pypi.python.org/pypi/pandevice
    :alt: Latest version released on PyPi

.. |rtd| image:: https://img.shields.io/badge/docs-latest-brightgreen.svg
    :target: http://pandevice.readthedocs.org/en/latest/?badge=latest
    :alt: Documentation Status

.. |coverage| image:: https://img.shields.io/coveralls/PaloAltoNetworks/pandevice/master.svg?label=coverage
    :target: https://coveralls.io/r/PaloAltoNetworks/pandevice?branch=master
    :alt: Test coverage

.. |travis| image:: https://img.shields.io/travis/PaloAltoNetworks/pandevice/master.svg
    :target: http://travis-ci.org/PaloAltoNetworks/pandevice
    :alt: Build status from Travis

.. |gitter| image:: https://badges.gitter.im/PaloAltoNetworks/pandevice.svg
    :target: https://gitter.im/PaloAltoNetworks/pandevice
    :alt: Chat on Gitter

===================================
Palo Alto Networks Device Framework
===================================

The Device Framework is a mechanism for interacting with Palo Alto Networks
devices (including physical and virtualized Next-generation Firewalls and
Panorama).  The Device Framework is object oriented and mimics the traditional
interaction with the device via the GUI or CLI/API.

* Documentation: http://pandevice.readthedocs.io
* Overview: http://paloaltonetworks.github.io/pandevice
* Free software: ISC License

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

Install
-------

Install using pip::

    pip install pandevice

Upgrade to the latest version::

    pip install --upgrade pandevice

If you have poetry installed, you can also add pandevice to your project::

    poetry add pandevice

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

Create an interface and commit::

    fw = firewall.Firewall("10.0.0.1", api_username="admin", api_password="admin")
    eth1 = network.EthernetInterface("ethernet1/1", mode="layer3")
    fw.add(eth1)
    eth1.create()
    fw.commit()

Operational commands leverage the 'op' method of the device::

    fw = firewall.Firewall("10.0.0.1", api_username="admin", api_password="admin")
    print fw.op("show system info")

Some operational commands have methods to refresh the variables in an object::

    # populates the version, serial, and model variables from the live device
    fw.refresh_system_info()

See more examples in the `Usage Guide`_.


Contributors
------------

- Brian Torres-Gil - `github <https://github.com/btorresgil>`__
- Garfield Freeman - `github <https://github.com/shinmog>`__
- John Anderson - `github <https://github.com/lampwins>`__
- Aditya Sripal - `github <https://github.com/AdityaSripal>`__

Thank you to Kevin Steves, creator of the pan-python library:
    https://github.com/kevinsteves/pan-python


.. _pan-python: http://github.com/kevinsteves/pan-python
.. _Configuration Tree: http://pandevice.readthedocs.io/en/latest/configtree.html
.. _Usage Guide: http://pandevice.readthedocs.io/en/latest/usage.html

.. |pypi| image:: https://img.shields.io/pypi/v/pandevice.svg
    :target: https://pypi.python.org/pypi/pandevice
    :alt: Latest version released on PyPi

.. |rtd| image:: https://img.shields.io/badge/docs-latest-brightgreen.svg
    :target: http://pandevice.readthedocs.io/en/latest/?badge=latest
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

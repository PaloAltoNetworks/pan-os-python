
Palo Alto Networks PAN-OS SDK for Python
========================================

The PAN-OS SDK for Python (pan-os-python) is a package to help interact with
Palo Alto Networks devices (including physical and virtualized Next-generation
Firewalls and Panorama).  The pan-os-python SDK is object oriented and mimics
the traditional interaction with the device via the GUI or CLI/API.


* 
  Free software: ISC License

* 
  Documentation: http://pan-os-python.readthedocs.io

----


.. image:: https://img.shields.io/pypi/v/pan-os-python.svg
   :target: https://pypi.python.org/pypi/pan-os-python
   :alt: Latest version released on PyPi


.. image:: https://img.shields.io/badge/docs-latest-brightgreen.svg
   :target: http://pan-os-python.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status


.. image:: https://badges.gitter.im/PaloAltoNetworks/pan-os-python.svg
   :target: https://gitter.im/PaloAltoNetworks/pan-os-python
   :alt: Chat on Gitter


----

Features
--------


* Object model of Firewall and Panorama configuration
* Multiple connection methods including Panorama as a proxy
* All operations natively vsys-aware
* Support for high availability pairs and retry/recovery during node failure
* Batch User-ID operations
* Device API exception classification

Status
------

Palo Alto Networks PAN-OS SDK for Python is considered stable. It is fully tested
and used in many production environments. Semantic versioning is applied to indicate
bug fixes, new features, and breaking changes in each version.

Install
-------

Install using pip:

.. code-block:: shell

   pip install pan-os-python

Upgrade to the latest version:

.. code-block:: shell

   pip install --upgrade pan-os-python

If you have poetry installed, you can also add pan-os-python to your project:

.. code-block:: shell

   poetry add pan-os-python

How to import
-------------

To use pan-os-python in a project:

.. code-block:: python

   import panos

You can also be more specific about which modules you want to import:

.. code-block:: python

   from panos import firewall
   from panos import network

A few examples
--------------

For configuration tasks, create a tree structure using the classes in
each module. Nodes hierarchy must follow the model in the
`Configuration Tree <http://pan-os-python.readthedocs.io/en/latest/configtree.html>`_.

The following examples assume the modules were imported as such:

.. code-block:: python

   from panos import firewall
   from panos import network

Create an interface and commit:

.. code-block:: python

   fw = firewall.Firewall("10.0.0.1", api_username="admin", api_password="admin")
   eth1 = network.EthernetInterface("ethernet1/1", mode="layer3")
   fw.add(eth1)
   eth1.create()
   fw.commit()

Operational commands leverage the 'op' method of the device:

.. code-block:: python

   fw = firewall.Firewall("10.0.0.1", api_username="admin", api_password="admin")
   print fw.op("show system info")

Some operational commands have methods to refresh the variables in an object:

.. code-block:: python

   # populates the version, serial, and model variables from the live device
   fw.refresh_system_info()

See more examples in the `Usage Guide <http://pan-os-python.readthedocs.io/en/latest/usage.html>`_.

Contributors
------------


* Brian Torres-Gil - `btorresgil <https://github.com/btorresgil>`_
* Garfield Freeman - `shinmog <https://github.com/shinmog>`_
* John Anderson - `lampwins <https://github.com/lampwins>`_
* Aditya Sripal - `AdityaSripal <https://github.com/AdityaSripal>`_

Thank you to `Kevin Steves <https://github.com/kevinsteves>`_\ , creator of the `pan-python library <https://github.com/kevinsteves/pan-python>`_

.. _classtree:

Configuration tree diagrams
===========================

These diagrams illustrates the possible tree structures for a Firewall/Panorama configuration.

The tree diagrams are broken out into partial diagrams by module or function for better readability.
The nodes are color coded by the module they are in according to the legend.

Module Legend
-------------

.. graphviz:: _diagrams/legend.dot

.. _panoramatree:

Panorama
--------

A Panorama object can contain a DeviceGroup or Firewall, each of which
can contain configuration objects. (see :ref:`firewalltree` below for objects that
can be added to the Firewall object)

.. graphviz:: _diagrams/panos.panorama.dot

.. _firewalltree:

Firewall
--------

.. graphviz:: _diagrams/panos.firewall.dot

.. _devicetree:

Device
------

.. graphviz:: _diagrams/panos.device.dot

.. _hatree:

HA
--

.. graphviz:: _diagrams/panos.ha.dot

.. _networktree:

Network
-------

.. graphviz:: _diagrams/panos.network.dot

.. _policytree:

Policies
--------

.. graphviz:: _diagrams/panos.policies.dot


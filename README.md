Palo Alto Networks PAN-OS SDK for Python
========================================

The PAN-OS SDK for Python (pan-os-python) is a package to help interact with
Palo Alto Networks devices (including physical and virtualized Next-generation
Firewalls and Panorama).  The pan-os-python SDK is object oriented and mimics
the traditional interaction with the device via the GUI or CLI/API.

* Free software: ISC License

* Documentation: http://pan-os-python.readthedocs.io

-----

[![Latest version released on PyPi](https://img.shields.io/pypi/v/pan-os-python.svg)](https://pypi.python.org/pypi/pan-os-python)
[![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg)](http://pan-os-python.readthedocs.io/en/latest/?badge=latest)
[![Chat on Gitter](https://badges.gitter.im/PaloAltoNetworks/pan-os-python.svg)](https://gitter.im/PaloAltoNetworks/pan-os-python)

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

Palo Alto Networks PAN-OS SDK for Python is considered stable. It is fully tested
and used in many production environments. Semantic versioning is applied to indicate
bug fixes, new features, and breaking changes in each version.

Install
-------

Install using pip:

```shell
pip install pan-os-python
```

Upgrade to the latest version:

```shell
pip install --upgrade pan-os-python
```

If you have poetry installed, you can also add pan-os-python to your project:
 
```shell
poetry add pan-os-python
```

How to import
-------------

To use pan-os-python in a project:

```python
import panos
```

You can also be more specific about which modules you want to import:

```python
from panos import firewall
from panos import network
```


A few examples
--------------

For configuration tasks, create a tree structure using the classes in
each module. Nodes hierarchy must follow the model in the
[Configuration Tree](http://pan-os-python.readthedocs.io/en/latest/configtree.html).

The following examples assume the modules were imported as such:

```python
from panos import firewall
from panos import network
```

Create an interface and commit:

```python
fw = firewall.Firewall("10.0.0.1", api_username="admin", api_password="admin")
eth1 = network.EthernetInterface("ethernet1/1", mode="layer3")
fw.add(eth1)
eth1.create()
fw.commit()
```

Operational commands leverage the 'op' method of the device:

```python
fw = firewall.Firewall("10.0.0.1", api_username="admin", api_password="admin")
print fw.op("show system info")
```

Some operational commands have methods to refresh the variables in an object:

```python
# populates the version, serial, and model variables from the live device
fw.refresh_system_info()
```

See more examples in the [Usage Guide](http://pan-os-python.readthedocs.io/en/latest/usage.html).


Contributors
------------

- Brian Torres-Gil - [btorresgil](https://github.com/btorresgil)
- Garfield Freeman - [shinmog](https://github.com/shinmog)
- John Anderson - [lampwins](https://github.com/lampwins)
- Aditya Sripal - [AdityaSripal](https://github.com/AdityaSripal)

Thank you to [Kevin Steves](https://github.com/kevinsteves), creator of the [pan-python library](https://github.com/kevinsteves/pan-python)

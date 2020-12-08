Palo Alto Networks PAN-OS SDK for Python
========================================

The PAN-OS SDK for Python (pan-os-python) is a package to help interact with
Palo Alto Networks devices (including physical and virtualized Next-generation
Firewalls and Panorama).  The pan-os-python SDK is object oriented and mimics
the traditional interaction with the device via the GUI or CLI/API.

* Documentation: http://pan-os-python.readthedocs.io

-----

[![Latest version released on PyPi](https://img.shields.io/pypi/v/pan-os-python.svg)](https://pypi.python.org/pypi/pan-os-python)
[![Python versions](https://img.shields.io/badge/python-3.5%20%7C%203.6%20%7C%203.7%20%7C%203.8-blueviolet)](https://pypi.python.org/pypi/pan-os-python)
[![License](https://img.shields.io/pypi/l/pan-os-python)](https://github.com/PaloAltoNetworks/pan-os-python/blob/develop/LICENSE)
[![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg)](http://pan-os-python.readthedocs.io/en/latest/?badge=latest)
[![Chat on GitHub Discussions](https://img.shields.io/badge/chat%20on-GitHub%20Discussions-brightgreen)](https://github.com/PaloAltoNetworks/pan-os-python/discussions)

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://conventionalcommits.org/)
[![Powered by DepHell](https://img.shields.io/badge/Powered%20by-DepHell-red)](https://github.com/dephell/dephell)
[![GitHub contributors](https://img.shields.io/github/contributors/PaloAltoNetworks/pan-os-python)](https://github.com/PaloAltoNetworks/pan-os-python/graphs/contributors/)

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

Upgrade from pandevice
----------------------

This `pan-os-python` package is the evolution of the older `pandevice` package. To
upgrade from `pandevice` to `pan-os-python`, follow these steps.

Step 1. Ensure you are using python3

   [Python2 is end-of-life](https://www.python.org/doc/sunset-python-2/) and not
   supported by `pan-os-python`.

Step 2. Uninstall pandevice:

```shell
pip uninstall pandevice
 # or
poetry remove pandevice
```

Step 3. Install pan-os-python:

```shell
pip3 install pan-os-python
 # or
poetry add pan-os-python
```

Step 4. Change the import statements in your code from `pandevice` to `panos`. For example:

```python
import pandevice
from pandevice.firewall import Firewall

 # would change to

import panos
from panos.firewall import Firewall
```

Step 5. Test your script or application

   There are no known breaking changes
   between `pandevice v0.14.0` and `pan-os-python v1.0.0`, but it is a major
   upgrade so please verify everything works as expected.

Contributors
------------

- Brian Torres-Gil - [btorresgil](https://github.com/btorresgil)
- Garfield Freeman - [shinmog](https://github.com/shinmog)
- John Anderson - [lampwins](https://github.com/lampwins)
- Aditya Sripal - [AdityaSripal](https://github.com/AdityaSripal)

Thank you to [Kevin Steves](https://github.com/kevinsteves), creator of the [pan-python library](https://github.com/kevinsteves/pan-python)

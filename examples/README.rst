
How to use these scripts
========================

Set up your python environment
------------------------------

1. Install pan-python
2. Clone or install pandevice
3. Run a script

For example::

    pip install pan-python
    git clone https://github.com/PaloAltoNetworks-BD/pandevice
    cd pandevice/examples
    python example.py -h

upgrade.py
----------

This script upgrades a Palo Alto Networks firewall or Panorama to the
specified version. It takes care of all intermediate upgrades and reboots.

Usage::

    upgrade.py [-h] [-v] [-q] [-n] hostname username password version

Examples:

Upgrade a firewall at 10.0.0.1 to PAN-OS 7.0.0::

    $ python upgrade.py 10.0.0.1 admin password 7.0.0

Upgrade a Panorama at 172.16.4.4 to the latest Panorama version::

    $ python upgrade.py 172.16.4.4 admin password latest

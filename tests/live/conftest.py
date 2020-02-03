import os
import random

import pytest

from pandevice import firewall
from pandevice import panorama


live_devices = {}
one_fw_per_version = []
one_device_type_per_version = []
one_panorama_per_version = []
ha_pairs = []
panorama_fw_combinations = []


def desc(pano=None, fw=None):
    ans = []
    if pano is not None:
        ans.append("{0}.{1}Pano".format(*pano))
        if fw is not None:
            ans.append("With")
    if fw is not None:
        ans.append("{0}.{1}NGFW".format(*fw))
    return "".join(ans)


def init():
    """
    Environment variables:
        PD_USERNAME
        PD_PASSWORD
        PD_PANORAMAS
        PD_FIREWALLS
    """
    global live_devices
    global one_fw_per_version
    global one_device_per_version
    global one_panorama_per_version
    global ha_pairs
    global panorama_fw_combinations

    # Get os.environ stuff to set the live_devices global.
    try:
        username = os.environ["PD_USERNAME"]
        password = os.environ["PD_PASSWORD"]
        panos = os.environ["PD_PANORAMAS"].split()
        fws = os.environ["PD_FIREWALLS"].split()
    except KeyError as e:
        print('NOT RUNNING LIVE TESTS - missing "{0}"'.format(e))
        return

    # Add each panorama to the live_devices.
    for hostname in panos:
        c = panorama.Panorama(hostname, username, password)
        try:
            c.refresh_system_info()
        except Exception as e:
            raise ValueError(
                "Failed to connect to panorama {0}: {1}".format(hostname, e)
            )

        # There should only be one panorama per version.
        version = c._version_info
        if version in live_devices:
            raise ValueError(
                "Two panoramas, same version: {0} and {1}".format(
                    live_devices[version]["pano"].hostname, hostname
                )
            )
        live_devices.setdefault(version, {"fws": [], "pano": None})
        live_devices[version]["pano"] = c

    # Add each firewall to the live_devices.
    for hostname in fws:
        c = firewall.Firewall(hostname, username, password)
        try:
            c.refresh_system_info()
        except Exception as e:
            raise ValueError(
                "Failed to connect to firewall {0}: {1}".format(hostname, e)
            )

        # Multiple firewalls are allowed per version, but only ever the first
        # two will be used.
        version = c._version_info
        live_devices.setdefault(version, {"fws": [], "pano": None})
        live_devices[version]["fws"].append(c)

    # Set:
    #   one_fw_per_version
    #   one_device_type_per_version
    #   one_panorama_per_version
    for version in live_devices:
        pano = live_devices[version]["pano"]
        fws = live_devices[version]["fws"]
        if fws:
            fw = random.choice(fws)
            one_device_type_per_version.append((fw, desc(fw=version)))
            one_fw_per_version.append((fw, desc(fw=version)))
        if pano is not None:
            one_panorama_per_version.append((pano, desc(pano=version)))
            one_device_type_per_version.append((pano, desc(pano=version)))

    # Set: ha_pairs
    for version in live_devices:
        fws = live_devices[version]["fws"]
        if len(fws) >= 2:
            ha_pairs.append((fws[:2], version))

    # Set panorama_fw_combinations
    for pano_version in live_devices:
        pano = live_devices[pano_version]["pano"]
        if pano is None:
            continue

        for fw_version in live_devices:
            fws = live_devices[fw_version]["fws"]
            if not fws or pano_version < fw_version:
                continue

            fw = random.choice(fws)
            panorama_fw_combinations.append(
                ((pano, fw), desc(pano_version, fw_version),)
            )


# Invoke the init() to set globals for our tests.
init()


def pytest_report_header(config):
    if not one_device_type_per_version:
        ans = [
            "Skipping live tests; no devices in the config",
        ]
    else:
        ans = [
            "Given the following devices:",
        ]
        for v in sorted(live_devices.keys()):
            line = [
                "* Version:{0}.{1}.{2}".format(*v),
            ]
            if live_devices[v]["pano"] is not None:
                line.append("Panorama:{0}".format(live_devices[v]["pano"].hostname))
            for fw in live_devices[v]["fws"]:
                line.append("NGFW:{0}".format(fw.hostname))
            ans.append(" ".join(line))

    return ans


# Order tests alphabetically.  This is needed because by default pytest gets
# the tests of the current class, executes them, then walks the inheritance
# to get parent tests, which is not what we want.
def pytest_collection_modifyitems(items):
    grouping = {}
    lookup = {}
    reordered = []

    for x in items:
        location, tc = x.nodeid.rsplit("::", 1)
        lookup[(location, tc)] = x
        grouping.setdefault(location, [])
        grouping[location].append(tc)

    for location in sorted(grouping.keys()):
        tests = sorted(grouping[location])
        for tc in tests:
            reordered.append(lookup[(location, tc)])

    items[:] = reordered


# Define a state fixture.
class State(object):
    pass


class StateMap(object):
    def __init__(self):
        self.config = {}

    def setdefault(self, *x):
        key = tuple(d.hostname for d in x)
        return self.config.setdefault(key, State())


@pytest.fixture(scope="class")
def state_map(request):
    yield StateMap()


# Define parametrized fixtures.
@pytest.fixture(
    scope="session",
    params=[x[0] for x in one_fw_per_version],
    ids=[x[1] for x in one_fw_per_version],
)
def fw(request):
    return request.param


@pytest.fixture(
    scope="session",
    params=[x[0] for x in one_device_type_per_version],
    ids=[x[1] for x in one_device_type_per_version],
)
def dev(request):
    return request.param


@pytest.fixture(
    scope="session",
    params=[x[0] for x in one_panorama_per_version],
    ids=[x[1] for x in one_panorama_per_version],
)
def pano(request):
    return request.param


@pytest.fixture(
    scope="session",
    params=[x[0] for x in panorama_fw_combinations],
    ids=[x[1] for x in panorama_fw_combinations],
)
def pairing(request):
    return request.param

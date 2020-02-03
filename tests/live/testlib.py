import random

import pytest

from pandevice import network


def random_name():
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for x in range(10))


def random_ip(netmask=None):
    return "{0}.{1}.{2}.{3}{4}".format(
        random.randint(11, 150),
        random.randint(1, 200),
        random.randint(1, 200),
        1 if netmask is not None else random.randint(2, 200),
        netmask or "",
    )


def random_netmask():
    return "{0}.{1}.{2}.0/24".format(
        random.randint(11, 150), random.randint(1, 200), random.randint(1, 200),
    )


def random_ipv6(ending=None):
    if ending is None:
        return ":".join("{0:04x}".format(random.randint(1, 65535)) for x in range(8))
    else:
        return "{0:04x}:{1:04x}:{2:04x}:{3:04x}::{4}".format(
            random.randint(1, 65535),
            random.randint(1, 65535),
            random.randint(1, 65535),
            random.randint(1, 65535),
            ending,
        )


def random_mac():
    return ":".join("{0:02x}".format(random.randint(0, 255)) for x in range(6))


def get_available_interfaces(con, num=1):
    ifaces = network.EthernetInterface.refreshall(con, add=False)
    ifaces = set(x.name for x in ifaces)

    all_interfaces = set("ethernet1/{0}".format(x) for x in range(1, 10))
    available = all_interfaces.difference(ifaces)

    ans = []
    while len(ans) != num:
        # Raises KeyError
        ans.append(available.pop())

    return ans


class FwFlow(object):
    def test_01_setup_dependencies(self, fw, state_map):
        state = state_map.setdefault(fw)
        state.err = False
        state.fail_func = pytest.skip

        try:
            self.create_dependencies(fw, state)
        except Exception as e:
            print("SETUP ERROR: {0}".format(e))
            state.err = True
            pytest.skip("Setup failed")

    def create_dependencies(self, fw, state):
        pass

    def sanity(self, fw, state_map):
        state = state_map.setdefault(fw)
        if state.err:
            state.fail_func("prereq failed")

        return state

    def test_02_create(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.fail_func = pytest.xfail
        state.err = True
        self.setup_state_obj(fw, state)
        state.obj.create()
        state.err = False

    def setup_state_obj(self, fw, state):
        pass

    def test_03_refreshall(self, fw, state_map):
        state = self.sanity(fw, state_map)

        objs = state.obj.refreshall(state.obj.parent, add=False)
        assert len(objs) >= 1

    def test_04_update(self, fw, state_map):
        state = self.sanity(fw, state_map)

        self.update_state_obj(fw, state)
        state.obj.apply()

    def update_state_obj(self, fw, state):
        pass

    def test_97_delete(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.delete()

    def test_98_cleanup_dependencies(self, fw, state_map):
        state = state_map.setdefault(fw)
        self.cleanup_dependencies(fw, state)

    def cleanup_dependencies(self, fw, state):
        pass

    def test_99_removeall(self, fw, state_map):
        fw.removeall()


class DevFlow(object):
    def test_01_setup_dependencies(self, dev, state_map):
        state = state_map.setdefault(dev)
        state.err = False
        state.fail_func = pytest.skip

        try:
            self.create_dependencies(dev, state)
        except Exception as e:
            print("SETUP ERROR: {0}".format(e))
            state.err = True
            pytest.skip("Setup failed")

    def create_dependencies(self, dev, state):
        pass

    def sanity(self, dev, state_map):
        state = state_map.setdefault(dev)
        if state.err:
            state.fail_func("prereq failed")

        return state

    def test_02_create(self, dev, state_map):
        state = self.sanity(dev, state_map)

        state.fail_func = pytest.xfail
        state.err = True
        self.setup_state_obj(dev, state)
        state.obj.create()
        state.err = False

    def setup_state_obj(self, dev, state):
        pass

    def test_03_refreshall(self, dev, state_map):
        state = self.sanity(dev, state_map)

        objs = state.obj.refreshall(state.obj.parent, add=False)
        assert len(objs) >= 1

    def test_04_update(self, dev, state_map):
        state = self.sanity(dev, state_map)

        self.update_state_obj(dev, state)
        state.obj.apply()

    def update_state_obj(self, dev, state):
        pass

    def test_97_delete(self, dev, state_map):
        state = self.sanity(dev, state_map)

        state.obj.delete()

    def test_98_cleanup_dependencies(self, dev, state_map):
        state = state_map.setdefault(dev)

        self.cleanup_dependencies(dev, state)

    def cleanup_dependencies(self, dev, state):
        pass

    def test_99_removeall(self, dev, state_map):
        dev.removeall()


class PanoFlow(object):
    def test_01_setup_dependencies(self, pano, state_map):
        state = state_map.setdefault(pano)
        state.err = False
        state.fail_func = pytest.skip

        try:
            self.create_dependencies(pano, state)
        except Exception as e:
            print("SETUP ERROR: {0}".format(e))
            state.err = True
            pytest.skip("Setup failed")

    def create_dependencies(self, pano, state):
        pass

    def sanity(self, pano, state_map):
        state = state_map.setdefault(pano)
        if state.err:
            state.fail_func("prereq failed")

        return state

    def test_02_create(self, pano, state_map):
        state = self.sanity(pano, state_map)

        state.fail_func = pytest.xfail
        state.err = True
        self.setup_state_obj(pano, state)
        state.obj.create()
        state.err = False

    def setup_state_obj(self, pano, state):
        pass

    def test_03_refreshall(self, pano, state_map):
        state = self.sanity(pano, state_map)

        objs = state.obj.refreshall(state.obj.parent, add=False)
        assert len(objs) >= 1

    def test_04_update(self, pano, state_map):
        state = self.sanity(pano, state_map)

        self.update_state_obj(pano, state)
        state.obj.apply()

    def update_state_obj(self, pano, state):
        pass

    def test_97_delete(self, pano, state_map):
        state = self.sanity(pano, state_map)

        state.obj.delete()

    def test_98_cleanup_dependencies(self, pano, state_map):
        state = state_map.setdefault(pano)

        self.cleanup_dependencies(pano, state)

    def cleanup_dependencies(self, pano, state):
        pass

    def test_99_removeall(self, pano, state_map):
        pano.removeall()

import pytest

from pandevice import device
from tests.live import testlib


class TestDeviceConfig(object):
    def toggle_object_variable(self, obj, var, new_value):
        original_value = getattr(obj, var)
        for value in (new_value, original_value):
            setattr(obj, var, value)
            obj.update(var)

    def test_01_get_device_config(self, dev, state_map):
        state = state_map.setdefault(dev)
        state.got_device_config = False

        dco = device.SystemSettings.refreshall(dev)
        state.got_device_config = True
        state.dco = dco[0]

    def test_02_update_hostname(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail("failed to get device config")

        # Change the hostname
        self.toggle_object_variable(state.dco, "hostname", testlib.random_name())

    def test_03_update_secondary_dns(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail("failed to get device config")

        # Toggle the secondary ip address
        self.toggle_object_variable(state.dco, "dns_secondary", testlib.random_ip())

    def test_04_create_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail("failed to get device config")

        primary = None
        secondary = None

        for x in state.dco.children:
            if x.__class__ == device.NTPServerPrimary:
                primary = x
            elif x.__class__ == device.NTPServerSecondary:
                secondary = x

        state.restore_ntp = False
        if primary is None:
            state.ntp_obj = device.NTPServerPrimary(address=testlib.random_ip())
        elif secondary is None:
            state.ntp_obj = device.NTPServerSecondary(address=testlib.random_ip())
        else:
            state.created_ntp = True
            state.restore_ntp = True
            state.ntp_obj = secondary
            pytest.skip("Both primary and secondary exist, nothing to create")

        state.dco.add(state.ntp_obj)
        state.ntp_obj.create()
        state.created_ntp = True

    def test_05_update_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail("failed to get device config")
        if not state.created_ntp:
            pytest.xfail("failed to create ntp in previous step")

        self.toggle_object_variable(state.ntp_obj, "address", testlib.random_ip())

    def test_06_delete_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail("failed to get device config")
        if not state.created_ntp:
            pytest.xfail("failed to create ntp in previous step")

        state.ntp_obj.delete()

    def test_07_restore_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail("failed to get device config")
        if not state.restore_ntp:
            pytest.skip("restore not needed")

        state.dco.add(state.ntp_obj)
        state.ntp_obj.create()

    def test_99_removeall(self, dev, state_map):
        dev.removeall()


class TestPasswordProfile(testlib.DevFlow):
    def setup_state_obj(self, dev, state):
        state.obj = device.PasswordProfile(testlib.random_name(), 0, 0, 0, 0)
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.expiration = 120
        state.obj.warning = 15
        state.obj.login_count = 1
        state.obj.grace_period = 15


class TestFirewallAdministrator(testlib.FwFlow):
    def create_dependencies(self, fw, state):
        state.profiles = []
        for x in range(2):
            state.profiles.append(
                device.PasswordProfile(testlib.random_name(), x, x, x, x)
            )
            fw.add(state.profiles[x])

        state.profiles[0].create_similar()

    def setup_state_obj(self, fw, state):
        state.obj = device.Administrator(
            testlib.random_name(), superuser=True, password_profile=state.profiles[0]
        )
        fw.add(state.obj)

    def update_state_obj(self, fw, state):
        state.obj.password_profile = state.profiles[1]

    def test_05_superuser_read_only(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.superuser = None
        state.obj.superuser_read_only = True

        state.obj.apply()

    def test_06_device_admin(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.superuser_read_only = None
        state.obj.device_admin = True

        state.obj.apply()

    def test_07_device_admin_read_only(self, fw, state_map):
        state = self.sanity(fw, state_map)

        state.obj.device_admin = None
        state.obj.device_admin_read_only = True

        state.obj.apply()

    def test_08_set_password(self, fw, state_map):
        state = self.sanity(fw, state_map)

        # Set the password
        state.obj.change_password("secret")

        # Now verify the change by trying to login
        new_fw = fw.__class__(fw.hostname, state.obj.uid, "secret")
        new_fw.refresh_system_info()

    def cleanup_dependencies(self, fw, state):
        try:
            state.profiles[0].delete_similar()
        except IndexError:
            pass


class TestPanoramaAdministrator(testlib.PanoFlow):
    def create_dependencies(self, pano, state):
        state.profiles = []
        for x in range(2):
            state.profiles.append(
                device.PasswordProfile(testlib.random_name(), x, x, x, x)
            )
            pano.add(state.profiles[x])

        state.profiles[0].create_similar()

    def setup_state_obj(self, pano, state):
        state.obj = device.Administrator(
            testlib.random_name(), superuser=True, password_profile=state.profiles[0]
        )
        pano.add(state.obj)

    def update_state_obj(self, pano, state):
        state.obj.password_profile = state.profiles[1]

    def test_05_superuser_read_only(self, pano, state_map):
        state = self.sanity(pano, state_map)

        state.obj.superuser = None
        state.obj.superuser_read_only = True

        state.obj.apply()

    def test_06_panorama_admin(self, pano, state_map):
        state = self.sanity(pano, state_map)

        state.obj.superuser_read_only = None
        state.obj.panorama_admin = True

        state.obj.apply()

    def test_07_set_password(self, pano, state_map):
        state = self.sanity(pano, state_map)

        # Set the password
        state.obj.change_password("secret")

        # Now verify the change by trying to login
        new_pano = pano.__class__(pano.hostname, state.obj.uid, "secret")
        new_pano.refresh_system_info()

    def cleanup_dependencies(self, pano, state):
        try:
            state.profiles[0].delete_similar()
        except IndexError:
            pass

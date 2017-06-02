import pytest

from pandevice import device


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
            pytest.xfail('failed to get device config')

        # Change the hostname
        self.toggle_object_variable(state.dco, 'hostname',
                                    state.random_name())

    def test_03_update_secondary_dns(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail('failed to get device config')

        # Toggle the secondary ip address
        self.toggle_object_variable(state.dco, 'dns_secondary',
                                    state.random_ip())

    def test_04_create_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail('failed to get device config')

        primary = None
        secondary = None

        for x in state.dco.children:
            if x.__class__ == device.NTPServerPrimary:
                primary = x
            elif x.__class__ == device.NTPServerSecondary:
                secondary = x

        state.restore_ntp = False
        if primary is None:
            state.ntp_obj = device.NTPServerPrimary(
                address=state.random_ip())
        elif secondary is None:
            state.ntp_obj = device.NTPServerSecondary(
                address=state.random_ip())
        else:
            state.created_ntp = True
            state.restore_ntp = True
            state.ntp_obj = secondary
            pytest.skip('Both primary and secondary exist, nothing to create')

        state.dco.add(state.ntp_obj)
        state.ntp_obj.create()
        state.created_ntp = True

    def test_05_update_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail('failed to get device config')
        if not state.created_ntp:
            pytest.xfail('failed to create ntp in previous step')

        self.toggle_object_variable(state.ntp_obj, 'address',
                                    state.random_ip())

    def test_06_delete_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail('failed to get device config')
        if not state.created_ntp:
            pytest.xfail('failed to create ntp in previous step')

        state.ntp_obj.delete()

    def test_07_restore_ntp(self, dev, state_map):
        state = state_map.setdefault(dev)
        if not state.got_device_config:
            pytest.xfail('failed to get device config')
        if not state.restore_ntp:
            pytest.skip('restore not needed')

        state.dco.add(state.ntp_obj)
        state.ntp_obj.create()

    def test_99_removeall(self, dev, state_map):
        dev.removeall()

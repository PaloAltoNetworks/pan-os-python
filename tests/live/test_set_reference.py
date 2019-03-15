import pytest

from pandevice.device import Vsys
from pandevice.firewall import Firewall
from pandevice.network import EthernetInterface
from pandevice.network import VirtualRouter
from pandevice.network import VirtualWire
from pandevice.network import Vlan
from pandevice.network import Zone
from pandevice.panorama import Panorama
from pandevice.panorama import Template

from tests.live import testlib


class VsysImport(object):
    CLASS = None
    VSYS_PARAM = None

    def sanity(self, dev, state_map, fw_test=False):
        state = state_map.setdefault(dev)
        if state.err:
            state.fail_func('prereq failed')

        if fw_test:
            if not isinstance(dev, Firewall):
                pytest.skip('Skipping firewall-only test')
            dev.removeall()
            dev.add(state.obj)
            vsys_list = Vsys.refreshall(dev, name_only=True)
            for v in vsys_list:
                v.refresh_variable(self.VSYS_PARAM)

        return state

    def assert_imported_into(self, vsys, state):
        found = False

        vsys_list = Vsys.refreshall(state.parent, add=False, name_only=True)
        for v in vsys_list:
            v.refresh_variable(self.VSYS_PARAM)
            if getattr(v, self.VSYS_PARAM) is None:
                setattr(v, self.VSYS_PARAM, [])
            if vsys == v.name:
                found = True
                assert state.name in getattr(v, self.VSYS_PARAM)
            else:
                assert state.name not in getattr(v, self.VSYS_PARAM)

        if vsys is not None:
            assert found

    def test_01_setup(self, dev, state_map):
        state = state_map.setdefault(dev)
        state.err = True
        state.fail_func = pytest.skip
        state.parent = dev
        state.name = None
        state.delete_parent = False
        state.obj = None

        if self.CLASS is None:
            pytest.skip('{0}.CLASS must be defined'.format(
                        self.__class__.__name__))
        elif self.VSYS_PARAM is None:
            pytest.skip('{0}.VSYS_PARAM must be defined'.format(
                        self.__class__.__name__))

        if isinstance(state.parent, Panorama):
            tmpl = Template(testlib.random_name())
            state.parent.add(tmpl)
            state.parent = tmpl
            state.parent.add(Vsys('vsys1'))
            state.parent.add(Vsys('vsys2'))
            state.parent.add(Vsys('vsys3'))
            state.parent.create()
            state.delete_parent = True
        else:
            vsys_list = [x.name for x in Vsys.refreshall(dev, add=False, name_only=True)]
            if not all('vsys{0}'.format(x) in vsys_list for x in range(1, 4)):
                pytest.skip('Firewall needs vsys1 - vsys3 to exist')

        args = {}
        if self.CLASS == EthernetInterface:
            state.name = testlib.get_available_interfaces(state.parent)[0]
            args = {'mode': 'layer3'}
        else:
            state.name = testlib.random_name()
        state.obj = self.CLASS(state.name, **args)
        state.parent.add(state.obj)
        state.err = False

    def test_02_create(self, dev, state_map):
        state = self.sanity(dev, state_map)

        state.err = True
        state.fail_func = pytest.xfail
        state.obj.create()
        state.err = False

    def test_03_vsys2_object_rt(self, dev, state_map):
        v = 'vsys2'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=True)

        assert isinstance(ans, Vsys)
        assert ans.name == v
        self.assert_imported_into(v, state)

    def test_04_update_false_does_not_update_object_rt(self, dev, state_map):
        v = 'vsys2'
        other_v = 'vsys3'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(other_v, refresh=True, update=False)

        assert isinstance(ans, Vsys)
        assert ans.name == other_v
        self.assert_imported_into(v, state)

    def test_05_import_into_lower_vsys_object_rt(self, dev, state_map):
        v = 'vsys1'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=True)

        assert isinstance(ans, Vsys)
        assert ans.name == v
        self.assert_imported_into(v, state)

    def test_06_import_into_higher_vsys_object_rt(self, dev, state_map):
        v = 'vsys3'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=True)

        assert isinstance(ans, Vsys)
        assert ans.name == v
        self.assert_imported_into(v, state)

    def test_07_import_into_current_vsys_object_rt(self, dev, state_map):
        v = 'vsys3'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=True)

        assert isinstance(ans, Vsys)
        assert ans.name == v
        self.assert_imported_into(v, state)

    def test_08_unimport_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(None, refresh=True, update=True)

        assert ans is None
        self.assert_imported_into(None, state)

    def test_09_unimport_when_unimported_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(None, refresh=True, update=True)

        assert ans is None
        self.assert_imported_into(None, state)

    def test_10_vsys2_bool_rt(self, dev, state_map):
        v = 'vsys2'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=True, return_type='bool')

        assert isinstance(ans, bool)
        assert ans
        self.assert_imported_into(v, state)

    def test_11_already_in_correct_vsys_bool_rt(self, dev, state_map):
        v = 'vsys2'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=True, return_type='bool')

        assert isinstance(ans, bool)
        assert not ans
        self.assert_imported_into(v, state)

    def test_12_same_vsys_no_update_bool_rt(self, dev, state_map):
        v = 'vsys2'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(v, refresh=True, update=False, return_type='bool')

        assert isinstance(ans, bool)
        assert not ans
        self.assert_imported_into(v, state)

    def test_13_different_vsys_no_update_bool_rt(self, dev, state_map):
        v = 'vsys2'
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys('vsys1', refresh=True, update=False, return_type='bool')

        assert isinstance(ans, bool)
        assert ans
        self.assert_imported_into(v, state)

    def test_20_setup_for_classic_tests(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = state.obj.set_vsys(None, refresh=True, update=True)

        assert ans is None
        self.assert_imported_into(None, state)

    def test_21_classic_import_object_rt(self, dev, state_map):
        v = 'vsys1'
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(v, refresh=False, update=True)

        assert isinstance(ans, Vsys)
        assert ans.name == v
        assert state.name in [str(x) for x in getattr(ans, self.VSYS_PARAM)]
        self.assert_imported_into(v, state)

    def test_22_classic_import_noop_object_rt(self, dev, state_map):
        v = 'vsys1'
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(v, refresh=False, update=True)

        assert isinstance(ans, Vsys)
        assert ans.name == v
        assert state.name in [str(x) for x in getattr(ans, self.VSYS_PARAM)]
        self.assert_imported_into(v, state)

    def test_23_classic_import_no_update_object_rt(self, dev, state_map):
        v = 'vsys1'
        other_v = 'vsys2'
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(other_v, refresh=False, update=False)

        assert isinstance(ans, Vsys)
        assert ans.name == other_v
        assert state.name in [str(x) for x in getattr(ans, self.VSYS_PARAM)]
        self.assert_imported_into(v, state)

    def test_24_classic_import_higher_vsys_object_rt(self, dev, state_map):
        v = 'vsys3'
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(v, refresh=False, update=True)

        previous_vsys = dev.find('vsys1')
        assert isinstance(ans, Vsys)
        assert ans.name == v
        assert state.name in [str(x) for x in getattr(ans, self.VSYS_PARAM)]
        assert previous_vsys is not None
        assert state.name not in [str(x) for x in (getattr(previous_vsys, self.VSYS_PARAM) or [])]
        self.assert_imported_into(v, state)

    def test_25_classic_import_lower_vsys_object_rt(self, dev, state_map):
        v = 'vsys2'
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(v, refresh=False, update=True)

        previous_vsys = dev.find('vsys3')
        assert isinstance(ans, Vsys)
        assert ans.name == v
        assert state.name in [str(x) for x in getattr(ans, self.VSYS_PARAM)]
        assert previous_vsys is not None
        assert state.name not in [str(x) for x in (getattr(previous_vsys, self.VSYS_PARAM) or [])]
        self.assert_imported_into(v, state)

    def test_26_classic_import_unimport_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(None, refresh=False, update=True)

        previous_vsys = dev.find('vsys2')
        assert ans is None
        assert previous_vsys is not None
        assert state.name not in (getattr(previous_vsys, self.VSYS_PARAM) or [])
        self.assert_imported_into(None, state)

    def test_27_classic_import_unimport_when_unimported_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map, True)

        ans = state.obj.set_vsys(None, refresh=False, update=True)

        assert ans is None
        self.assert_imported_into(None, state)

    def test_98_cleanup_dependencies(self, dev, state_map):
        state = state_map.setdefault(dev)

        if state.delete_parent:
            try:
                state.parent.delete()
            except Exception:
                pass
        else:
            try:
                state.obj.delete()
            except Exception:
                pass

    def test_99_removeall(self, dev, state_map):
        dev.removeall()


class TestInterfaceImport(VsysImport):
    CLASS = EthernetInterface
    VSYS_PARAM = 'interface'


class TestVirtualRouterImport(VsysImport):
    CLASS = VirtualRouter
    VSYS_PARAM = 'virtual_routers'


class TestVlanImport(VsysImport):
    CLASS = Vlan
    VSYS_PARAM = 'vlans'


class TestVirtualWireImport(VsysImport):
    CLASS = VirtualWire
    VSYS_PARAM = 'virtual_wires'


class PlaceInterface(object):
    FUNC = None
    CLASS = None
    PARAM = None

    def sanity(self, dev, state_map, fw_test=False):
        state = state_map.setdefault(dev)
        if state.err:
            state.fail_func('prereq failed')

        if fw_test:
            if not isinstance(dev, Firewall):
                pytest.skip('skipping firewall-only test')
            if self.CLASS != Zone:
                dev.vsys = None
            self.CLASS.refreshall(dev)

        if state.tmpl is None:
            dev.vsys = 'vsys2'

        return state

    def assert_placement(self, name, dev, state):
        found = False

        if state.tmpl is None and self.CLASS != Zone:
            dev.vsys = None

        obj_list = self.CLASS.refreshall(state.parent, add=False)
        for o in obj_list:
            if getattr(o, self.PARAM) is None:
                setattr(o, self.PARAM, [])
            if o.name == name:
                found = True
                assert state.name in getattr(o, self.PARAM)
            else:
                assert state.name not in getattr(o, self.PARAM)

        if name is not None:
            assert found

    def test_01_setup(self, dev, state_map):
        state = state_map.setdefault(dev)
        state.err = True
        state.fail_func = pytest.skip
        state.parent = dev
        state.tmpl = None
        state.name = None
        state.obj = None
        state.targets = [testlib.random_name() for x in range(2)]

        if self.FUNC is None:
            pytest.skip('{0}.FUNC must be defined'.format(
                        self.__class__.__name__))
        elif self.CLASS is None:
            pytest.skip('{0}.CLASS must be defined'.format(
                        self.__class__.__name__))
        elif self.PARAM is None:
            pytest.skip('{0}.PARAM must be defined'.format(
                        self.__class__.__name__))

        if isinstance(state.parent, Panorama):
            tmpl = Template(testlib.random_name())
            state.parent.add(tmpl)
            v = Vsys('vsys2')
            tmpl.add(v)
            state.parent = v
            tmpl.create()
            state.tmpl = tmpl
        else:
            vsys_list = [x.name for x in Vsys.refreshall(dev, add=False, name_only=True)]
            if 'vsys2' not in vsys_list:
                pytest.skip('Firewall needs vsys2 to exist')

        cls_args = {}
        eth_args = {'mode': 'layer3'}
        if self.CLASS == Vlan:
            eth_args['mode'] = 'layer2'
        elif self.CLASS == Zone:
            cls_args['mode'] = 'layer3'

        state.name = testlib.get_available_interfaces(state.parent)[0]
        state.obj = EthernetInterface(state.name, **eth_args)
        state.parent.add(state.obj)

        if state.tmpl is None:
            dev.vsys = 'vsys2'

        instances = [self.CLASS(state.targets[x], **cls_args) for x in range(2)]
        for x in instances:
            state.parent.add(x)
            x.create()

        state.err = False

    def test_02_create(self, dev, state_map):
        state = self.sanity(dev, state_map)

        state.err = True
        state.fail_func = pytest.xfail
        state.obj.create()
        state.obj.set_vsys('vsys2', refresh=True, update=True)
        state.err = False

    def test_03_set_no_priors_object_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=True)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        self.assert_placement(state.targets[i], dev, state)

    def test_04_update_false_does_not_update_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[1], refresh=True, update=False)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[1]
        self.assert_placement(state.targets[0], dev, state)

    def test_05_change_forward_object_rt(self, dev, state_map):
        i = 1
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=True)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        self.assert_placement(state.targets[i], dev, state)

    def test_06_change_backward_object_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=True)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        self.assert_placement(state.targets[i], dev, state)

    def test_07_change_to_current_object_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=True)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        self.assert_placement(state.targets[i], dev, state)

    def test_08_remove_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(None, refresh=True, update=True)

        assert ans is None
        self.assert_placement(None, dev, state)

    def test_09_remove_when_not_present_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(None, refresh=True, update=True)

        assert ans is None
        self.assert_placement(None, dev, state)

    def test_10_change_bool_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=True, return_type='bool')

        assert isinstance(ans, bool)
        assert ans
        self.assert_placement(state.targets[i], dev, state)

    def test_11_in_place_bool_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=True, return_type='bool')

        assert isinstance(ans, bool)
        assert not ans
        self.assert_placement(state.targets[i], dev, state)

    def test_12_same_spot_no_update_bool_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=True, update=False, return_type='bool')

        assert isinstance(ans, bool)
        assert not ans
        self.assert_placement(state.targets[i], dev, state)

    def test_13_different_spot_no_update_bool_rt(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(state.targets[1], refresh=True, update=False, return_type='bool')

        assert isinstance(ans, bool)
        assert ans
        self.assert_placement(state.targets[0], dev, state)

    def test_20_setup_for_classic_tests(self, dev, state_map):
        state = self.sanity(dev, state_map)

        ans = getattr(state.obj, self.FUNC)(None, refresh=True, update=True)

        assert ans is None
        self.assert_placement(None, dev, state)

    def test_21_classic_placement_object_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=False, update=True)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        assert state.name in [str(x) for x in getattr(ans, self.PARAM)]
        self.assert_placement(state.targets[i], dev, state)

    def test_22_classic_noop_object_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=False, update=True)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        assert state.name in [str(x) for x in getattr(ans, self.PARAM)]
        self.assert_placement(state.targets[i], dev, state)

    def test_23_classic_no_update_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(state.targets[1], refresh=False, update=False)

        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[1]
        assert state.name in [str(x) for x in getattr(ans, self.PARAM)]
        self.assert_placement(state.targets[0], dev, state)

    def test_24_classic_placement_move_forward_object_rt(self, dev, state_map):
        i = 1
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=False, update=True)

        prev_obj = state.parent.find(state.targets[0])
        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        assert state.name in [str(x) for x in getattr(ans, self.PARAM)]
        assert prev_obj is not None
        assert state.name not in [str(x) for x in (getattr(prev_obj, self.PARAM) or [])]
        self.assert_placement(state.targets[i], dev, state)

    def test_25_classic_placement_move_backward_object_rt(self, dev, state_map):
        i = 0
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(state.targets[i], refresh=False, update=True)

        prev_obj = state.parent.find(state.targets[1])
        assert isinstance(ans, self.CLASS)
        assert ans.name == state.targets[i]
        assert state.name in [str(x) for x in getattr(ans, self.PARAM)]
        assert prev_obj is not None
        assert state.name not in [str(x) for x in (getattr(prev_obj, self.PARAM) or [])]
        self.assert_placement(state.targets[i], dev, state)

    def test_26_classic_remove_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(None, refresh=False, update=True)

        prev_obj = state.parent.find(state.targets[0])
        assert ans is None
        assert prev_obj is not None
        assert state.name not in [str(x) for x in (getattr(prev_obj, self.PARAM) or [])]
        self.assert_placement(None, dev, state)

    def test_27_classic_remove_when_already_removed_object_rt(self, dev, state_map):
        state = self.sanity(dev, state_map, True)

        ans = getattr(state.obj, self.FUNC)(None, refresh=False, update=True)

        assert ans is None
        self.assert_placement(None, dev, state)

    def test_98_cleanup_dependencies(self, dev, state_map):
        state = self.sanity(dev, state_map)

        if state.tmpl is not None:
            try:
                state.tmpl.delete()
            except Exception:
                pass
        else:
            if self.CLASS != Zone:
                dev.vsys = None
            instances = self.CLASS.refreshall(dev, name_only=True)
            dev.vsys = 'vsys2'
            for o in instances:
                if o.name in state.targets:
                    try:
                        o.delete()
                    except Exception:
                        pass
            try:
                state.obj.delete()
            except Exception:
                pass
            if dev.vsys is not None:
                dev.vsys = None

    def test_99_removeall(self, dev, state_map):
        dev.removeall()


class TestVirtualRouterPlacement(PlaceInterface):
    FUNC = 'set_virtual_router'
    CLASS = VirtualRouter
    PARAM = 'interface'


class TestVlanPlacement(PlaceInterface):
    FUNC = 'set_vlan'
    CLASS = Vlan
    PARAM = 'interface'


class TestZonePlacement(PlaceInterface):
    FUNC = 'set_zone'
    CLASS = Zone
    PARAM = 'interface'

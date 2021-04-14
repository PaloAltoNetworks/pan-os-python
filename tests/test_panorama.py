import xml.etree.ElementTree as ET

try:
    from unittest import mock
except ImportError:
    import mock

from panos.panorama import DeviceGroup
from panos.panorama import Panorama


def _device_group_hierarchy():
    pano = Panorama("127.0.0.1", "admin", "admin", "secret")
    pano._version_info = (9999, 0, 0)
    dg = DeviceGroup("drums")
    pano.add(dg)
    pano.op = mock.Mock(
        return_value=ET.fromstring(
            """
<response code="19" status="success">
    <result>
        <dg-hierarchy>
            <dg dg_id="55" name="people">
                <dg dg_id="54" name="friends">
                    <dg dg_id="57" name="jack" />
                    <dg dg_id="58" name="jill" />
                </dg>
            </dg>
            <dg dg_id="11" name="solo group" />
            <dg dg_id="44" name="another solo group" />
            <dg dg_id="69" name="instruments">
                <dg dg_id="71" name="bass" />
                <dg dg_id="72" name="drums" />
                <dg dg_id="73" name="guitar" />
            </dg>
            <dg dg_id="100" name="parent">
                <dg dg_id="101" name="child" />
            </dg>
        </dg-hierarchy>
    </result>
</response>""",
        )
    )

    return dg


def test_panorama_dg_hierarchy_top_has_none_parent():
    dg = _device_group_hierarchy()

    ans = dg.parent.opstate.dg_hierarchy.fetch()

    for key in ("people", "solo group", "another solo group", "instruments", "parent"):
        assert key in ans
        assert ans[key] is None


def test_panorama_dg_hierarchy_first_level_child():
    dg = _device_group_hierarchy()

    ans = dg.parent.opstate.dg_hierarchy.fetch()

    fields = [
        ("people", "friends"),
        ("instruments", "bass"),
        ("instruments", "drums"),
        ("instruments", "guitar"),
        ("parent", "child"),
    ]

    for parent, child in fields:
        assert child in ans
        assert ans[child] == parent


def test_panorama_dg_hierarchy_second_level_children():
    dg = _device_group_hierarchy()

    ans = dg.parent.opstate.dg_hierarchy.fetch()

    for field in ("jack", "jill"):
        assert field in ans
        assert ans[field] == "friends"
        assert ans["friends"] == "people"
        assert ans["people"] is None


def test_device_group_hierarchy_refresh():
    dg = _device_group_hierarchy()

    assert dg.opstate.dg_hierarchy.parent is None

    dg.opstate.dg_hierarchy.refresh()

    assert dg.opstate.dg_hierarchy.parent == "instruments"

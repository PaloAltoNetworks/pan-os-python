import xml.etree.ElementTree as ET

import pytest

try:
    from unittest import mock
except ImportError:
    import mock

from panos.firewall import Firewall
from panos.objects import ApplicationContainer
from panos.objects import ApplicationObject
from panos.objects import ServiceObject
from panos.objects import Tag


PREDEFINED_CONFIG = {
    ApplicationContainer: {
        "single": "refresh_application",
        "multiple": "refreshall_applications",
        "refresher": "application",
        "var": "application_container_objects",
    },
    ApplicationObject: {
        "single": "refresh_application",
        "multiple": "refreshall_applications",
        "refresher": "application",
        "var": "application_objects",
    },
    ServiceObject: {
        "single": "refresh_service",
        "multiple": "refreshall_services",
        "refresher": "service",
        "var": "service_objects",
    },
    Tag: {
        "single": "refresh_tag",
        "multiple": "refreshall_tags",
        "refresher": "tag",
        "var": "tag_objects",
    },
}

PREDEFINED_TEST_DATA = (
    (
        """//*[contains(local-name(), "application")]/entry[@name='{0}']""",
        '//*[contains(local-name(), "application")]/entry',
        ApplicationContainer(
            name="ap container 1",
            applications=["func1", "func2"],
        ),
        ApplicationContainer(
            name="application container deux",
            applications=["a", "la", "mode"],
        ),
    ),
    (
        """//*[contains(local-name(), "application")]/entry[@name='{0}']""",
        '//*[contains(local-name(), "application")]/entry',
        ApplicationObject(
            name="app1",
            category="cat1",
            subcategory="subcat1",
            technology="tech1",
            risk=1,
            timeout=42,
            evasive_behavior=True,
            file_type_ident=True,
        ),
        ApplicationObject(
            name="app2",
            category="cat2",
            subcategory="subcat2",
            technology="tech2",
            risk=5,
            timeout=11,
            used_by_malware=True,
            consume_big_bandwidth=True,
            tag=["tag1", "tag2"],
        ),
    ),
    (
        None,
        "/service/entry",
        ServiceObject(
            name="foo",
            protocol="tcp",
            destination_port="12345",
            description="all your base",
            tag=["are belong", "to us"],
        ),
        ServiceObject(
            name="bar",
            protocol="udp",
            source_port="1025-2048",
            destination_port="1-1024",
            description="wu",
            tag=["tang", "clan"],
        ),
    ),
    (
        None,
        "/tag/entry",
        Tag(
            name="foo",
            color="color1",
            comments="First color",
        ),
        Tag(
            name="bar",
            color="color42",
            comments="Another color for another time",
        ),
    ),
)


def object_not_found():
    elm = ET.Element("response", {"code": "7", "status": "success"})
    ET.SubElement(elm, "result")

    return elm


@pytest.fixture(
    scope="function",
    params=[(x[0], x[2]) for x in PREDEFINED_TEST_DATA],
    ids=[x[2].__class__.__name__ for x in PREDEFINED_TEST_DATA],
)
def predef_single(request):
    request.param[1].parent = None
    return request.param


@pytest.fixture(
    scope="function",
    params=[(x[1], x[2:]) for x in PREDEFINED_TEST_DATA],
    ids=[x[2].__class__.__name__ for x in PREDEFINED_TEST_DATA],
)
def predef_multiple(request):
    for x in request.param[2:]:
        x.parent = None

    return request.param


def _fw(*args):
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._version_info = (9999, 0, 0)

    if len(args) == 0:
        fw.xapi.get = mock.Mock(return_value=object_not_found())
    else:
        prefix = "<response><result>"
        suffix = "</result></response>"
        inner = "".join(x.element_str().decode("utf-8") for x in args)
        fw.xapi.get = mock.Mock(
            return_value=ET.fromstring(
                prefix + inner + suffix,
            )
        )

    return fw


def test_single_object_xpath(predef_single):
    xpath, obj = predef_single
    conf = PREDEFINED_CONFIG[obj.__class__]
    expected = "/config/predefined"
    if xpath is not None:
        expected += xpath.format(obj.uid)
    else:
        expected += obj.xpath()
    fw = _fw(obj)

    getattr(fw.predefined, conf["single"])(obj.uid)

    fw.xapi.get.assert_called_once_with(expected, retry_on_peer=False)


def test_get_single_object(predef_single):
    xpath, obj = predef_single
    conf = PREDEFINED_CONFIG[obj.__class__]
    fw = _fw(obj)

    getattr(fw.predefined, conf["single"])(obj.uid)

    data = getattr(fw.predefined, conf["var"])
    assert obj.uid in data
    assert data[obj.uid].equal(obj)


def test_multiple_object_xpath(predef_multiple):
    xpath, objs = predef_multiple
    conf = PREDEFINED_CONFIG[objs[0].__class__]
    expected = "/config/predefined"
    if xpath is not None:
        expected += xpath
    else:
        expected += objs[0].xpath_short()
    fw = _fw(*objs)

    getattr(fw.predefined, conf["multiple"])()

    fw.xapi.get.assert_called_once_with(expected, retry_on_peer=False)


def test_get_multiple_objects(predef_multiple):
    xpath, objs = predef_multiple
    conf = PREDEFINED_CONFIG[objs[0].__class__]
    fw = _fw(*objs)

    getattr(fw.predefined, conf["multiple"])()

    for x in objs:
        data = getattr(fw.predefined, conf["var"])
        assert x.uid in data
        assert data[x.uid].equal(x)


def test_refresher_refresh_not_needed(predef_single):
    xpath, obj = predef_single
    conf = PREDEFINED_CONFIG[obj.__class__]
    fw = _fw()
    getattr(fw.predefined, conf["var"])[obj.uid] = obj

    ans = getattr(fw.predefined, conf["refresher"])(obj.uid)

    assert not fw.xapi.get.called
    assert ans.equal(obj)


def test_refresher_when_refresh_is_needed(predef_single):
    xpath, obj = predef_single
    conf = PREDEFINED_CONFIG[obj.__class__]
    fw = _fw(obj)

    ans = getattr(fw.predefined, conf["refresher"])(obj.uid)

    assert fw.xapi.get.called == 1
    assert ans.equal(obj)


def test_refresher_object_not_found_returns_none(predef_single):
    xpath, obj = predef_single
    conf = PREDEFINED_CONFIG[obj.__class__]
    fw = _fw()

    ans = getattr(fw.predefined, conf["refresher"])("foobar")

    assert fw.xapi.get.called == 1
    assert ans is None


def test_refreshall_invokes_all_refresh_methods():
    fw = _fw()

    for spec in PREDEFINED_CONFIG.values():
        getattr(fw.predefined, spec["var"])["a"] = "a"

    funcs = [x for x in dir(fw.predefined) if x.startswith("refreshall_")]
    for x in funcs:
        setattr(fw.predefined, x, mock.Mock())

    ans = fw.predefined.refreshall()

    assert ans is None
    for x in funcs:
        assert getattr(fw.predefined, x).called == 1

    for spec in PREDEFINED_CONFIG.values():
        assert len(getattr(fw.predefined, spec["var"])) == 0

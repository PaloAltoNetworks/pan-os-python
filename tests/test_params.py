import pytest
import xml.etree.ElementTree as ET

from panos.base import ENTRY, Root
from panos.base import VersionedPanObject, VersionedParamPath
from panos.firewall import Firewall


class FakeObject(VersionedPanObject):
    """Fake object for testing."""

    SUFFIX = ENTRY
    ROOT = Root.VSYS

    def _setup(self):
        self._xpaths.add_profile(value="/fake")

        params = []

        params.append(
            VersionedParamPath(
                "uuid",
                vartype="attrib",
                path="uuid",
            ),
        )
        params.append(
            VersionedParamPath(
                "size",
                vartype="int",
                path="size",
            ),
        )
        params.append(
            VersionedParamPath(
                "listing",
                vartype="member",
                path="listing",
            ),
        )
        params.append(
            VersionedParamPath(
                "pb1",
                vartype="exist",
                path="pb1",
            ),
        )
        params.append(
            VersionedParamPath(
                "pb2",
                vartype="exist",
                path="pb2",
            ),
        )
        params.append(
            VersionedParamPath(
                "live",
                vartype="yesno",
                path="live",
            ),
        )
        params.append(
            VersionedParamPath(
                "disabled",
                vartype="yesno",
                path="disabled",
            ),
        )
        params.append(
            VersionedParamPath(
                "uuid2",
                vartype="attrib",
                path="level-2/uuid",
            ),
        )
        params.append(
            VersionedParamPath(
                "age",
                vartype="int",
                path="level-2/age",
            ),
        )
        params.append(
            VersionedParamPath(
                "interfaces",
                vartype="member",
                path="level-2/interface",
            ),
        )

        self._params = tuple(params)


def _verify_render(o, expected):
    ans = o.element_str().decode("utf-8")

    assert ans == expected


def _refreshed_object():
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._version_info = (9999, 0, 0)

    o = FakeObject()
    fw.add(o)

    o = o.refreshall_from_xml(_refresh_xml())[0]

    return o


def _refresh_xml():
    return ET.fromstring(
        """
<result>
    <entry name="test" uuid="123-456">
        <size>5</size>
        <listing>
            <member>first</member>
            <member>second</member>
        </listing>
        <pb1 />
        <disabled>yes</disabled>
        <level-2 uuid="456-789">
            <age>12</age>
            <interface>
                <member>third</member>
                <member>fourth</member>
            </interface>
        </level-2>
    </entry>
</result>"""
    )


# int at base level
def test_render_int():
    _verify_render(
        FakeObject("test", size=5),
        '<entry name="test"><size>5</size></entry>',
    )


def test_parse_int():
    o = _refreshed_object()

    assert o.size == 5


# member list at base level
def test_render_member():
    _verify_render(
        FakeObject("test", listing=["one", "two"]),
        '<entry name="test"><listing><member>one</member><member>two</member></listing></entry>',
    )


def test_parse_member():
    o = _refreshed_object()

    assert o.listing == ["first", "second"]


# exist at base level
def test_render_exist():
    _verify_render(
        FakeObject("test", pb1=True),
        '<entry name="test"><pb1 /></entry>',
    )


def test_parse_exists():
    o = _refreshed_object()

    assert o.pb1
    assert not o.pb2


# yesno at base level
def test_render_yesno():
    _verify_render(
        FakeObject("test", disabled=True),
        '<entry name="test"><disabled>yes</disabled></entry>',
    )


def test_parse_yesno():
    o = _refreshed_object()

    assert o.disabled


# attrib
def test_render_attrib():
    _verify_render(
        FakeObject("test", uuid="123-456"),
        '<entry name="test" uuid="123-456" />',
    )


def test_parse_attrib():
    o = _refreshed_object()

    assert o.uuid == "123-456"


# int at depth 1
def test_render_d1_int():
    _verify_render(
        FakeObject("test", age=12),
        '<entry name="test"><level-2><age>12</age></level-2></entry>',
    )


def test_parse_d1_int():
    o = _refreshed_object()

    assert o.age == 12


# member list at depth 1
def test_render_d1_member():
    _verify_render(
        FakeObject("test", interfaces=["third", "fourth"]),
        "".join(
            [
                '<entry name="test"><level-2>',
                "<interface><member>third</member><member>fourth</member></interface>",
                "</level-2></entry>",
            ]
        ),
    )


def test_parse_d1_member():
    o = _refreshed_object()

    assert o.interfaces == ["third", "fourth"]


# uuid at depth 1
def test_render_d1_attrib_standalone():
    _verify_render(
        FakeObject("test", uuid2="456-789"),
        '<entry name="test"><level-2 uuid="456-789" /></entry>',
    )


def test_render_d1_attrib_mixed():
    _verify_render(
        FakeObject("test", uuid2="456-789", age=12),
        '<entry name="test"><level-2 uuid="456-789"><age>12</age></level-2></entry>',
    )


def test_parse_d1_attrib():
    o = _refreshed_object()

    assert o.uuid2 == "456-789"


# should raise an exception
def test_update_attrib_raises_not_implemented_exception():
    o = _refreshed_object()

    with pytest.raises(NotImplementedError):
        o.update("uuid")

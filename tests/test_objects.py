import xml.etree.ElementTree as ET

import pytest

from panos.objects import ApplicationObject


@pytest.mark.parametrize(
    "default_type",
    ["ident-by-icmp-type", "ident-by-icmp6-type"],
)
def test_application_object_renders_icmp_type_and_code_ranges(default_type):
    obj = ApplicationObject(
        "icmp-range",
        default_type=default_type,
        default_icmp_type="13-14",
        default_icmp_code="5-6",
    )
    expected = "".join(
        [
            '<entry name="icmp-range"><default><{0}>'.format(default_type),
            "<type>13-14</type>",
            "<code>5-6</code>",
            "</{0}></default></entry>".format(default_type),
        ]
    )

    assert obj.element_str().decode("utf-8") == expected


@pytest.mark.parametrize(
    "default_type",
    ["ident-by-icmp-type", "ident-by-icmp6-type"],
)
def test_application_object_parses_icmp_type_and_code_ranges(default_type):
    obj = ApplicationObject()
    xml = ET.fromstring(
        """
<entry name="icmp-range">
    <default>
        <{0}>
            <type>13-14</type>
            <code>5-6</code>
        </{0}>
    </default>
</entry>
""".format(default_type)
    )

    obj.parse_xml(xml)

    assert obj.default_type == default_type
    assert obj.default_icmp_type == "13-14"
    assert obj.default_icmp_code == "5-6"

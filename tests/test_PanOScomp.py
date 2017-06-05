import pytest

from pandevice import PanOSVersion

@pytest.mark.parametrize("panos1, panos2", [
    ("6.1.0", "6.1.0"),
    ("0.0.0", "0.0.0"),
    ("7.3.4-h1", "7.3.4-h1"),
    ("3.4.2-c5", "3.4.2-c5"),
    ("4.4.4-b8", "4.4.4-b8")
])
def test_eq(panos1, panos2):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert x == y
    assert (x != y) == False
    assert x >= y
    assert x <= y
    assert (x > y) == False
    assert (x < y) == False

@pytest.mark.parametrize("panos1, panos2", [
    ("6.1.1", "6.2.0"),
    ("0.0.0", "0.0.1"),
    ("7.3.4-h1", "8.1.0-b2"),
    ("3.4.2-c5", "3.4.2-c7"),
    ("4.4.4-b8", "4.4.4-b10"),
    ("3.3.3-h3", "3.3.3-h5"),
    ("2.3.4-h3", "2.3.5-h3"),
    ("1.8.7-c3", "1.8.7-b3"),
    ("3.2.1-c8", "3.2.1"),
    ("4.5.3-c13", "4.5.3-h13"),
    ("4.5.3-c13", "4.5.3-h15"),
    ("3.6.6-b4", "3.6.6-h4"),
    ("3.6.6-b4", "3.6.6-h6"),
    ("7.0.0", "7.0.0-h2"),
    ("2.3.3-b3", "2.3.4"),
    ("2.3.3-c8", "2.3.4"),
    ("2.3.3-h7", "2.3.4"),
    ("3.4.2-c3", "3.4.3-h1"),
    ("3.2.1-b8", "3.2.2-h1")
])
def test_comp(panos1, panos2):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert y > x
    assert y >= x
    assert x < y
    assert x <= y
    assert x != y
    assert (x == y) == False


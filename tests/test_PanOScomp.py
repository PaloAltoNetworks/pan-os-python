import pytest

from pandevice import PanOSVersion

@pytest.mark.parametrize("panos1, panos2", [
    ("6.1.0", "6.1.0"),
    ("0.0.0", "0.0.0"),
    ("7.3.4-h1", "7.3.4-h1"),
    ("3.4.2-c5", "3.4.2-c5"),
    ("4.4.4-b8", "4.4.4-b8")
])
def test_gen_eq(panos1, panos2):
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
    ("0.0.9-h18", "9.0.0-c1"),
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
    ("7.0.0-b3", "7.0.0"),
    ("7.0.0-c7", "7.0.0"),
    ("2.3.3-b3", "2.3.4"),
    ("2.3.3-c8", "2.3.4"),
    ("2.3.3-h7", "2.3.4"),
    ("3.4.2-c3", "3.4.3-h1"),
    ("3.2.1-b8", "3.2.2-h1"),
    ("4.2.2-h10", "4.2.2-h11"),
    ("5.3.3-c4", "5.3.3-h1"),
    ("5.4.2-b8", "5.4.2-h1")
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


@pytest.mark.parametrize("panos1, panos2, expected", [
    ("3.4.1", "3.4.1", True),
    ("4.2.6-b8", "4.2.6-b8", True),
    ("7.1.9-c3", "7.1.9-c3", True),
    ("4.5.6-h8", "4.5.6-h8", True),
    ("4.2.1", "5.2.1", False),
    ("4.2.1", "4.2.2", False),
    ("4.2.1", "4.3.1", False),
    ("3.2.6", "3.2.6-b7", False),
    ("4.5.6", "4.5.6-h8", False),
    ("7.1.9", "7.1.9-c3", False),
    ("7.1.9-b7", "7.1.9-c3", False),
    ("4.5.6-b4", "4.5.6-h8", False),
    ("4.5.6-c6", "4.5.6-h8", False),
    ("3.2.1-h3", "3.2.1-h2", False)
])
def test_eq(panos1, panos2, expected):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert (x == y) == expected


@pytest.mark.parametrize("panos1, panos2, expected", [
    ("3.4.1", "3.4.1", False),
    ("4.2.6-b8", "4.2.6-b8", False),
    ("7.1.9-c3", "7.1.9-c3", False),
    ("4.5.6-h8", "4.5.6-h8", False),
    ("4.2.1", "5.2.1", True),
    ("4.2.1", "4.2.2", True),
    ("4.2.1", "4.3.1", True),
    ("3.2.6", "3.2.6-b7", True),
    ("4.5.6", "4.5.6-h8", True),
    ("7.1.9", "7.1.9-c3", True),
    ("7.1.9-b7", "7.1.9-c3", True),
    ("4.5.6-b4", "4.5.6-h8", True),
    ("4.5.6-c6", "4.5.6-h8", True),
    ("3.2.1-h3", "3.2.1-h2", True)
])
def test_neq(panos1, panos2, expected):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert (x != y) == expected


@pytest.mark.parametrize("panos1, panos2, expected", [
    ("0.9.9", "1.0.0", True),
    ("3.8.7", "3.8.8", True),
    ("6.1.1", "6.2.0", True),
    ("0.0.0", "0.0.1", True),
    ("0.0.9-h18", "9.0.0-c1", True),
    ("7.3.4-b2", "8.1.0-h1", True),
    ("3.4.2-c5", "3.4.2-c3", False),
    ("4.4.4-b8", "4.4.4-b10", True),
    ("3.3.3-h3", "3.3.3-h5", True),
    ("2.3.4-h3", "2.2.5-h3", False),
    ("1.8.7-c3", "1.8.7-b3", True),
    ("3.2.1-c8", "3.2.1", True),
    ("4.5.3-h13", "4.5.3-c13", False),
    ("4.5.3-c13", "4.5.3-h15", True),
    ("3.6.6-b4", "3.6.6-h4", True),
    ("3.6.6-b4", "3.6.6-h6", True),
    ("7.0.0", "7.0.0-b2", False),
    ("7.0.0-h3", "7.0.0", False),
    ("7.0.0-c7", "7.0.0", True),
    ("2.3.3-b3", "2.3.4", True),
    ("2.3.3-c8", "2.3.4", True),
    ("2.3.3-h7", "2.3.4", True),
    ("3.4.2-c3", "3.4.3-h1", True),
    ("3.2.1-b8", "3.2.2-h1", True),
    ("4.2.2-h10", "4.2.2-h11", True),
    ("5.3.3-c4", "5.3.3-h1", True),
    ("5.4.2-b8", "5.4.2-h1", True),
    ("3.4.1", "3.4.1", False),
    ("4.2.6-b8", "4.2.6-b8", False),
    ("7.1.9-c3", "7.1.9-c3", False),
    ("4.5.6-h8", "4.5.6-h8", False),
    ("9.9.9", "0.0.0", False),
    ("5.4.3-b9", "5.4.2-b10", False),
    ("3.7.8-b1", "3.7.8-c3", False),
])
def test_lt(panos1, panos2, expected):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert (x < y) == expected


@pytest.mark.parametrize("panos1, panos2, expected", [
    ("0.9.9", "1.0.0", False),
    ("3.8.7", "3.6.8", True),
    ("6.1.1", "6.2.0", False),
    ("0.1.0", "0.0.1", True),
    ("0.0.9-h18", "9.0.0-c1", False),
    ("7.3.4-b2", "8.1.0-h1", False),
    ("3.4.2-c5", "3.4.2-c3", True),
    ("4.4.4-b8", "4.4.4-b4", True),
    ("3.3.3-h3", "3.3.3-h1", True),
    ("2.3.4-h3", "2.2.5-h7", True),
    ("1.8.7-b3", "1.8.7-c3", True),
    ("3.2.1-c8", "3.2.1", False),
    ("4.5.3-h13", "4.5.3-c13", True),
    ("4.5.3-c13", "4.5.3-h15", False),
    ("3.6.6-b4", "3.6.6-c4", True),
    ("3.6.6-b4", "3.6.6-h6", False),
    ("7.0.0", "7.0.0-b2", True),
    ("7.0.0-h3", "7.0.0", True),
    ("7.0.0-c7", "7.0.0", False),
    ("2.3.3-h3", "2.3.4", False),
    ("2.3.5-c8", "2.3.4", True),
    ("2.3.3-h7", "2.3.4", False),
    ("3.4.4-c3", "3.4.3-h1", True),
    ("3.2.1-b8", "3.2.2-h1", False),
    ("4.2.2-h10", "4.2.2-h9", True),
    ("5.3.3-h4", "5.3.3-c1", True),
    ("5.4.2-b8", "5.4.2-h1", False),
    ("3.4.1", "3.4.1", False),
    ("4.2.6-b8", "4.2.6-b8", False),
    ("7.1.9-c3", "7.1.9-c3", False),
    ("4.5.6-h8", "4.5.6-h8", False),
    ("9.9.9", "0.0.0", True),
    ("5.4.2-b9", "5.4.2-c12", True),
    ("3.7.8-b1", "3.7.8-c3", True),
])
def test_gt(panos1, panos2, expected):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert (x > y) == expected


@pytest.mark.parametrize("panos1, panos2, expected", [
    ("0.9.9", "1.0.0", True),
    ("3.8.7", "3.8.8", True),
    ("6.1.1", "6.2.0", True),
    ("0.0.0", "0.0.1", True),
    ("0.0.9-h18", "9.0.0-c1", True),
    ("7.3.4-b2", "8.1.0-h1", True),
    ("3.4.2-c5", "3.4.2-c3", False),
    ("4.4.4-b8", "4.4.4-b10", True),
    ("3.3.3-h3", "3.3.3-h5", True),
    ("2.3.4-h3", "2.2.5-h3", False),
    ("1.8.7-c3", "1.8.7-b3", True),
    ("3.2.1-c8", "3.2.1", True),
    ("4.5.3-h13", "4.5.3-c13", False),
    ("4.5.3-c13", "4.5.3-h15", True),
    ("3.6.6-b4", "3.6.6-h4", True),
    ("3.6.6-b4", "3.6.6-h6", True),
    ("7.0.0", "7.0.0-b2", False),
    ("7.0.0-h3", "7.0.0", False),
    ("7.0.0", "7.0.0-c7", False),
    ("2.3.3-b3", "2.3.4", True),
    ("2.3.3-c8", "2.3.4", True),
    ("2.3.3-h7", "2.3.4", True),
    ("3.4.2-c3", "3.4.3-h1", True),
    ("3.2.1-b8", "3.2.2-h1", True),
    ("4.2.2-h10", "4.2.2-h11", True),
    ("5.3.3-c4", "5.3.3-h1", True),
    ("5.4.2-b8", "5.4.2-h1", True),
    ("3.4.1", "3.4.1", True),
    ("4.2.6-b8", "4.2.6-b8", True),
    ("7.1.9-c3", "7.1.9-c3", True),
    ("4.5.6-h8", "4.5.6-h8", True),
    ("9.9.9", "0.0.0", False),
    ("5.4.3-b9", "5.4.2-b10", False),
    ("3.7.8-b1", "3.7.8-c3", False),
])
def test_le(panos1, panos2, expected):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert (x <= y) == expected

@pytest.mark.parametrize("panos1, panos2, expected", [
    ("0.9.9", "1.0.0", False),
    ("3.8.7", "3.6.8", True),
    ("6.1.1", "6.2.0", False),
    ("0.1.0", "0.0.1", True),
    ("0.0.9-h18", "9.0.0-c1", False),
    ("7.3.4-b2", "8.1.0-h1", False),
    ("3.4.2-c5", "3.4.2-c3", True),
    ("4.4.4-b8", "4.4.4-b4", True),
    ("3.3.3-h3", "3.3.3-h1", True),
    ("2.3.4-h3", "2.2.5-h7", True),
    ("1.8.7-b3", "1.8.7-c3", True),
    ("3.2.1-c8", "3.2.1", False),
    ("4.5.3-h13", "4.5.3-c13", True),
    ("4.5.3-c13", "4.5.3-h15", False),
    ("3.6.6-b4", "3.6.6-c4", True),
    ("3.6.6-b4", "3.6.6-h6", False),
    ("7.0.0", "7.0.0-b2", True),
    ("7.0.0-h3", "7.0.0", True),
    ("7.0.0-c7", "7.0.0", False),
    ("2.3.3-h3", "2.3.4", False),
    ("2.3.5-c8", "2.3.4", True),
    ("2.3.3-h7", "2.3.4", False),
    ("3.4.4-c3", "3.4.3-h1", True),
    ("3.2.1-b8", "3.2.2-h1", False),
    ("4.2.2-h10", "4.2.2-h9", True),
    ("5.3.3-h4", "5.3.3-c1", True),
    ("5.4.2-b8", "5.4.2-h1", False),
    ("3.4.1", "3.4.1", True),
    ("4.2.6-b8", "4.2.6-b8", True),
    ("7.1.9-c3", "7.1.9-c3", True),
    ("4.5.6-h8", "4.5.6-h8", True),
    ("9.9.9", "0.0.0", True),
    ("5.4.2-b9", "5.4.2-c12", True),
    ("3.7.8-b1", "3.7.8-c3", True),
])
def test_ge(panos1, panos2, expected):
    x = PanOSVersion(panos1)
    y = PanOSVersion(panos2)
    assert (x >= y) == expected

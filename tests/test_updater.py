from unittest import mock
from unittest.mock import Mock, patch

import pytest

from panos import PanOSVersion
from panos.firewall import Firewall
from panos.panorama import Panorama
from panos.updater import SoftwareUpdater

firewall_latest = "12.0.1"
firewall_versionlist_to_test = [
    "12.0.1",
    "12.0.0",
    "11.3.1-h1",
    "11.3.1",
    "11.3.0",
    "11.2.1-h1",
    "11.2.1",
    "11.2.0",
    "11.1.1-h1",
    "11.1.1",
    "11.1.0",
    "11.0.2",
    "11.0.2-h1",
    "11.0.1",
    "11.0.1-h2",
    "11.0.0",
    "10.2.3",
    "10.2.1",
    "10.2.1-h2",
    "10.2.0",
    "10.1.1",
    "10.1.1-h2",
    "10.1.0",
    "10.0.1",
    "10.0.1-h2",
    "10.0.0",
    "9.1.1",
    "9.1.1-h2",
    "9.1.0",
    "9.0.1",
    "9.0.1-h2",
    "9.0.0",
    "8.1.1",
    "8.1.1-h2",
    "8.1.0",
    "8.0.1",
    "8.0.1-h2",
    "8.0.0",
    "7.1.1",
    "7.1.1-h2",
    "7.1.0",
    "7.0.3",
    "7.0.2",
    "7.0.1",
    "7.0.1-h2",
    # "7.0.0",  # 7.0.0 was pulled
    "6.1.1",
    "6.1.1-h2",
    "6.1.0",
    "6.0.3",
    "6.0.2",
    "6.0.1",
    "6.0.1-h2",
    "6.0.0",
    # "5.1.1",  # No 5.1 for firewalls
    # "5.1.1-h2",  # No 5.1 for firewalls
    # "5.1.0",  # No 5.1 for firewalls
    "5.0.1",
    "5.0.1-h2",
    "5.0.0",
]

firewall_versionlist_to_test_dict = {
    version: {
        "version": version,
        "filename": f"PanOS_vm-{version}",
        "size": "497",
        "size-kb": "509820",
        "released-on": "2023/06/28 12:13:04",
        "release-notes": f"https://www.paloaltonetworks.com/documentation/{version}/pan-os/pan-os-release-notes",
        "downloaded": True,
        "current": False,
        "latest": version == firewall_latest,
    }
    for version in firewall_versionlist_to_test
}

firewall_next_expected_version = [
    ("5.0.0", "6.0.0"),  # Special case, there was no 5.1 for firewalls
    ("5.0.1", "6.0.0"),  # Special case, there was no 5.1 for firewalls
    ("5.1.0", "6.0.0"),
    ("5.1.2", "6.0.0"),
    ("6.0.0", "6.1.0"),
    ("6.0.3", "6.1.0"),
    ("6.1.0", "7.0.1"),  # Special case, 7.0.0 was revoked
    ("6.1.4", "7.0.1"),  # Special case, 7.0.0 was revoked
    ("7.0.0", "7.1.0"),
    ("7.0.5", "7.1.0"),
    ("7.1.0", "8.0.0"),
    ("7.1.6", "8.0.0"),
    ("8.0.0", "8.1.0"),
    ("8.0.7", "8.1.0"),
    ("8.1.0", "9.0.0"),
    ("8.1.8", "9.0.0"),
    ("9.0.0", "9.1.0"),
    ("9.0.9", "9.1.0"),
    ("9.1.0", "10.0.0"),
    ("9.1.10", "10.0.0"),
    ("10.0.0", "10.1.0"),
    ("10.0.11", "10.1.0"),
    ("10.1.0", "10.2.0"),
    ("10.1.10-h2", "10.2.0"),
    ("10.1.12", "10.2.0"),
    ("10.2.0", "11.0.0"),
    ("10.2.12", "11.0.0"),
    ("11.0.0", "11.1.0"),
    ("11.0.13", "11.1.0"),
    ("11.1.0", "11.2.0"),
    ("11.1.13", "11.2.0"),
    ("11.2.0", "11.3.0"),
    ("11.2.13", "11.3.0"),
    ("11.3.0", "12.0.0"),
    ("11.3.13", "12.0.0"),
]

firewall_valid_direct_upgrade_paths = [
    ("9.0.0", "9.0.2"),
    ("9.0.9", "9.0.11"),
    ("9.1.0", "9.1.3-h2"),
    ("9.1.10", "9.1.33"),
    ("10.0.0", "10.0.5"),
    ("10.0.0", "10.0.1"),
    ("10.1.0", "10.1.2"),
    ("10.1.10-h2", "10.1.10-h4"),
    ("10.1.12-h4", "10.1.13"),
    ("10.2.0", "10.2.14"),
    ("10.2.0", "10.2.14"),
]

firewall_invalid_direct_upgrade_paths = [
    ("9.0.0", "8.0.0"),  # Downgrade
    ("10.0.0", "8.0.0"),  # Downgrade
    ("10.1.4", "10.1.2"),  # Downgrade
    ("10.1.4-h4", "10.1.4-h2"),  # Downgrade
    ("8.0.0", "9.0.0"),  # Skips minor version
    ("8.0.0", "9.0.1"),  # Skips minor version,not first patch of release
    ("8.0.0", "9.1.0"),  # Skips minor version,not first minor of next release
    ("8.0.0", "9.1.2"),  # Skips minor version,not first patch of release
    ("8.0.0", "10.0.0"),  # Skips major version
    ("9.0.0", "9.1.5"),  # Not first patch version of release
    ("9.0.1", "10.0.3"),  # Skips minor version
    ("9.0.1", "11.0.5"),  # Skips major version
    ("10.1.10-h2", "10.2.3"),  # Not first patch version of release
    ("5.0.0", "5.1.0"),  # Special case, there was no 5.1 for firewalls
    ("6.1.0", "7.0.0"),  # Special case, 7.0.0 was revoked
    ("10.1.0", "11.0.0"),  # New trend,first x.2.x numbered release was 10.2
]


def _fw():
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    return fw


# Test next expected valid
@pytest.mark.parametrize(
    "input_version, expected_next_minor", firewall_next_expected_version
)
def test_next_minor_version_firewall_valid(input_version, expected_next_minor):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    next_minor = swUpdater._next_minor_version(
        PanOSVersion(input_version), firewall_versionlist_to_test
    )
    assert next_minor == expected_next_minor


# Test next expected invalid
@pytest.mark.parametrize(
    "input_version, expected_next_minor", firewall_invalid_direct_upgrade_paths
)
def test_next_minor_version_firewall_invalid(input_version, expected_next_minor):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    next_minor = swUpdater._next_minor_version(
        PanOSVersion(input_version), firewall_versionlist_to_test
    )
    assert next_minor != expected_next_minor


# Test valid direct upgrades return True
@pytest.mark.parametrize(
    "input_version, target_version", firewall_valid_direct_upgrade_paths
)
def test__direct_upgrade_possible_firewall_valid(input_version, target_version):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    assert swUpdater._direct_upgrade_possible(
        input_version, target_version, firewall_versionlist_to_test
    )


# Test next expected versions return True
@pytest.mark.parametrize(
    "input_version, target_version", firewall_next_expected_version
)
def test__direct_upgrade_possible_firewall_valid_expected_next_versions(
    input_version, target_version
):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    assert swUpdater._direct_upgrade_possible(
        input_version, target_version, firewall_versionlist_to_test
    )


# Test invalid direct upgrades return False
@pytest.mark.parametrize(
    "input_version, target_version", firewall_invalid_direct_upgrade_paths
)
def test__direct_upgrade_possible_firewall_invalid(input_version, target_version):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    assert not swUpdater._direct_upgrade_possible(
        input_version, target_version, firewall_versionlist_to_test
    )


panorama_latest = "12.0.1"
panorama_versionlist_to_test = [
    "12.0.1",
    "12.0.0",
    "11.3.1-h1",
    "11.3.1",
    "11.3.0",
    "11.2.1-h1",
    "11.2.1",
    "11.2.0",
    "11.1.1-h1",
    "11.1.1",
    "11.1.0",
    "11.0.2",
    "11.0.2-h1",
    "11.0.1",
    "11.0.1-h2",
    "11.0.0",
    "10.2.1",
    "10.2.1-h2",
    "10.2.0",
    "10.1.1",
    "10.1.1-h2",
    "10.1.0",
    "10.0.1",
    "10.0.1-h2",
    "10.0.0",
    "9.1.1",
    "9.1.1-h2",
    "9.1.0",
    "9.0.1",
    "9.0.1-h2",
    "9.0.0",
    "8.1.1",
    "8.1.1-h2",
    "8.1.0",
    "8.0.1",
    "8.0.1-h2",
    "8.0.0",
    "7.1.1",
    "7.1.1-h2",
    "7.1.0",
    "7.0.3",
    "7.0.2",
    "7.0.1",
    "7.0.1-h2",
    # "7.0.0",  # 7.0.0 was pulled
    "6.1.1",
    "6.1.1-h2",
    "6.1.0",
    "6.0.3",
    "6.0.2",
    "6.0.1",
    "6.0.1-h2",
    "6.0.0",
    "5.1.1",  # 5.1 was only for Panorama, not for firewalls
    "5.1.1-h2",  # 5.1 was only for Panorama, not for firewalls
    "5.1.0",  # 5.1 was only for Panorama, not for firewalls
    "5.0.1",
    "5.0.1-h2",
    "5.0.0",
]
panorama_versionlist_to_test_dict = {
    version: {
        "version": version,
        "filename": f"PanOS_vm-{version}",
        "size": "497",
        "size-kb": "509820",
        "released-on": "2023/06/28 12:13:04",
        "release-notes": f"https://www.paloaltonetworks.com/documentation/{version}/pan-os/pan-os-release-notes",
        "downloaded": True,
        "current": False,
        "latest": version == panorama_latest,
    }
    for version in panorama_versionlist_to_test
}

panorama_next_expected_version = [
    ("5.0.0", "5.1.0"),
    ("5.0.1", "5.1.0"),
    ("5.1.0", "6.0.0"),
    ("5.1.2", "6.0.0"),
    ("6.0.0", "6.1.0"),
    ("6.0.3", "6.1.0"),
    ("6.1.0", "7.0.1"),  # Special case, 7.0.0 was revoked
    ("6.1.4", "7.0.1"),  # Special case, 7.0.0 was revoked
    ("7.0.0", "7.1.0"),
    ("7.0.5", "7.1.0"),
    ("7.1.0", "8.0.0"),
    ("7.1.6", "8.0.0"),
    ("8.0.0", "8.1.0"),
    ("8.0.7", "8.1.0"),
    ("8.1.0", "9.0.0"),
    ("8.1.8", "9.0.0"),
    ("9.0.0", "9.1.0"),
    ("9.0.9", "9.1.0"),
    ("9.1.0", "10.0.0"),
    ("9.1.10", "10.0.0"),
    ("10.0.0", "10.1.0"),
    ("10.0.11", "10.1.0"),
    ("10.1.0", "10.2.0"),
    ("10.1.10-h2", "10.2.0"),
    ("10.1.12", "10.2.0"),
    ("10.2.0", "11.0.0"),
    ("10.2.12", "11.0.0"),
    ("11.0.0", "11.1.0"),
    ("11.0.13", "11.1.0"),
    ("11.1.0", "11.2.0"),
    ("11.1.13", "11.2.0"),
    ("11.2.0", "11.3.0"),
    ("11.2.13", "11.3.0"),
    ("11.3.0", "12.0.0"),
    ("11.3.13", "12.0.0"),
]

panorama_valid_direct_upgrade_paths = [
    ("9.0.0", "9.0.2"),
    ("9.0.9", "9.0.11"),
    ("9.1.0", "9.1.3-h2"),
    ("9.1.10", "9.1.33"),
    ("10.0.0", "10.0.5"),
    ("10.0.0", "10.0.1"),
    ("10.1.0", "10.1.2"),
    ("10.1.10-h2", "10.1.10-h4"),
    ("10.1.12-h4", "10.1.13"),
    ("10.2.0", "10.2.14"),
    ("10.2.0", "10.2.14"),
]

panorama_invalid_direct_upgrade_paths = [
    ("9.0.0", "8.0.0"),  # Downgrade
    ("10.0.0", "8.0.0"),  # Downgrade
    ("10.1.4", "10.1.2"),  # Downgrade
    ("10.1.4-h4", "10.1.4-h2"),  # Downgrade
    ("8.0.0", "9.0.0"),  # Skips minor version
    ("8.0.0", "9.0.1"),  # Skips minor version,not first patch of release
    ("8.0.0", "9.1.0"),  # Skips minor version,not first minor of next release
    ("8.0.0", "9.1.2"),  # Skips minor version,not first patch of release
    ("8.0.0", "10.0.0"),  # Skips major version
    ("9.0.0", "9.1.5"),  # Not first patch version of release
    ("9.0.1", "10.0.3"),  # Skips minor version
    ("9.0.1", "11.0.5"),  # Skips major version
    ("10.1.10-h2", "10.2.3"),  # Not first patch version of release
    ("6.1.0", "7.0.0"),  # Special case, 7.0.0 was revoked
    ("10.1.0", "11.0.0"),  # New trend,first x.2.x numbered release was 10.2
]


def _rama():
    rama = Panorama("127.0.0.1", "admin", "admin", "secret")
    return rama


# Test next expected valid
@pytest.mark.parametrize(
    "input_version, expected_next_minor", panorama_next_expected_version
)
def test_next_minor_version_panorama_valid(input_version, expected_next_minor):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    next_minor = swUpdater._next_minor_version(
        PanOSVersion(input_version), panorama_versionlist_to_test
    )
    assert next_minor == expected_next_minor


# Test next expected invalid
@pytest.mark.parametrize(
    "input_version, expected_next_minor", panorama_invalid_direct_upgrade_paths
)
def test_next_minor_version_panorama_invalid(input_version, expected_next_minor):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    next_minor = swUpdater._next_minor_version(
        PanOSVersion(input_version), panorama_versionlist_to_test
    )
    assert next_minor != expected_next_minor


# Test valid direct upgrades return True
@pytest.mark.parametrize(
    "input_version, target_version", panorama_next_expected_version
)
def test__direct_upgrade_possible_panorama_valid(input_version, target_version):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    assert swUpdater._direct_upgrade_possible(
        input_version, target_version, panorama_versionlist_to_test
    )


# Test next expected versions return True
@pytest.mark.parametrize(
    "input_version, target_version", panorama_next_expected_version
)
def test__direct_upgrade_possible_panorama_valid_expected_next_versions(
    input_version, target_version
):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    assert swUpdater._direct_upgrade_possible(
        input_version, target_version, panorama_versionlist_to_test
    )


# Test invalid direct upgrades return False
@pytest.mark.parametrize(
    "input_version, target_version", panorama_invalid_direct_upgrade_paths
)
def test__direct_upgrade_possible_panorama_invalid(input_version, target_version):
    fw = _fw()
    swUpdater = SoftwareUpdater(fw)
    assert not swUpdater._direct_upgrade_possible(
        input_version, target_version, panorama_versionlist_to_test
    )


###################################################
###################################################
# class MockedSoftwareUpdater:
#     def __init__(self, *args, **kwargs):
#         self.pandevice = None
#         self.versions = []

#     def check(self):
#         # Override the check method to do nothing
#         pass

#     # def upgrade_to_version(self, target_version, dryrun=False):
#         # Your implementation of upgrade_to_version here

# @pytest.fixture
# def mock_software_updater():
#     with patch('panos.updater.SoftwareUpdater') as mock_updater:
#         # Create a mock Pandevice object and attach it to the mock_software_updater
#         mock_pandevice = Mock()
#         mock_pandevice.version = "9.0.5"  # Set a version for the mock Pandevice
#         mock_pandevice.id = "mock_device_id"  # Set a mock ID attribute

#         # Create a mock SoftwareUpdater instance
#         mock_software_updater_instance = mock_updater.return_value
#         mock_software_updater_instance.pandevice = mock_pandevice
#         mock_software_updater_instance.versions = firewall_versionlist_to_test

#         yield mock_software_updater_instance

# # Test the upgrade_to_version function
# def test_upgrade_to_version(mock_software_updater):
#     # Create a mock object for the PanOSVersion
#     mock_version = Mock(spec=PanOSVersion)

#     # Set up the expected behavior of the mock objects
#     mock_software_updater._next_minor_version.return_value = "9.1.0"  # Example next_minor_version

#     # Call the function you want to test
#     target_version = "9.1.0"  # Replace with your desired target version
#     software_updater = SoftwareUpdater(mock_software_updater)
#     software_updater.upgrade_to_version(target_version)

#     # Add your assertions here based on the expected behavior
#     # For example, check if the upgrade steps were called correctly
#     mock_software_updater._next_minor_version.assert_called_once_with(mock_version, firewall_versionlist_to_test)

#     # Add more assertions as needed
###################################################
###################################################


###################################################
###################################################
# def test_upgrade_to_next_version():
#     # Prep the firewall and example data
#     fw = _fw()
#     swUpdater = SoftwareUpdater(fw)
#     swUpdater.pandevice.version = "9.0.3"
#     swUpdater.versions = firewall_versionlist_to_test_dict

#     # Mock ContentUpdater and replace the check method
#     with patch('panos.updater.ContentUpdater', autospec=True) as mock_contentUpdater:
#         mock_contentUpdater_instance = mock_contentUpdater.return_value
#         mock_contentUpdater_instance.check.return_value = None  # Mock the ContentUpdater check method

#         # Mock SoftwareUpdater and replace the check method
#         with patch('panos.updater.SoftwareUpdater', autospec=True) as mock_softwareUpdater:
#             mock_softwareUpdater_instance = mock_softwareUpdater.return_value
#             mock_softwareUpdater_instance.check.return_value = None  # Mock the SoftwareUpdater check method

#             # Run the test
#             result = swUpdater.upgrade_to_version("9.1.0")
#             print(result)

#     # Dummy assertion whilst testing the rest of this function
#     assert True
###################################################
###################################################


###################################################
###################################################
# def test_upgrade_to_next_version():
#     mock_fw = Mock()
#     mock_fw.version = "9.0.3"
#     mock_fw.syncjob.return_value = {"success": True}
#     # mock_fw.syncreboot.return_value = PanOSVersion("9.1.0")
#     mock_fw.syncreboot.return_value = "9.1.0"
#     with patch.object(SoftwareUpdater, 'check') as mock_check:
#         # Set the return value of the check method to None, preventing it from executing
#         mock_check.return_value = None
#         swUpdater = SoftwareUpdater(mock_fw)
#         swUpdater.versions = firewall_versionlist_to_test_dict
#         result = swUpdater.upgrade_to_version("9.1.0")
#         print(result)
#     assert True
###################################################
###################################################

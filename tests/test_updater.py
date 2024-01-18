try:
    from unittest import mock
except ImportError:
    import mock

from panos import PanOSVersion
from panos.firewall import Firewall


def _fw(version):
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._set_version_and_version_info(version)
    return fw


def _updater_fw_setup(*args):
    fw = _fw()

    return fw


def versionStrToTuple(version_string):
    tokens = version_string.split(".")[:3]
    tokens[2] = tokens[2].split("-")[0]
    return tuple(int(x) for x in tokens)


def _create_mock_check(fw):
    patches = range(5)

    def mock_check():
        version_info = versionStrToTuple(fw.version)
        current_minor = ".".join(map(lambda x: str(x), version_info[0:-1]))
        if version_info[1] == 0:
            next_minor = ".".join([str(version_info[0]), "1"])
        else:
            next_minor = ".".join([str(version_info[0] + 1), "0"])
        versions = [".".join((str(current_minor), str(patch))) for patch in patches]
        versions += [".".join((str(next_minor), str(patch))) for patch in patches]
        fw.software.versions = {version: {"downloaded": False} for version in versions}

    return mock_check


def _create_mock_download_install_reboot(fw):
    def mock_download_install_reboot(next_version, sync):
        fw.version = str(next_version)
        return next_version

    return mock_download_install_reboot


def test_upgrade_to_version_with_install_base():
    fw = _fw("8.0.2")

    fw.software.check = mock.Mock(side_effect=_create_mock_check(fw))
    fw.software.download_install_reboot = mock.Mock(
        side_effect=_create_mock_download_install_reboot(fw)
    )
    fw.content.download_and_install_latest = mock.Mock()
    fw.software.download = mock.Mock()

    result = fw.software.upgrade_to_version("10.1.3")
    assert result == ["8.0.2", "8.1.0", "9.0.0", "9.1.0", "10.0.0", "10.1.0", "10.1.3"]


def test_upgrade_to_version_without_install_base():
    fw = _fw("8.0.2")

    fw.software.check = mock.Mock(side_effect=_create_mock_check(fw))
    fw.software.download_install_reboot = mock.Mock(
        side_effect=_create_mock_download_install_reboot(fw)
    )
    fw.content.download_and_install_latest = mock.Mock()
    fw.software.download = mock.Mock()

    result = fw.software.upgrade_to_version("10.1.3", install_base=False)
    assert result == ["8.0.2", "8.1.4", "9.0.4", "9.1.4", "10.0.4", "10.1.3"]


def test_next_upgrade_version_with_10_2_with_install_base():
    fw = _fw("10.1.3")
    fw.software.versions = {
        "10.1.0": "",
        "10.1.1": "",
        "10.1.2": "",
        "10.1.3": "",
        "10.1.4": "",
        "10.2.0": "",
        "10.2.1": "",
        "10.2.2": "",
        "10.2.3": "",
    }
    result = fw.software._next_upgrade_version("11.0.2", install_base=True)
    assert result == PanOSVersion("10.2.0")


def test_next_upgrade_version_with_10_2_without_install_base():
    fw = _fw("10.1.3")
    fw.software.versions = {
        "10.1.0": "",
        "10.1.1": "",
        "10.1.2": "",
        "10.1.3": "",
        "10.1.4": "",
        "10.2.0": "",
        "10.2.1": "",
        "10.2.2": "",
        "10.2.3": "",
    }
    result = fw.software._next_upgrade_version("11.0.2", install_base=False)
    assert result == PanOSVersion("10.2.3")

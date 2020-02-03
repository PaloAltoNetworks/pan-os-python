import pytest
import time

from tests.live import testlib
from pandevice import base


class TestUserID_FW(object):
    """Tests UserID on live Firewall."""

    def test_01_fw_login(self, fw, state_map):
        state = state_map.setdefault(fw)
        user, ip = testlib.random_name(), testlib.random_ip()
        fw.userid.login(user, ip)
        state.single_user = [user, ip]

    def test_02_fw_logins(self, fw, state_map):
        state = state_map.setdefault(fw)
        users = [(testlib.random_name(), testlib.random_ip()) for i in range(10)]
        fw.userid.logins(users)
        state.multi_user = users

    def test_03_fw_logout(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.single_user:
            raise Exception("User not logged in yet")
        user, ip = state.single_user
        fw.userid.logout(user, ip)

    def test_04_fw_logouts(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_user:
            raise Exception("User not logged in yet")
        fw.userid.logouts(state.multi_user)

    def test_05_register_str(self, fw, state_map):
        state = state_map.setdefault(fw)
        ip, tag = testlib.random_ip(), testlib.random_name()
        fw.userid.register(ip, tag)
        state.single_register = [ip, tag]

    def test_06_unregister_str(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.single_register:
            raise Exception("No single_register")
        ip, tag = state.single_register
        fw.userid.unregister(ip, tag)

    def test_07_register_lst(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips = [testlib.random_ip() for x in range(10)]
        tags = [testlib.random_name() for i in range(15)]
        fw.userid.register(ips, tags)
        state.multi_register_01 = [ips, tags]

    def test_08_get_registered_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_01:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_01
        test1 = set(fw.userid.get_registered_ip())
        assert test1 == set(ips)
        test2 = set(fw.userid.get_registered_ip(ips[0:3], tags))
        assert test2 == set(ips[0:3])
        test3 = set(fw.userid.get_registered_ip(ips[0:3], tags[0:5]))
        assert test3 == set(ips[0:3])
        test4 = set(fw.userid.get_registered_ip(ips, tags[0:5]))
        assert test4 == set(ips)
        test5 = set(fw.userid.get_registered_ip(ips[0], tags[0]))
        assert test5 == set([ips[0],])
        tests = [test1, test2, test3, test4, test5]
        assert len(test5) != 0
        assert all([test1 >= x for x in tests])
        assert all([x >= test5 for x in tests])
        assert test2 >= test3
        assert test4 >= test3

    def test_09_audit_registered_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        original = set(fw.userid.get_registered_ip())
        new_ips = [testlib.random_ip() for x in range(5)]
        new_tags = [testlib.random_name() for i in range(8)]
        ip_tags_pairs = dict([(ip, tuple(new_tags)) for ip in new_ips])
        fw.userid.audit_registered_ip(ip_tags_pairs)
        state.multi_register_02 = [new_ips, new_tags]
        new_set = set(fw.userid.get_registered_ip())
        assert len(new_set) < len(original)
        assert new_set == set(new_ips)

    def test_10_clear_registered_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_02:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_02
        original = list(fw.userid.get_registered_ip())
        fw.userid.clear_registered_ip(ips[0], tags[0])
        mod1 = list(fw.userid.get_registered_ip())
        fw.userid.clear_registered_ip(ips[0:4], tags[0:5])
        mod2 = list(fw.userid.get_registered_ip())
        fw.userid.clear_registered_ip(ips[0:4], tags)
        mod3 = list(fw.userid.get_registered_ip())
        fw.userid.clear_registered_ip(ips, tags[0:7])
        mod4 = list(fw.userid.get_registered_ip())
        fw.userid.clear_registered_ip()
        mod5 = list(fw.userid.get_registered_ip())
        assert len(mod3) < len(mod2)
        assert len(mod3) < len(mod1)
        assert len(mod3) < len(original)
        assert len(mod5) == 0

    def test_11_batch(self, fw, state_map):
        fw.userid.clear_registered_ip()  # Fresh start
        fw.userid.batch_start()
        users = [(testlib.random_name(), testlib.random_ip()) for i in range(5)]
        fw.userid.logins(users)
        ips = [testlib.random_ip() for x in range(5)]
        tags = [testlib.random_name() for y in range(5)]
        fw.userid.register(ips, tags)
        fw.userid.unregister(ips[2], tags[4])
        fw.userid.get_registered_ip(ips[0:3], tags[2:4])
        new_ips = [testlib.random_ip() for x in range(3)]
        new_tags = [testlib.random_name() for y in range(3)]
        fw.userid.audit_registered_ip(dict([(ip, tuple(new_tags)) for ip in new_ips]))
        fw.userid.get_registered_ip()
        fw.userid.unregister(new_ips, new_tags)
        fw.userid.batch_end()

    def test_12_uidmessage(self, fw, state_map):
        state = state_map.setdefault(fw)
        state.uid = fw.userid._create_uidmessage()

    def test_13_send(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.uid:
            raise Exception("No UID")
        fw.userid.send(
            state.uid[0]
        )  # State.uid returns length-two tuple of XML elements

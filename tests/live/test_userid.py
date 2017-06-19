import pytest
import time
import random

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
        fw.userid.clear_registered_ip()
        state = state_map.setdefault(fw)
        ip, tag = testlib.random_ip(), testlib.random_name()
        fw.userid.register(ip, tag)
        state.single_register = [ip, tag]

    def test_06_unregister_str(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.single_register:
            raise Exception("No single_register")
        ip, tag = state.single_register
        fw.userid.unregister(ip, (tag, "aaaaaaa"))
        assert fw.userid.get_registered_ip() == {}

    def test_07_error(self, fw):
        fw.userid.clear_registered_ip()
        ips = [testlib.random_ip() for x in range(10)]
        tags = [testlib.random_name() for i in range(10)]
        fw.userid.register(ips, tags)
        fw.userid.unregister(ips, tags[9])
        original = fw.userid.get_registered_ip()
        new_tags = tags[0:9]
        new_tags.append("aaaaaa")
        fw.userid.unregister(ips[0], new_tags)
        mod1 = fw.userid.get_registered_ip()
        assert len(original.keys()) == len(mod1.keys()) + 1

    def test_08_register_lst(self, fw, state_map):
        fw.userid.clear_registered_ip()
        state = state_map.setdefault(fw)
        ips = [testlib.random_ip() for x in range(10)]
        tags = [testlib.random_name() for i in range(15)]
        fw.userid.register(ips, tags)
        state.multi_register_01 = [ips, tags]

    def test_09a_get_registered_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_01:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_01
        get1 = fw.userid.get_registered_ip()
        state.get1 = get1
        assert set(get1) == set(ips)
        for x in ips:
            assert set(get1[x]) == set(tags)

    def test09b_get_registered_subset_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_01:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_01
        get2 = fw.userid.get_registered_ip(
                    ips[0:3], tags
        )
        state.get2 = get2
        assert set(get2) == set(ips[0:3])
        for i in ips[0:3]:
            assert set(get2[i]) == set(tags)

    def test09c_get_registered_subset_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_01:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_01
        get3 = fw.userid.get_registered_ip(
                    ips[0:3], tags[0:5]
        )
        state.get3 = get3
        assert set(get3) == set(ips[0:3])
        for i in ips[0:3]:
            assert set(get3[i]) == set(tags[0:5])

    def test_09d_get_registered_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_01:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_01
        get4 = fw.userid.get_registered_ip(
                    ips, tags[0:5]
        )
        state.get4 = get4
        assert set(get4) == set(ips)
        for x in ips:
            assert set(get4[x]) == set(tags[0:5])

    def test_09e_get_registered_single_ip_single_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_01:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_01
        get5 = fw.userid.get_registered_ip(ips[0], tags[0])
        state.get5 = get5
        assert list(get5.keys()) == [ips[0], ]
        assert get5[ips[0]] == [tags[0], ]
        gets = [state.get1, state.get2, state.get3, state.get4, state.get5]
        assert len(get5) != 0
        assert all([set(state.get1) >= set(x) for x in gets])
        assert all([set(x) >= set(get5) for x in gets])
        assert set(state.get2) >= set(state.get3)
        assert set(state.get4) >= set(state.get3)

    def test_10_audit_registered_ip(self, fw, state_map):
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

    def test_11a_clear_registered_single_ip_single_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_02:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_02
        state.original = list(fw.userid.get_registered_ip())
        fw.userid.clear_registered_ip(ips[0], tags[0])
        state.clear1 = fw.userid.get_registered_ip()
        assert tags[0] not in state.clear1[ips[0]]

    def test_11b_clear_registered_subset_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_02:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_02
        fw.userid.clear_registered_ip(ips[0:4], tags[0:5])
        state.clear2 = fw.userid.get_registered_ip()
        assert all([all([tag not in state.clear2[ip] for tag in tags[0:5]]) for ip in ips[0:4]])

    def test_11c_clear_registered_subset_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_02:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_02
        fw.userid.clear_registered_ip(ips[0:4], tags)
        state.clear3 = fw.userid.get_registered_ip()
        assert set(state.original) - set(state.clear3) == set(ips[0:4])

    def test_11d_clear_registered_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.multi_register_02:
            raise Exception("Multi register not set")
        ips, tags = state.multi_register_02
        fw.userid.clear_registered_ip(ips, tags[0:7])
        state.clear4 = fw.userid.get_registered_ip()
        assert all(all([tag not in state.clear4[ip] for tag in tags[0:7]]) for ip in ips[4:])

    def test_11e_clear_registered_ip(self, fw, state_map):
        fw.userid.clear_registered_ip()
        clear5 = fw.userid.get_registered_ip()
        assert len(clear5) == 0

    def test_11f_clear_registered_ip_sanity(self, fw, state_map):
        state = state_map.setdefault(fw)
        assert set(state.clear3) < set(state.clear2)
        assert set(state.clear3) < set(state.clear1)
        assert set(state.clear3) < set(state.original)

    def test_12_batch(self, fw):
        fw.userid.clear_registered_ip()
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

    def test_13_uidmessage(self, fw, state_map):
        state = state_map.setdefault(fw)
        state.uid = fw.userid._create_uidmessage()

    def test_14_send(self, fw, state_map):
        state = state_map.setdefault(fw)
        if not state.uid:
            raise Exception("No UID")
        fw.userid.send(state.uid[0]) #State.uid returns length-two tuple of XML elements

    def test_15_unregister_lst_setup(self, fw, state_map):
        fw.userid.clear_registered_ip()
        state = state_map.setdefault(fw)
        state.ips = [testlib.random_ip() for x in range(10)]
        state.tags = [testlib.random_name() for y in range(10)]
        fw.userid.register(state.ips, state.tags)
        state.original = fw.userid.get_registered_ip()

    def test_15a_unregister_single_ip_single_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.unregister(ips[0], tags[0])
        unreg1 = fw.userid.get_registered_ip()
        assert state.original.keys() == unreg1.keys()
        assert len(state.original[ips[0]]) == len(unreg1[ips[0]]) + 1
        assert set(state.original[ips[0]]) - set(unreg1[ips[0]]) == set([tags[0], ])

    def test_15b_unregister_single_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.unregister(ips[1], tags[2:5])
        unreg2 = fw.userid.get_registered_ip()
        assert state.original.keys() == unreg2.keys()
        assert len(state.original[ips[1]]) == len(unreg2[ips[1]]) + 3
        assert set(state.original[ips[1]]) - set(unreg2[ips[1]]) == set(tags[2:5])

    def test_15c_unregister_subset_ip_single_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.unregister(ips[2:4], tags[2])
        unreg3 = fw.userid.get_registered_ip()
        assert state.original.keys() == unreg3.keys()
        assert all([len(state.original[ip]) == len(unreg3[ip]) + 1 for ip in ips[2:4]])
        assert all([set(state.original[ip]) - set(unreg3[ip]) == set([tags[2], ]) for ip in ips[2:4]])

    def test_15d_unregister_subset_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.unregister(ips[4:6], tags[3:5])
        unreg4 = fw.userid.get_registered_ip()
        state.unreg4 = unreg4
        assert state.original.keys() == unreg4.keys()
        assert all([set(state.original[ip]) - set(unreg4[ip]) == set(tags[3:5]) for ip in ips[4:6]])

    def test_15e_unregister_ip_single_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.unregister(ips, tags[9])
        unreg5 = fw.userid.get_registered_ip()
        assert state.original.keys() == unreg5.keys()
        assert all([set(state.unreg4[ip]) - set(unreg5[ip]) == set([tags[9], ]) for ip in ips])

    def test_15f_unregister_single_ip_all_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.unregister(ips[8], tags)
        unreg6 = fw.userid.get_registered_ip()
        state.unreg6 = unreg6
        assert set(state.original.keys()) > set(unreg6.keys())
        assert set(state.original.keys()) - set(unreg6.keys()) == set([ips[8], ])

    def test_15g_unregister_ip_subset_tag(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        new_ips = list(state.unreg6.keys())
        fw.userid.unregister(new_ips, tags[5:7])
        unreg7 = fw.userid.get_registered_ip()
        assert set(new_ips) == unreg7.keys()
        assert all([set(state.unreg6[ip]) - set(unreg7[ip]) == set(tags[5:7]) for ip in new_ips])

    def test_15h_unregister_ip(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.clear_registered_ip()
        fw.userid.register(ips, tags)
        fw.userid.unregister(ips[0:5], tags)
        unreg8 = fw.userid.get_registered_ip()
        assert set(state.original.keys()) > set(unreg8.keys())
        assert set(state.original.keys()) - set(unreg8.keys()) == set(ips[0:5])

    def test_15i_unregister_sanity(self, fw, state_map):
        state = state_map.setdefault(fw)
        ips, tags = state.ips, state.tags
        fw.userid.clear_registered_ip()
        fw.userid.register(ips, tags)
        fw.userid.unregister(ips, tags)
        empty = fw.userid.get_registered_ip()
        assert empty == {}

    def test_16a_unregister_single_ip_extra_tag(self, fw):
        fw.userid.clear_registered_ip()
        fw.userid.register("5.5.5.5", "hello")
        fw.userid.unregister("5.5.5.5", ("hello", "apple"))
        result = fw.userid.get_registered_ip()
        assert result == {}

    def test_16b_unregister_multi_ip_multi_extra_tag(self, fw):
        fw.userid.clear_registered_ip()
        fw.userid.register(["1.2.3.4", "5.5.5.5"], "hello")
        fw.userid.register("5.5.5.5", "bye")
        fw.userid.unregister(["1.2.3.4", "5.5.5.5"], ["hello", "bye", "apple", "arty"])
        assert fw.userid.get_registered_ip() == {}

    def test_16c_unregister_single_ip_redundant_tag(self, fw):
        fw.userid.clear_registered_ip()
        fw.userid.register("1.2.3.4", ["hello", "apple", "bye"])
        fw.userid.unregister("1.2.3.4", "hello")
        fw.userid.unregister("1.2.3.4", "hello")
        result = fw.userid.get_registered_ip()
        assert set(result["1.2.3.4"]) == set(["apple", "bye"])

    def test_16d_unregister_no_valid_tag(self, fw):
        fw.userid.clear_registered_ip()
        fw.userid.register("8.8.8.8", ["peanut"])
        fw.userid.unregister("1.2.3.4", ["apple", "goodbye"])
        assert fw.userid.get_registered_ip() == {"8.8.8.8": ["peanut"]}

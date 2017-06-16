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

    def test_03_looper(self, fw, state_map):
        fw.userid.clear_registered_ip()
        ips = [testlib.random_ip() for x in range(10)]
        tags = [testlib.random_name() for x in range(10)]
        tag_set = set(tags)
        one_ip = random.choice(ips)

        print(ips)
        print(tags)
        assert len(fw.userid.get_registered_ip()) == 0

        for num in range(1, 6):
            print('Loop {0}...'.format(num))

            # Register stuff
            fw.userid.register(ips, tags)
            ans = fw.userid.get_registered_ip()
            for ip in ips:
                assert ip in ans
                assert set(ans[ip]) == set(tag_set)

            # Unregister one at random
            fw.userid.unregister(ips, random.choice(tags))
            ans = fw.userid.get_registered_ip()
            assert len(ans[one_ip]) == 9

            # Unregister one more at random
            fw.userid.unregister(ips, random.choice(tags))
            ans = fw.userid.get_registered_ip()
            assert len(ans[one_ip]) in (8, 9)

            # Unregister everything, which includes already deleted things
            fw.userid.unregister(ips, tags)
            ans = fw.userid.get_registered_ip()
            assert ans == {}

    def test_07_register_lst(self, fw, state_map):
        fw.userid.clear_registered_ip()
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
        test2 = set(fw.userid.get_registered_ip(
                    ips[0:3], tags
        ))
        assert test2 == set(ips[0:3])
        test3 = set(fw.userid.get_registered_ip(
                    ips[0:3], tags[0:5]
        ))
        assert test3 == set(ips[0:3])
        test4 = set(fw.userid.get_registered_ip(
                    ips, tags[0:5]
        ))
        assert test4 == set(ips)
        test5 = set(fw.userid.get_registered_ip(ips[0], tags[0]))
        assert test5 == set([ips[0], ])
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
        mod1 = fw.userid.get_registered_ip()
        assert tags[0] not in mod1[ips[0]]
        fw.userid.clear_registered_ip(ips[0:4], tags[0:5])
        mod2 = fw.userid.get_registered_ip()
        #assert all([all([tag not in mod2[ip] for tag in tags[0:5]) for ip in ips[0:4]])
        fw.userid.clear_registered_ip(ips[0:4], tags)
        mod3 = fw.userid.get_registered_ip()
        fw.userid.clear_registered_ip(ips, tags[0:7])
        mod4 = fw.userid.get_registered_ip()
        #assert
        fw.userid.clear_registered_ip()
        mod5 = fw.userid.get_registered_ip()
        assert set(mod3) < set(mod2)
        assert set(mod3) < set(mod1)
        assert set(mod3) < set(original)
        assert len(mod5) == 0

    def test_11_batch(self, fw):
        fw.userid.clear_registered_ip() #Fresh start
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
        fw.userid.send(state.uid[0]) #State.uid returns length-two tuple of XML elements

    def test_14_unregister_lst(self, fw):
        fw.userid.clear_registered_ip()
        ips = [testlib.random_ip() for x in range(10)]
        tags = [testlib.random_name() for y in range(10)]
        fw.userid.register(ips, tags)
        original = fw.userid.get_registered_ip()

        fw.userid.unregister(ips[0], tags[0])
        mod1 = fw.userid.get_registered_ip()
        assert original.keys() == mod1.keys()
        assert len(original[ips[0]]) == len(mod1[ips[0]]) + 1
        assert set(original[ips[0]]) - set(mod1[ips[0]]) == set([tags[0], ])

        fw.userid.unregister(ips[1], tags[2:5])
        mod2 = fw.userid.get_registered_ip()
        assert original.keys() == mod2.keys()
        assert len(original[ips[1]]) == len(mod2[ips[1]]) + 3
        assert set(original[ips[1]]) - set(mod2[ips[1]]) == set(tags[2:5])

        fw.userid.unregister(ips[2:4], tags[2])
        mod3 = fw.userid.get_registered_ip()
        assert original.keys() == mod3.keys()
        assert all([len(original[ip]) == len(mod3[ip]) + 1 for ip in ips[2:4]])
        assert all([set(original[ip]) - set(mod3[ip]) == set([tags[2], ]) for ip in ips[2:4]])

        fw.userid.unregister(ips[4:6], tags[3:5])
        mod4 = fw.userid.get_registered_ip()
        assert original.keys() == mod4.keys()
        assert all([set(original[ip]) - set(mod4[ip]) == set(tags[3:5]) for ip in ips[4:6]])

        fw.userid.unregister(ips, tags[9])
        mod5 = fw.userid.get_registered_ip()
        assert original.keys() == mod5.keys()
        assert all([set(mod4[ip]) - set(mod5[ip]) == set([tags[9], ]) for ip in ips])

        fw.userid.unregister(ips[8], tags[0:9])
        mod6 = fw.userid.get_registered_ip()
        assert set(original.keys()) > set(mod6.keys())
        assert set(original.keys()) - set(mod6.keys()) == set([ips[8], ])

        new_ips = list(mod6.keys())
        fw.userid.unregister(new_ips, tags[5:7])
        mod7 = fw.userid.get_registered_ip()
        assert mod6.keys() == mod7.keys()
        assert all([set(mod6[ip]) - set(mod7[ip]) == set(tags[5:7]) for ip in new_ips])

        fw.userid.clear_registered_ip()
        fw.userid.register(ips, tags)
        fw.userid.unregister(ips[0:5], tags)
        mod8 = fw.userid.get_registered_ip()
        assert set(original.keys()) > set(mod8.keys())
        assert set(original.keys()) - set(mod8.keys()) == set(ips[0:5])

        fw.userid.clear_registered_ip()
        fw.userid.register(ips, tags)
        fw.userid.unregister(ips, tags)
        empty = fw.userid.get_registered_ip()
        assert empty == {}

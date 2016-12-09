import mock
import unittest
import xml.etree.ElementTree as ET

import pandevice.base
import pandevice.network
import pandevice.objects
import pandevice.policies


class TestObject(unittest.TestCase):
    OLD_CLS = None
    NEW_CLS = None
    PARAMS = ()

    def setUp(self):
        if self.OLD_CLS is None:
            raise unittest.SkipTest('OLD_CLS not defined')
        elif self.NEW_CLS is None:
            raise unittest.SkipTest('NEW_CLS not defined')

    def test_empty_objects_are_equal(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(
            old.element_str(),
            new.element_str(),
        )

    def test_positionally_populated_objects_are_equal(self):
        args = tuple(y for x, y in self.PARAMS)
        new = self.NEW_CLS('jack', *args)
        old = self.OLD_CLS('jack', *args)

        self.assertEqual(
            old.element_str(),
            new.element_str(),
        )

    def test_keyword_populated_objects_are_equal(self):
        kwargs = dict(self.PARAMS)
        old = self.OLD_CLS('burton', **kwargs)
        new = self.NEW_CLS('burton', **kwargs)

        self.assertEqual(
            old.element_str(),
            new.element_str(),
        )

    def test_parsing_old_elmstring_works(self):
        kwargs = dict(self.PARAMS)
        old = self.OLD_CLS('myuid', **kwargs)
        new = self.NEW_CLS()

        new.parse_xml(old.element())

        if old.SUFFIX == pandevice.base.ENTRY:
            self.assertEqual(old.uid, new.uid)

        for key, value in self.PARAMS:
            self.assertEqual(
                getattr(old, key),
                getattr(new, key),
            )

    def test_root_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.ROOT, new.ROOT)

    def test_class_xpath_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.XPATH, new.XPATH)

    def test_suffix_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.SUFFIX, new.SUFFIX)

    def test_childtypes_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.CHILDTYPES, new.CHILDTYPES)

    def test_childmethods_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.CHILDMETHODS, new.CHILDMETHODS)

    def test_ha_sync_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.HA_SYNC, new.HA_SYNC)

    def test_name_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.NAME, new.NAME)

    def test_xpath_function_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.xpath(), new.xpath())

    def test_xpath_short_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')

        self.assertEqual(old.xpath_short(), new.xpath_short())


class TestVersionedObject(unittest.TestCase):
    MASKED_VALUE = 'old default'
    DEFAULT_VALUE = 'new default'
    MIDDLE_VALUE = '6.1 profile'
    NEWEST_VALUE = '7.0 profile'

    def setUp(self):
        self.obj = pandevice.base.VersioningSupport()
        self.obj.add_profile('1.0.0', self.MASKED_VALUE)
        self.obj.add_profile('1.0.0', self.DEFAULT_VALUE)
        self.obj.add_profile('6.1.0', self.MIDDLE_VALUE)
        self.obj.add_profile('7.0.0', self.NEWEST_VALUE)

    def _check(self, version, expected):
        result = self.obj._get_versioned_value(version)

        self.assertEqual(expected, result)

    def test__get_versioned_value_on_higher_panos_version_gets_newest_value(self):
        self._check((8, 0, 0), self.NEWEST_VALUE)

    def test__get_versioned_value_on_lower_panos_version_gets_oldest_value(self):
        self._check((0, 0, 0), self.MASKED_VALUE)

    def test__get_versioned_value_for_exact_panos_version_match(self):
        self._check((6, 1, 0), self.MIDDLE_VALUE)

    def test__get_versioned_value_for_inbetween_panos_version(self):
        self._check((6, 5, 0), self.MIDDLE_VALUE)

    def test__get_versioned_value_gets_newer_value_with_multiple_exact_version_profiles(self):
        self._check((1, 0, 0), self.DEFAULT_VALUE)

    def test_add_profile_raises_error_on_adding_lower_version_after_adding_a_higher_version(self):
        self.assertRaises(
            ValueError,
            self.obj.add_profile, '5.5.5', 'foo')

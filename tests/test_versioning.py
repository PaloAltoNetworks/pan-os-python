try:
    from unittest import mock
except ImportError:
    import mock
import unittest
import xml.etree.ElementTree as ET

import pandevice.base
import pandevice.device
import pandevice.ha
import pandevice.network
import pandevice.objects
import pandevice.policies


class TestObject(unittest.TestCase):
    OLD_CLS = None
    NEW_CLS = None
    # This is a tuple of two-element tuples.
    PARAMS = ()

    def setUp(self):
        if self.OLD_CLS is None:
            raise unittest.SkipTest('OLD_CLS not defined')
        elif self.NEW_CLS is None:
            raise unittest.SkipTest('NEW_CLS not defined')

    def test_empty_objects_are_equal(self):
        if self.OLD_CLS.SUFFIX is not None:
            old = self.OLD_CLS('foo')
            new = self.NEW_CLS('foo')
        else:
            old = self.OLD_CLS()
            new = self.NEW_CLS()

        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'element_str'):
            raise unittest.SkipTest('OLD_CLS does not have element_str()')

        self.assertEqual(
            old.element_str(),
            new.element_str(),
        )

    def test_positionally_populated_objects_are_equal(self):
        args = tuple(y for x, y in self.PARAMS)
        if self.OLD_CLS.NAME is not None:
            new = self.NEW_CLS('jack', *args)
            old = self.OLD_CLS('jack', *args)
        else:
            new = self.NEW_CLS(*args)
            old = self.OLD_CLS(*args)
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'element_str'):
            raise unittest.SkipTest('OLD_CLS does not have element_str()')

        self.assertEqual(
            old.element_str(),
            new.element_str(),
        )

    def test_keyword_populated_objects_are_equal(self):
        kwargs = dict(self.PARAMS)
        if self.OLD_CLS.NAME is not None:
            old = self.OLD_CLS('burton', **kwargs)
            new = self.NEW_CLS('burton', **kwargs)
        else:
            old = self.OLD_CLS(**kwargs)
            new = self.NEW_CLS(**kwargs)
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'element_str'):
            raise unittest.SkipTest('OLD_CLS does not have element_str()')

        self.assertEqual(
            old.element_str(),
            new.element_str(),
        )

    def test_parsing_old_elmstring_works(self):
        kwargs = dict(self.PARAMS)
        if self.OLD_CLS.NAME is not None:
            old = self.OLD_CLS('myuid', **kwargs)
            orig = self.OLD_CLS('blah')
            new = self.NEW_CLS('blah')
        else:
            old = self.OLD_CLS(**kwargs)
            orig = self.OLD_CLS()
            new = self.NEW_CLS()
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'element'):
            raise unittest.SkipTest('OLD_CLS does not have element()')

        # We make a fresh OLD_CLS from an instantiated OLD_CLS first because
        # if there are conditional variables, they should not show up
        # in NEW_CLS, but would be in OLD_CLS.
        orig.refresh(xml=old.element())
        new.parse_xml(orig.element())

        if orig.SUFFIX == pandevice.base.ENTRY:
            self.assertEqual(orig.uid, new.uid)

        if orig.element_str() != new.element_str():
            for key, value in self.PARAMS:
                self.assertEqual(
                    getattr(orig, key),
                    getattr(new, key),
                    'Key({0}) orig({1}) vs new({2})'.format(
                        key,
                        getattr(orig, key),
                        getattr(new, key)),
                )

    def test_root_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'ROOT'):
            raise unittest.SkipTest('OLD_CLS does not have ROOT')

        self.assertEqual(old.ROOT, new.ROOT)

    def test_class_xpath_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'XPATH'):
            raise unittest.SkipTest('OLD_CLS does not have XPATH')

        self.assertEqual(old.XPATH, new.XPATH)

    def test_suffix_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'SUFFIX'):
            raise unittest.SkipTest('OLD_CLS does not have SUFFIX')

        self.assertEqual(old.SUFFIX, new.SUFFIX)

    def test_childtypes_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'CHILDTYPES'):
            raise unittest.SkipTest('OLD_CLS does not have CHILDTYPES')

        for x in old.CHILDTYPES:
            self.assertTrue(x in new.CHILDTYPES,
                            'CHILDTYPE {0} missing'.format(x))

    def test_childmethods_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'CHILDMETHODS'):
            raise unittest.SkipTest('OLD_CLS does not have CHILDMETHODS')

        for x in old.CHILDMETHODS:
            self.assertTrue(x in new.CHILDMETHODS)

    def test_ha_sync_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'HA_SYNC'):
            raise unittest.SkipTest('OLD_CLS does not have HA_SYNC')

        self.assertEqual(old.HA_SYNC, new.HA_SYNC)

    def test_name_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'NAME'):
            raise unittest.SkipTest('OLD_CLS does not have NAME')

        self.assertEqual(old.NAME, new.NAME)

    def test_xpath_function_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'xpath'):
            raise unittest.SkipTest('OLD_CLS does not have xpath()')

        self.assertEqual(old.xpath(), new.xpath())

    def test_xpath_short_is_same(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        if not hasattr(old, 'xpath_short'):
            raise unittest.SkipTest('OLD_CLS does not have xpath_short()')

        self.assertEqual(old.xpath_short(), new.xpath_short())

    def test_xpath_import_is_same(self):
        if not hasattr(self.OLD_CLS, 'XPATH_IMPORT'):
            raise unittest.SkipTest('No XPATH_IMPORT for this class')

        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        self.assertEqual(old.XPATH_IMPORT, new.XPATH_IMPORT)

    def test_has_the_same_functions(self):
        old = self.OLD_CLS('foo')
        new = self.NEW_CLS('foo')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        ignore_functions = (
            'variables',
            '_variables',
            'vars_with_mode',
        )
        funcs = [x for x in dir(old) if callable(getattr(old, x))
                 and x not in ignore_functions]
        for x in funcs:
            self.assertTrue(hasattr(new, x) and callable(getattr(new, x)),
                            'NEW_CLS missing function {0}'.format(x))

    def test_access_to_set_vlan_function(self):
        old = self.OLD_CLS('jack')
        new = self.NEW_CLS('jack')
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        new._set_reference = mock.Mock(return_value='foo')

        if hasattr(old, 'set_vlan'):
            ret_val = new.set_vlan('burton')

            self.assertEqual('foo', ret_val)
            self.assertEqual(1, new._set_reference.call_count)
        else:
            with self.assertRaises(AttributeError):
                new.set_vlan('burton')

    def test_empty_name_is_equal(self):
        try:
            old = self.OLD_CLS()
        except TypeError:
            raise unittest.SkipTest('Cannot create empty class of this type')

        new = self.NEW_CLS()
        new.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        self.assertEqual(old.uid, new.uid)


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

if __name__=='__main__':
    unittest.main()

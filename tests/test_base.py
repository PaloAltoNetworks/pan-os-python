# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import mock
import unittest
import uuid

import pan.xapi
import pandevice.base as Base
import pandevice.errors as Err


OBJECT_NAME = 'MyObjectName'
VSYS = 'vsys1'


class TestPanObject(unittest.TestCase):
    def setUp(self):
        self.obj = Base.PanObject(OBJECT_NAME)

    def verify_object(self, obj, **kwargs):
        self.assertEqual(
            kwargs.get('name', None),
            obj.name)
        self.assertEqual(
            kwargs.get('children', []),
            obj.children)
        self.assertEqual(
            kwargs.get('parent', None),
            obj.parent)

    def test_create_with_name(self):
        self.obj = Base.PanObject(OBJECT_NAME)

        self.verify_object(self.obj, name=OBJECT_NAME)

    def test_create_without_name(self):
        self.obj = Base.PanObject()

        self.verify_object(self.obj)

    def test_str_of_object_with_name(self):
        self.assertEqual(OBJECT_NAME, str(self.obj))

    def test_str_of_object_without_name(self):
        self.obj = Base.PanObject()

        self.assertEqual('None', str(self.obj))

    def test_has_callable_variables(self):
        self.assertTrue(callable(self.obj.variables))

    def test_property_vsys_without_parent(self):
        self.assertIsNone(self.obj.vsys)

    def test_property_vsys_with_parent(self):
        self.obj.parent = mock.Mock(vsys=VSYS)

        self.assertEqual(VSYS, self.obj.vsys)

    def test_property_vsys_raises_error(self):
        self.assertRaises(
            Err.PanDeviceError,
            setattr,
            self.obj, 'vsys', 'foo')

    def test_property_uid(self):
        expected = OBJECT_NAME

        ret_val = self.obj.uid

        self.assertEqual(expected, ret_val)

    def test_add_without_children(self):
        CHILD_NAME = 'child'
        child = Base.PanObject(CHILD_NAME)

        ret_value = self.obj.add(child)

        self.assertEqual(child, ret_value)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=[child, ])
        self.verify_object(
            child,
            name=CHILD_NAME,
            parent=self.obj)

    def test_add_with_children(self):
        CHILD1_NAME = 'FirstChild'
        child1 = Base.PanObject(CHILD1_NAME)
        child1.parent = self.obj

        self.obj.children = [child1, ]

        CHILD2_NAME = 'SecondChild'
        child2 = Base.PanObject(CHILD2_NAME)

        ret_val = self.obj.add(child2)

        self.assertEqual(child2, ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=[child1, child2])
        self.verify_object(
            child1,
            name=CHILD1_NAME,
            parent=self.obj)
        self.verify_object(
            child2,
            name=CHILD2_NAME,
            parent=self.obj)

    def test_insert_without_children(self):
        CHILD_NAME = 'Child'
        child = Base.PanObject(CHILD_NAME)

        ret_val = self.obj.insert(0, child)

        self.assertEqual(child, ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=[child, ])
        self.verify_object(
            child,
            name=CHILD_NAME,
            parent=self.obj)

    def test_insert_with_children(self):
        CHILD1_NAME = 'FirstChild'
        child1 = Base.PanObject(CHILD1_NAME)
        child1.parent = self.obj

        CHILD3_NAME = 'ThirdChild'
        child3 = Base.PanObject(CHILD3_NAME)
        child3.parent = self.obj

        self.obj.children = [child1, child3]

        CHILD2_NAME = 'SecondChild'
        child2 = Base.PanObject(CHILD2_NAME)

        ret_val = self.obj.insert(1, child2)

        self.assertEqual(child2, ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=[child1, child2, child3])
        self.verify_object(
            child1,
            name=CHILD1_NAME,
            parent=self.obj)
        self.verify_object(
            child2,
            name=CHILD2_NAME,
            parent=self.obj)
        self.verify_object(
            child3,
            name=CHILD3_NAME,
            parent=self.obj)

    def test_extend_without_children(self):
        CHILD1_NAME = 'FirstChild'
        child1 = Base.PanObject(CHILD1_NAME)

        CHILD2_NAME = 'SecondChild'
        child2 = Base.PanObject(CHILD2_NAME)

        children = [child1, child2]

        ret_val = self.obj.extend(children)

        self.assertIsNone(ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=children)
        self.verify_object(
            child1,
            name=CHILD1_NAME,
            parent=self.obj)
        self.verify_object(
            child2,
            name=CHILD2_NAME,
            parent=self.obj)

    def test_extend_with_children(self):
        CHILD1_NAME = 'FirstChild'
        child1 = Base.PanObject(CHILD1_NAME)
        child1.parent = self.obj

        self.obj.children = [child1, ]

        CHILD2_NAME = 'SecondChild'
        child2 = Base.PanObject(CHILD2_NAME)

        CHILD3_NAME = 'ThirdChild'
        child3 = Base.PanObject(CHILD3_NAME)

        new_children = [child2, child3]
        all_children = [child1, child2, child3]

        ret_val = self.obj.extend(new_children)

        self.assertIsNone(ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=all_children)
        self.verify_object(
            child1,
            name=CHILD1_NAME,
            parent=self.obj)
        self.verify_object(
            child2,
            name=CHILD2_NAME,
            parent=self.obj)
        self.verify_object(
            child3,
            name=CHILD3_NAME,
            parent=self.obj)

    def test_pop(self):
        CHILD_NAME = 'Child'
        child = Base.PanObject(CHILD_NAME)
        child.parent = self.obj

        self.obj.children = [child, ]

        ret_val = self.obj.pop(0)

        self.assertEqual(child, ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME)
        self.verify_object(
            child,
            name=CHILD_NAME)

    def test_pop_raises_error(self):
        '''An invalid index should raise IndexError.'''
        self.assertRaises(
            IndexError,
            self.obj.pop, 0)

    def test_remove(self):
        CHILD1_NAME = 'Child1'
        child1 = Base.PanObject(CHILD1_NAME)
        child1.parent = self.obj

        CHILD2_NAME = 'Child2'
        child2 = Base.PanObject(CHILD2_NAME)
        child2.parent = self.obj

        self.obj.children = [child1, child2]

        ret_val = self.obj.remove(child2)

        self.assertIsNone(ret_val)
        self.verify_object(
            self.obj,
            name=OBJECT_NAME,
            children=[child1, ])
        self.verify_object(
            child1,
            name=CHILD1_NAME,
            parent=self.obj)
        self.verify_object(
            child2,
            name=CHILD2_NAME)

    def test_remove_raises_error(self):
        '''An invalid child should raise ValueError.'''
        CHILD1_NAME = 'Child1'
        child1 = Base.PanObject(CHILD1_NAME)
        child1.parent = self.obj

        CHILD2_NAME = 'Child2'
        child2 = Base.PanObject(CHILD2_NAME)

        self.obj.children = [child1, ]

        self.assertRaises(
            ValueError,
            self.obj.remove, child2)

    def test_remove_by_name_when_find_returns_index(self):
        CHILD_NAME = 'MyChild'
        self.obj.children = [1, 2, 3]

        INDEX_VALUE = 4
        self.obj.find_index = mock.Mock(return_value=INDEX_VALUE)

        POP_RETURN_VALUE = 'foo'
        self.obj.pop = mock.Mock(return_value=POP_RETURN_VALUE)

        ret_val = self.obj.remove_by_name(CHILD_NAME, None)

        self.assertEqual(POP_RETURN_VALUE, ret_val)
        self.obj.find_index.assert_called_once_with(CHILD_NAME, None)
        self.obj.pop.assert_called_once_with(INDEX_VALUE)

    def test_remove_by_name_when_find_returns_none(self):
        CHILD_NAME = 'foo'
        self.obj.children = ['a', 'b', 'c']

        self.obj.find_index = mock.Mock(return_value=None)

        ret_val = self.obj.remove_by_name(CHILD_NAME, None)

        self.assertIsNone(ret_val)
        self.obj.find_index.assert_called_once_with(CHILD_NAME, None)

    # Skipping removeall

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_xpath_with_entry_suffix(self, m_uid):
        Uid = 'baz'
        ParentValue = '/foo'
        SelfXpath = '/bar'
        Suffix = Base.ENTRY
        expected = ParentValue + SelfXpath + Base.ENTRY % (Uid, )

        m_uid.return_value = Uid
        self.obj._parent_xpath = mock.Mock(
            return_value=ParentValue)
        self.obj.XPATH = SelfXpath
        self.obj.SUFFIX = Suffix

        ret_val = self.obj.xpath()

        self.assertEqual(expected, ret_val)
        self.obj._parent_xpath.assert_called_once_with()

    # Skipping xpath_nosuffix

    # Skipping xpath_short

    def test_parent_xpath_for_none_parent(self):
        '''None parent results in empty xpath string.'''
        ret_val = self.obj._parent_xpath()

        self.assertEqual('', ret_val)

    def test_parent_xpath_for_xpath_root_parent(self):
        '''If the parent has "xpath_root()", then use that.'''
        Path = '/foo/bar'

        spec = {
            'xpath_root.return_value': Path,
        }
        self.obj.parent = mock.Mock(**spec)

        ret_val = self.obj._parent_xpath()

        self.assertEqual(Path, ret_val)
        self.obj.parent.xpath_root.assert_called_once_with(
            self.obj.ROOT)

    def test_parent_xpath_for_xpath_parent(self):
        '''Default case for parent xpath.'''
        Path = '/hello/world'

        spec = {
            'xpath.return_value': Path,
        }
        self.obj.parent = mock.Mock(spec=['xpath', ], **spec)

        ret_val = self.obj._parent_xpath()

        self.assertEqual(Path, ret_val)
        self.obj.parent.xpath.assert_called_once_with()

    def test_xpath_vsys_without_parent(self):
        ret_val = self.obj.xpath_vsys()

        self.assertIsNone(ret_val)

    def test_xpath_vsys_with_parent(self):
        expected_value = 'foo'
        spec = {
            'xpath_vsys.return_value': expected_value,
        }
        self.obj.parent = mock.Mock(**spec)

        ret_val = self.obj.xpath_vsys()

        self.assertEqual(expected_value, ret_val)
        self.obj.parent.xpath_vsys.assert_called_once_with()

    def test_xpath_panorama_without_parent(self):
        ret_val = self.obj.xpath_panorama()

        self.assertIsNone(ret_val)

    def test_xpath_panorama_with_parent(self):
        expected_value = 'foo'
        spec = {
            'xpath_panorama.return_value': expected_value,
        }
        self.obj.parent = mock.Mock(**spec)

        ret_val = self.obj.xpath_panorama()

        self.assertEqual(expected_value, ret_val)
        self.obj.parent.xpath_panorama.assert_called_once_with()

    # Skip element()

    @mock.patch('pandevice.base.ET')
    def test_element_str(self, m_ET):
        Element_Value = 42
        self.obj.element = mock.Mock(return_value=Element_Value)

        Tostring_Value = '42'
        spec = {
            'tostring.return_value': Tostring_Value,
        }
        m_ET.configure_mock(**spec)

        ret_val = self.obj.element_str()

        self.assertEqual(Tostring_Value, ret_val)
        self.obj.element.assert_called_once_with()
        m_ET.tostring.assert_called_once_with(Element_Value)

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    @mock.patch('pandevice.base.ET')
    def test_root_element_with_entry_suffix(self, m_ET, m_uid):
        self.obj.SUFFIX = Base.ENTRY
        Uid = 'uid'
        expected = 'Value'

        spec = {
            'Element.return_value': expected,
        }
        m_ET.configure_mock(**spec)
        m_uid.return_value = Uid

        ret_val = self.obj._root_element()

        self.assertEqual(expected, ret_val)
        m_ET.Element.assert_called_once_with('entry', {'name': Uid})

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    @mock.patch('pandevice.base.ET')
    def test_root_element_with_member_suffix(self, m_ET, m_uid):
        self.obj.SUFFIX = Base.MEMBER
        Uid = 'uid'
        expected = mock.Mock(text=Uid)

        spec = {
            'Element.return_value': mock.Mock(),
        }
        m_ET.configure_mock(**spec)
        m_uid.return_value = Uid

        ret_val = self.obj._root_element()

        self.assertEqual(Uid, ret_val.text)
        m_ET.Element.assert_called_once_with('member')

    @mock.patch('pandevice.base.ET')
    def test_root_element_with_none_suffix_no_slashes(self, m_ET):
        self.obj.SUFFIX = None

        expected_tag = 'baz'
        full_path = expected_tag
        self.obj.XPATH = full_path

        expected_value = '42'
        spec = {
            'Element.return_value': expected_value,
        }
        m_ET.configure_mock(**spec)

        ret_val = self.obj._root_element()

        self.assertEqual(expected_value, ret_val)
        m_ET.Element.assert_called_once_with(expected_tag)

    @mock.patch('pandevice.base.ET')
    def test_root_element_with_none_suffix_multiple_slashes(self, m_ET):
        self.obj.SUFFIX = None

        expected_tag = 'baz'
        full_path = '/foo/bar/baz'
        self.obj.XPATH = full_path

        expected_value = '42'
        spec = {
            'Element.return_value': expected_value,
        }
        m_ET.configure_mock(**spec)

        ret_val = self.obj._root_element()

        self.assertEqual(expected_value, ret_val)
        m_ET.Element.assert_called_once_with(expected_tag)

    # Skip _subelements

    def test_check_child_methods_for_name_not_in_childmethods(self):
        spec = {
            '_check_child_methods.return_value': None,
        }
        for x in xrange(3):
            m = mock.Mock(**spec)
            self.obj.children.append(m)

        Method = str(uuid.uuid4()).replace('-', '_')

        ret_val = self.obj._check_child_methods(Method)

        self.assertIsNone(ret_val)
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with(Method)

    def test_check_child_methods_for_name_in_childmethods(self):
        spec = {
            '_check_child_methods.return_value': None,
        }
        for x in xrange(3):
            m = mock.Mock(**spec)
            self.obj.children.append(m)

        Method = str(uuid.uuid4()).replace('-', '_')
        self.obj.CHILDMETHODS += (Method, )
        setattr(self.obj, 'child_{0}'.format(Method), mock.Mock())

        ret_val = self.obj._check_child_methods(Method)

        self.assertIsNone(ret_val)
        m = getattr(self.obj, 'child_{0}'.format(Method))
        m.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with(Method)

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_apply_with_ha_sync(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'
        PanDeviceElementStr = 'element string'

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=PanDeviceXpath)
        self.obj.element_str = mock.Mock(return_value=PanDeviceElementStr)
        m_uid.return_value = 'uid'
        for x in xrange(3):
            child = mock.Mock(**spec)
            self.obj.children.append(child)

        ret_val = self.obj.apply()

        self.assertIsNone(ret_val)
        m_pandevice.set_config_changed.assert_called_once_with()
        m_pandevice.active().xapi.edit.assert_called_once_with(
            PanDeviceXpath,
            PanDeviceElementStr,
            retry_on_peer=self.obj.HA_SYNC,
        )
        self.obj.xpath.assert_called_once_with()
        self.obj.element_str.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with('apply')

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_apply_without_ha_sync(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'
        PanDeviceElementStr = 'element string'

        self.obj.HA_SYNC = False

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=PanDeviceXpath)
        self.obj.element_str = mock.Mock(return_value=PanDeviceElementStr)
        m_uid.return_value = 'uid'
        for x in xrange(3):
            child = mock.Mock(**spec)
            self.obj.children.append(child)

        ret_val = self.obj.apply()

        self.assertIsNone(ret_val)
        m_pandevice.set_config_changed.assert_called_once_with()
        m_pandevice.xapi.edit.assert_called_once_with(
            PanDeviceXpath,
            PanDeviceElementStr,
            retry_on_peer=self.obj.HA_SYNC,
        )
        self.obj.xpath.assert_called_once_with()
        self.obj.element_str.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with('apply')

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_create_with_ha_sync(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'
        PanDeviceElementStr = 'element string'

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath_short = mock.Mock(return_value=PanDeviceXpath)
        self.obj.element_str = mock.Mock(return_value=PanDeviceElementStr)
        m_uid.return_value = 'uid'
        for x in xrange(3):
            child = mock.Mock(**spec)
            self.obj.children.append(child)

        ret_val = self.obj.create()

        self.assertIsNone(ret_val)
        m_pandevice.set_config_changed.assert_called_once_with()
        m_pandevice.active().xapi.set.assert_called_once_with(
            PanDeviceXpath,
            PanDeviceElementStr,
            retry_on_peer=self.obj.HA_SYNC,
        )
        self.obj.xpath_short.assert_called_once_with()
        self.obj.element_str.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with('create')

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_create_without_ha_sync(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'
        PanDeviceElementStr = 'element string'

        self.obj.HA_SYNC = False

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath_short = mock.Mock(return_value=PanDeviceXpath)
        self.obj.element_str = mock.Mock(return_value=PanDeviceElementStr)
        m_uid.return_value = 'uid'
        for x in xrange(3):
            child = mock.Mock()
            self.obj.children.append(child)

        ret_val = self.obj.create()

        self.assertIsNone(ret_val)
        m_pandevice.set_config_changed.assert_called_once_with()
        m_pandevice.xapi.set.assert_called_once_with(
            PanDeviceXpath,
            PanDeviceElementStr,
            retry_on_peer=self.obj.HA_SYNC,
        )
        self.obj.xpath_short.assert_called_once_with()
        self.obj.element_str.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with('create')

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_delete_with_ha_sync_no_parent(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=PanDeviceXpath)
        m_uid.return_value = 'uid'
        for x in xrange(3):
            child = mock.Mock(**spec)
            self.obj.children.append(child)

        ret_val = self.obj.delete()

        self.assertIsNone(ret_val)
        m_pandevice.set_config_changed.assert_called_once_with()
        m_pandevice.active().xapi.delete.assert_called_once_with(
            PanDeviceXpath,
            retry_on_peer=self.obj.HA_SYNC,
        )
        self.obj.xpath.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with('delete')

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_delete_with_ha_sync_and_parent(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'
        Uid = 'uid'

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.parent = mock.Mock()
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=PanDeviceXpath)
        m_uid.return_value = Uid
        for x in xrange(3):
            child = mock.Mock(**spec)
            self.obj.children.append(child)

        ret_val = self.obj.delete()

        self.assertIsNone(ret_val)
        self.obj.parent.remove.assert_called_once_with(self.obj)
        m_pandevice.set_config_changed.assert_called_once_with()
        m_pandevice.active().xapi.delete.assert_called_once_with(
            PanDeviceXpath,
            retry_on_peer=self.obj.HA_SYNC,
        )
        self.obj.xpath.assert_called_once_with()
        for c in self.obj.children:
            c._check_child_methods.assert_called_once_with('delete')

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test_delete_without_ha_sync(self, m_uid):
        PanDeviceId = '42'
        PanDeviceXpath = 'path'

        m_uid.return_value = 'uid'

        self.obj.HA_SYNC = False

        spec = {
            'id': PanDeviceId,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=PanDeviceXpath)
        for x in xrange(3):
            child = mock.Mock()

    # Skip update

    # Skip refresh

    # Skip refresh_variable

    # Skip _refresh_children

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_default_args_none_suffix(self, m_uid):
        Xpath = '/x/path'
        lasttag = ''

        expected = 'foo'
        spec = {
            'find.return_value': expected,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.get.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)

        ret_val = self.obj._refresh_xml(False, True)

        self.assertEqual(expected, ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_default_args_with_member_suffix(self, m_uid):
        Xpath = '/x/path'
        lasttag = 'member'

        expected = 'foo'
        spec = {
            'find.return_value': expected,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.get.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        self.obj.SUFFIX = Base.MEMBER

        ret_val = self.obj._refresh_xml(False, True)

        self.assertEqual(expected, ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_default_args_with_entry_suffix(self, m_uid):
        Xpath = '/x/path'
        lasttag = 'entry'

        expected = 'foo'
        spec = {
            'find.return_value': expected,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.get.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        self.obj.SUFFIX = Base.ENTRY

        ret_val = self.obj._refresh_xml(False, True)

        self.assertEqual(expected, ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_with_running_config(self, m_uid):
        Xpath = '/x/path'
        lasttag = ''

        expected = 'foo'
        spec = {
            'find.return_value': expected,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.show.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        self.obj.refresh = mock.Mock()

        ret_val = self.obj._refresh_xml(True, True)

        self.assertEqual(expected, ret_val)
        m_pandevice.xapi.show.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_no_refresh_children(self, m_uid):
        Xpath = '/x/path'
        lasttag = ''

        expected = 'foo'
        spec = {
            'find.return_value': expected,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.get.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        self.obj.refresh = mock.Mock()

        ret_val = self.obj._refresh_xml(False, False)

        self.assertEqual(expected, ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_api_action_raises_pannosuchnode_with_exceptions_on_raises_error(self, m_uid):
        Xpath = '/x/path'

        spec = {
            'id': 'myid',
            'xapi.get.side_effect': Err.PanNoSuchNode,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        m_uid.return_value = 'uid'

        self.assertRaises(
            Err.PanObjectMissing,
            self.obj._refresh_xml, False, True)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_api_action_raises_pannosuchnode_with_exceptions_off_returns_none(self, m_uid):
        Xpath = '/x/path'

        spec = {
            'id': 'myid',
            'xapi.get.side_effect': Err.PanNoSuchNode,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        m_uid.return_value = 'uid'

        ret_val = self.obj._refresh_xml(False, False)

        self.assertIsNone(ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_api_action_raises_panxapierror_with_exceptions_on_raises_error(self, m_uid):
        Xpath = '/x/path'

        spec = {
            'id': 'myid',
            'xapi.get.side_effect': pan.xapi.PanXapiError,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        m_uid.return_value = 'uid'

        self.assertRaises(
            Err.PanObjectMissing,
            self.obj._refresh_xml, False, True)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_api_action_raises_panxapierror_with_exceptions_off_returns_none(self, m_uid):
        Xpath = '/x/path'

        spec = {
            'id': 'myid',
            'xapi.get.side_effect': pan.xapi.PanXapiError,
        }
        m_pandevice = mock.Mock(**spec)
        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)
        m_uid.return_value = 'uid'

        ret_val = self.obj._refresh_xml(False, False)

        self.assertIsNone(ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_find_fails_with_exceptions_on_raises_error(self, m_uid):
        Xpath = '/x/path'
        lasttag = ''

        expected = 'foo'
        spec = {
            'find.return_value': None,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.get.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)

        self.assertRaises(
            Err.PanObjectMissing,
            self.obj._refresh_xml, False, True)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    @mock.patch('pandevice.base.PanObject.uid', new_callable=mock.PropertyMock)
    def test__refresh_xml_find_fails_with_exceptions_off_returns_none(self, m_uid):
        '''Requires exceptions=False.'''
        Xpath = '/x/path'
        lasttag = ''

        expected = 'foo'
        spec = {
            'find.return_value': None,
        }
        m_root = mock.Mock(**spec)
        m_uid.return_value = 'uid'

        spec = {
            'id': 'myid',
            'xapi.get.return_value': m_root,
        }
        m_pandevice = mock.Mock(**spec)

        self.obj.nearest_pandevice = mock.Mock(return_value=m_pandevice)
        self.obj.xpath = mock.Mock(return_value=Xpath)

        ret_val = self.obj._refresh_xml(False, False)

        self.assertIsNone(ret_val)
        m_pandevice.xapi.get.assert_called_once_with(
            Xpath,
            retry_on_peer=self.obj.HA_SYNC)
        self.obj.xpath.assert_called_once_with()
        m_root.find.assert_called_once_with(
            'result/{0}'.format(lasttag))

    def test_nearest_pandevice(self):
        expected = 'return value'

        self.obj._nearest_pandevice = mock.Mock(return_value=expected)

        ret_val = self.obj.nearest_pandevice()

        self.assertEqual(expected, ret_val)
        self.obj._nearest_pandevice.assert_called_once_with()

    def test__nearest_pandevice_with_parent(self):
        expected = 'ParentObject'

        spec = {
            '_nearest_pandevice.return_value': expected,
        }
        self.obj.parent = mock.Mock(**spec)

        ret_val = self.obj._nearest_pandevice()

        self.assertEqual(expected, ret_val)
        self.obj.parent._nearest_pandevice.assert_called_once_with()

    def test__nearest_pandevice_without_parent_raises_error(self):
        self.assertRaises(
            Err.PanDeviceNotSet,
            self.obj._nearest_pandevice)

    def test_panorama_with_parent(self):
        expected = 'PanoramaObject'

        spec = {
            'panorama.return_value': expected,
        }
        self.obj.parent = mock.Mock(**spec)

        ret_val = self.obj.panorama()

        self.assertEqual(expected, ret_val)
        self.obj.parent.panorama.assert_called_once_with()

    def test_panorama_without_parent_raises_error(self):
        self.assertRaises(
            Err.PanDeviceNotSet,
            self.obj.panorama)

    def test_devicegroup_with_parent(self):
        expected = 'DeviceGroup'

        spec = {
            'devicegroup.return_value': expected,
        }
        self.obj.parent = mock.Mock(**spec)

        ret_val = self.obj.devicegroup()

        self.assertEqual(expected, ret_val)
        self.obj.parent.devicegroup.assert_called_once_with()

    def test_devicegroup_without_parent(self):
        ret_val = self.obj.devicegroup()

        self.assertIsNone(ret_val)

    # Skip find

    # Skip findall

    # Skip find_or_create

    # Skip findall_or_create

    # Skip find_index

    # Skip applyall

    # Skip refreshall

    # Skip refreshall_from_xml

    # Skip _parse_xml

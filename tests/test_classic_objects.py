''' Tests specifically for classic objects.

Note:  All tests in this file are for classic objects.  These are to try and
make sure that the fix for classic objects with a self.NAME == None still
work properly.

'''


from pandevice import device


def test_system_settings_with_positional_arg_sets_hostname():
    ss = device.SystemSettings('foobar')

    assert ss.hostname == 'foobar'


def test_system_settings_parsing():
    ss = device.SystemSettings(hostname='foobar')
    ss2 = device.SystemSettings()

    ss2.refresh(xml=ss.element())

    assert ss.equal(ss2)

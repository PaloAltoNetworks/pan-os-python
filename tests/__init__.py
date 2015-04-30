# -*- coding: utf-8 -*-

import inspect
import unittest
from test_pandevice import TestPandevice

realfw = unittest.TestSuite()
mockfw = unittest.TestSuite()

for name, method in inspect.getmembers(
        TestPandevice,
        inspect.ismethod):
    # Separate mock and real tests into different TestSuites
    # All test methods using a mock firewall should end with "_mock"
    if name == "setUp":
        continue
    elif name.startswith("test_") and name.endswith("_mock"):
        mockfw.addTest(TestPandevice(name))
    elif name.startswith("test_"):
        realfw.addTest(TestPandevice(name))

import unittest
from distutils.version import LooseVersion
import sys
sys.path.append('../')

import pandevice

class TestPanOSVersion(unittest.TestCase):
    def setUp(self):
        self.t1 = pandevice.PanOSVersion("1.5.1")
        self.t2 = pandevice.PanOSVersion("2.3.2")

    def test_NumberCase(self):
        self.assertTrue(self.t2 > self.t1)
        self.assertTrue(self.t2 >= self.t1)
        self.assertTrue(self.t1 < self.t2)
        self.assertTrue(self.t1 <= self.t2)
        self.assertTrue(self.t1 != self.t2)
        self.assertFalse(self.t1 == self.t2)

if __name__=='__main__':
    unittest.main()

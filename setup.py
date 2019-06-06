#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

requirements = [
    'pan-python',
]

test_requirements = [
    'pan-python',
    'mock',
    'pytest',
]

setup_kwargs = dict(
    name='pandevice',
    version='0.11.0',
    description='Framework for interacting with Palo Alto Networks devices via API',
    long_description='The Palo Alto Networks Device Framework is a way to interact with Palo Alto Networks devices (including Next-generation Firewalls and Panorama) using the device API that is object oriented and conceptually similar to interaction with the device via the GUI or CLI.',
    author='Palo Alto Networks',
    author_email='techpartners@paloaltonetworks.com',
    url='https://github.com/PaloAltoNetworks/pandevice',
    packages=[
        'pandevice',
    ],
    package_dir={'pandevice':
                 'pandevice'},
    include_package_data=True,
    install_requires=requirements,
    license="ISC",
    zip_safe=False,
    keywords='pandevice',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        "Programming Language :: Python :: 3",
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
    tests_require=test_requirements,
)

try:
    from setuptools.command.test import test as TestCommand
except ImportError:
    setup_kwargs.setdefault('setup_requires', [])
    setup_kwargs['setup_requires'].append('pytest-runner')
else:
    import sys

    class PyTest(TestCommand):
        user_options = [("pytest-args=", "a", "Arguments to pass to pytest")]

        def initialize_options(self):
            TestCommand.initialize_options(self)
            self.pytest_args = ""

        def run_tests(self):
            import shlex

            # import here, cause outside the eggs aren't loaded
            import pytest

            errno = pytest.main(shlex.split(self.pytest_args))
            sys.exit(errno)

    setup_kwargs.setdefault('cmdclass', {})
    setup_kwargs['cmdclass']['pytest'] = PyTest


setup(**setup_kwargs)

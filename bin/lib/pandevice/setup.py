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
]

setup(
    name='pandevice',
    version='0.2.0',
    description='The Palo Alto Networks Device Framework is a way to interact with Palo Alto Networks devices (including Next-generation Firewalls and Panorama) using the device API that is conceptually similar to iinteraction with the device via GUI or CLI.',
    long_description=readme + '\n\n' + history,
    author='Brian Torres-Gil',
    author_email='btorres-gil@paloaltonetworks.com',
    url='https://github.com/PaloAltoNetworks-BD/pandevice',
    packages=[
        'pandevice',
    ],
    package_dir={'pandevice':
                 'pandevice'},
    include_package_data=True,
    install_requires=requirements,
    license="BSD",
    zip_safe=False,
    keywords='pandevice',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    test_suite='tests.mockfw',
    tests_require=test_requirements
)

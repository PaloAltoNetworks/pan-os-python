#!/usr/bin/env python

# $ ./setup.py sdist

# PyPI

# one time
# $ ./setup.py register -r testpypi

# $ ./setup.py sdist upload -r testpypi

from distutils.core import setup

version = 'snapshot'
version = None

if version is None:
    import sys
    sys.path[:0] = ['lib']
    from pan.xapi import __version__
    version = __version__
elif version == 'snapshot':
    import time
    version = 'snapshot-' + time.strftime('%Y%m%d')

with open('README.txt') as file:
    long_description = file.read()

setup(name='pan-python',
      version=version,
      description='Multi-tool set for Palo Alto Networks' +
      ' PAN-OS, Panorama, WildFire and AutoFocus',
      long_description=long_description,
      author='Kevin Steves',
      author_email='kevin.steves@pobox.com',
      url='https://github.com/kevinsteves/pan-python',
      license='ISC',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: End Users/Desktop',
          'License :: OSI Approved :: ISC License (ISCL)',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.2',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
      ],

      package_dir={'': 'lib'},
      packages=['pan', 'pan/afapi'],
      scripts=[
          'bin/panxapi.py',
          'bin/panconf.py',
          'bin/panwfapi.py',
          'bin/panafapi.py',
      ],
      )

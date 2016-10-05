#!/usr/bin/env python

#
# Copyright (c) 2012-2014 Kevin Steves <kevin.steves@pobox.com>
#
# Permission to use, copy, modify, and distribute this software for any
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
#

from __future__ import print_function
import sys
import os
import signal
import getopt
import json
import pprint
import logging

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.config


def main():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        # Windows
        pass

    options = parse_opts()

    if options['config'] is None:
        print('No config', file=sys.stderr)
        sys.exit(1)

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(pan.config.DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(pan.config.DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(pan.config.DEBUG1)

#        log_format = '%(levelname)s %(name)s %(message)s'
        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    xml = read_file(options['config'])

    try:
        conf = pan.config.PanConfig(config=xml)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    if options['debug']:
        print('config_version:', conf.config_version(),
              file=sys.stderr)
        print('config_panorama:', conf.config_panorama(),
              file=sys.stderr)
        print('config_multi_vsys:', conf.config_multi_vsys(),
              file=sys.stderr)

    if options['print_xml']:
        try:
            s = conf.xml(xpath=options['xpath'])
        except pan.config.PanConfigError as msg:
            print('pan.config.PanConfigError:', msg, file=sys.stderr)
            sys.exit(1)

        if s is not None:
            print(s.rstrip())

    if options['print_flat']:
        xpaths = conf.config_xpaths()
        path = './'
        if options['xpath']:
            o = conf_flat(conf, path, xpath=options['xpath'])
            if o:
                print('\n'.join(o))
        elif conf.config_version() is None:
            o = conf_flat(conf, path)
            if o:
                print('\n'.join(o))
        else:
            for xpath in xpaths:
                o = conf_flat(conf, path, xpath=xpath)
                if o:
                    print('\n'.join(o))

    if options['print_set']:
        xpaths = conf.config_xpaths()
        path = 'set '
        member_list = options['mlist']
        if conf.config_version() is not None:
            version = conf.config_version().split('.')
            if int(version[0]) >= 5:  # XXX ValueError
                member_list = True
        if options['xpath']:
            o = conf_set(conf, path, xpath=options['xpath'],
                         member_list=member_list)
            if o:
                print('\n'.join(o))
        elif conf.config_version() is None:
            o = conf_set(conf, path)
            if o:
                print('\n'.join(o))
        else:
            for xpath in xpaths:
                o = conf_set(conf, path, xpath=xpath,
                             member_list=member_list)
                if o:
                    print('\n'.join(o))

    if options['print_python'] or options['print_json']:
        try:
            d = conf.python(xpath=options['xpath'])
        except pan.config.PanConfigError as msg:
            print('pan.config.PanConfigError:', msg, file=sys.stderr)
            sys.exit(1)

        if d:
            if options['print_python']:
                print('var1 =', pprint.pformat(d))
            if options['print_json']:
                if options['compact']:
                    print(json.dumps(d, separators=(',', ':')))
                else:
                    print(json.dumps(d, sort_keys=True, indent=2))

    sys.exit(0)


def conf_flat(conf, path, xpath=None):
    try:
        o = conf.flat(path, xpath)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    return o


def conf_set(conf, path, xpath=None, member_list=None):
    try:
        o = conf.set_cli(path, xpath, member_list)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    return o


def parse_opts():
    options = {
        'config': None,
        'print_xml': False,
        'print_python': False,
        'print_json': False,
        'print_flat': False,
        'print_set': False,
        'mlist': False,
        'compact': False,
        'xpath': None,
        'debug': 0,
        }

    short_options = ''
    long_options = ['version', 'help', 'debug=',
                    'config=', 'xml', 'py', 'json', 'flat', 'set',
                    'mlist', 'compact',
                    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if opt == '--config':
            options['config'] = arg
        elif opt == '--xml':
            options['print_xml'] = True
        elif opt == '--py':
            options['print_python'] = True
        elif opt == '--json':
            options['print_json'] = True
        elif opt == '--flat':
            options['print_flat'] = True
        elif opt == '--set':
            options['print_set'] = True
        elif opt == '--mlist':
            options['mlist'] = True
        elif opt == '--compact':
            options['compact'] = True
        elif opt == '--debug':
            try:
                options['debug'] = int(arg)
                if options['debug'] < 0:
                    raise ValueError
            except ValueError:
                print('Invalid debug:', arg, file=sys.stderr)
                sys.exit(1)
            if options['debug'] > 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
        elif opt == '--version':
            print('pan-python', pan.config.__version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if len(args) > 0:
        options['xpath'] = args[0]

    return options


def read_file(path):
    if path == '-':
        lines = sys.stdin.readlines()
    else:
        try:
            f = open(path)
        except IOError as msg:
            print('open %s: %s' % (path, msg), file=sys.stderr)
            sys.exit(1)
        lines = f.readlines()
        f.close()

    return ''.join(lines)


def usage():
    usage = '''%s [options] [pseudo-xpath]
    --config path         path to XML config or '-' for stdin
    --xml                 print XML
    --py                  print XML in Python
    --json                print XML in JSON
    --flat                print XML flatly
    --set                 print XML as set CLI
    --mlist               print set CLI members as a list
    --compact             print compactly
    --debug level         enable debug level up to 3
    --version             display version
    --help                display usage
'''
    print(usage % os.path.basename(sys.argv[0]), end='', file=sys.stderr)

if __name__ == '__main__':
    main()

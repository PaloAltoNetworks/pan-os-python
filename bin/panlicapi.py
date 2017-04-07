#!/usr/bin/env python

#
# Copyright (c) 2017 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
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
import getopt
import json
import logging
import os
import pprint
import sys

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.licapi

debug = 0

INDENT = 4  # pprint.pformat()


def main():
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(pan.licapi.DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(pan.licapi.DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(pan.licapi.DEBUG1)

        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    try:
        licapi = pan.licapi.PanLicapi(panrc_tag=options['panrc_tag'],
                                      api_key=options['api_key'],
                                      api_version=options['api_version'],
                                      hostname=options['hostname'],
                                      timeout=options['timeout'],
                                      verify_cert=options['ssl'])

    except pan.licapi.PanLicapiError as e:
        print('pan.licapi.PanLicapi:', e, file=sys.stderr)
        sys.exit(1)

    if False:
        pass

    elif options['activate']:
        activate(licapi, options)

    elif options['deactivate']:
        deactivate(licapi, options)

    elif options['get']:
        get(licapi, options)

    sys.exit(0)


def activate(licapi, options):
    try:
        action = 'activate'
        r = licapi.activate(authcode=options['authcode'],
                            uuid=options['uuid'],
                            cpuid=options['cpuid'],
                            serialnumber=options['serial'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.licapi.PanLicapiError as e:
        print_exception(action, e)
        sys.exit(1)

    if options['key_file'] or options['xml_file']:
        write_keys(r, options)


def deactivate(licapi, options):
    try:
        action = 'deactivate'
        r = licapi.deactivate(encryptedtoken=options['token'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.licapi.PanLicapiError as e:
        print_exception(action, e)
        sys.exit(1)


def get(licapi, options):
    try:
        action = 'get'
        r = licapi.get(authcode=options['authcode'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.licapi.PanLicapiError as e:
        print_exception(action, e)
        sys.exit(1)


def write_keys(r, options):
    if r.json is None:
        print('No JSON response for write license keys', file=sys.stderr)
        sys.exit(1)

    if not isinstance(r.json, list):
        print('JSON response not list: %s',
              pprint.pformat(key, indent=INDENT),
              file=sys.stderr)
        sys.exit(1)

    for key in r.json:
        if not ('partidField' in key and 'keyField' in key):
            print('Malformed license: %s' %
                  pprint.pformat(key, indent=INDENT),
                  file=sys.stderr)
            continue

        if 'typeField' in key and key['typeField'] == 'SUP':
            if debug > 0:
                print('Support license skipped',
                      end='', file=sys.stderr)
                if 'feature_descField' in key:
                    print(': %s' % key['feature_descField'],
                          end='', file=sys.stderr)
                print()
            continue

        prefix = options['uuid'] if options['uuid'] else options['serial']
        files = []

        if options['key_file']:
            file = prefix + '-' + key['partidField'] + '.key'
            if options['dst'] is None:
                path = file
            else:
                path = os.path.join(options['dst'], file)
            files.append((path, key['keyField']))

        if options['xml_file']:
            file = prefix + '-' + key['partidField'] + '.xml'
            if options['dst'] is None:
                path = file
            else:
                path = os.path.join(options['dst'], file)
            files.append((path, install_xml(key['keyField'])))

        for x in files:
            if not write_key(*x):
                continue

            print('%s' % os.path.basename(x[0]), end='')
            if 'feature_descField' in key:
                print(': %s' % key['feature_descField'])
            else:
                print()


def write_key(path, x):
    try:
        f = open(path, 'w')
    except IOError as e:
        print('open %s: %s' % (path, e), file=sys.stderr)
        return False
    try:
        f.write(x)
    except IOError as e:
        print('write %s: %s' % (path, e), file=sys.stderr)
        return False
    finally:
        f.close()

    return True


def install_xml(x):
    document = '''\
<request><license><install>
%s\
</install></license></request>
'''

    return document % x


def print_exception(action, e):
    print('%s:' % action, end='', file=sys.stderr)
    print(' "%s"' % e, file=sys.stderr)


def print_status(action, r):
    print('%s:' % action, end='', file=sys.stderr)

    if r.http_code is not None:
        print(' %s' % r.http_code, end='', file=sys.stderr)
    if r.http_reason is not None:
        print(' %s' % r.http_reason, end='', file=sys.stderr)

    if r.http_headers is not None:
        # XXX
        content_type = r.http_headers.get('content-type')
        if False and content_type is not None:
            print(' %s' % content_type, end='', file=sys.stderr)
        length = r.http_headers.get('content-length')
        if length is not None:
            print(' %s' % length, end='', file=sys.stderr)

    print(' %.2fsecs' % r.wall_time, end='', file=sys.stderr)

    if r.json is not None:
        if 'Message' in r.json:
            print(' "%s"' % r.json['Message'],
                  end='', file=sys.stderr)

    print(file=sys.stderr)


def print_response(r, options):
    if r.http_text is None:
        return

    if r.http_content_type is None:
        return

    if r.http_content_type == 'text/html':
        # XXX
        print(r.http_text)

    elif r.http_content_type == 'application/json':
        if options['print_json']:
            print_json(r.http_text, isjson=True)

        if options['print_python']:
            print_python(r.http_text, isjson=True)


def exit_for_http_status(r):
    if r.http_code is not None:
        if not (200 <= r.http_code < 300):
            sys.exit(1)
        else:
            return
    sys.exit(1)


def print_python(obj, isjson=False):
    if isjson:
        try:
            obj = json.loads(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            print(obj, file=sys.stderr)
            sys.exit(1)

    print(pprint.pformat(obj, indent=INDENT))


def print_json(obj, isjson=False):
    if isjson:
        try:
            obj = json.loads(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            print(obj, file=sys.stderr)
            sys.exit(1)

    print(json.dumps(obj, sort_keys=True, indent=INDENT,
                     separators=(',', ': ')))


def process_arg(s, list=False):
    stdin_char = '-'

    if s == stdin_char:
        lines = sys.stdin.readlines()
    else:
        try:
            f = open(s)
            lines = f.readlines()
            f.close()
        except IOError:
            lines = [s]

    if debug > 1:
        print('lines:', lines, file=sys.stderr)

    if list:
        l = [x.rstrip('\r\n') for x in lines]
        return l

    lines = ''.join(lines)
    return lines


def parse_opts():
    options = {
        'activate': False,
        'deactivate': False,
        'get': False,
        'authcode': None,
        'cpuid': None,
        'uuid': None,
        'token': None,
        'serial': None,
        'key_file': False,
        'xml_file': False,
        'dst': None,
        'api_key': None,
        'api_version': None,
        'hostname': None,
        'ssl': True,
        'print_python': False,
        'print_json': False,
        'debug': 0,
        'panrc_tag': None,
        'timeout': None,
        }

    short_options = 'K:V:h:pjDt:T:kx'
    long_options = [
        'activate', 'deactivate', 'get', 'authcode=',
        'cpuid=', 'uuid=', 'token=', 'serial=', 'dst=',
        'ssl=',
        'version', 'help',
    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if False:
            pass
        elif opt == '--activate':
            options['activate'] = True
        elif opt == '--deactivate':
            options['deactivate'] = True
        elif opt == '--get':
            options['get'] = True
        elif opt == '--authcode':
            options['authcode'] = arg
        elif opt == '--cpuid':
            options['cpuid'] = arg
        elif opt == '--uuid':
            options['uuid'] = arg
        elif opt == '--token':
            options['token'] = process_arg(arg)
        elif opt == '--serial':
            options['serial'] = arg
        elif opt == '-k':
            options['key_file'] = True
        elif opt == '-x':
            options['xml_file'] = True
        elif opt == '--dst':
            if not os.path.isdir(arg):
                print('Invalid --dst: %s' % arg, file=sys.stderr)
                sys.exit(1)
            options['dst'] = arg
        elif opt == '-K':
            options['api_key'] = arg
        elif opt == '-V':
            options['api_version'] = arg
        elif opt == '-h':
            options['hostname'] = arg
        elif opt == '--ssl':
            if arg in ['verify', 'noverify']:
                if arg == 'noverify':
                    options['ssl'] = False
                elif arg == 'verify':
                    options['ssl'] = True
            else:
                print('Invalid --ssl option:', arg)
                sys.exit(1)
        elif opt == '-p':
            options['print_python'] = True
        elif opt == '-j':
            options['print_json'] = True
        elif opt == '-D':
            if not options['debug'] < 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
            global debug
            debug += 1
            options['debug'] = debug
        elif opt == '-t':
            if arg:
                options['panrc_tag'] = arg
        elif opt == '-T':
            options['timeout'] = arg
        elif opt == '--version':
            print('pan-python', pan.licapi.__version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if len(args) > 0:
        print('Extra options:', args, file=sys.stderr)
        sys.exit(1)

    if options['debug'] > 2:
        s = pprint.pformat(options, indent=INDENT)
        print(s, file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
    --activate            activate VM license
    --deactivate          deactivate VM license
    --get                 get quantity of VM provisioned
    --authcode code       license auth code
    --cpuid id            VM-Series vm-cpuid
    --uuid id             VM-Series vm-uuid
    --token token         deactivate license token
    --serial serial       get licenses for serial number
    -k                    write license key files
    -x                    write license install PAN-OS XML API documents
    --dst dir             destination directory for keys (default .)
    -t tag                .panrc tagname
    -K api_key            license API key
    -V api_version        license API version (default %s)
    -h hostname           license hostname
    -p                    print JSON response in Python to stdout
    -j                    print JSON to stdout
    -D                    enable debug (multiple up to -DDD)
    --ssl opt             SSL verify option: verify|noverify
    -T seconds            HTTP connect timeout
    --version             display version
    --help                display usage
'''
    print(usage % (os.path.basename(sys.argv[0]),
          pan.licapi.DEFAULT_API_VERSION), end='')

if __name__ == '__main__':
    main()

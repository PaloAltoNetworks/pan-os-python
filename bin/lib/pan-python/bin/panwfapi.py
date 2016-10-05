#!/usr/bin/env python

#
# Copyright (c) 2013-2016 Kevin Steves <kevin.steves@pobox.com>
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
from datetime import date, timedelta
import sys
import os
import signal
import getopt
import json
import pprint
import logging
import ssl
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.wfapi
import pan.config

debug = 0


def main():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        # Windows
        pass

#    set_encoding()
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(pan.wfapi.DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(pan.wfapi.DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(pan.wfapi.DEBUG1)

#        log_format = '%(levelname)s %(name)s %(message)s'
        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if options['cafile'] or options['capath'] or options['ssl']:
        ssl_context = create_ssl_context(options['cafile'],
                                         options['capath'],
                                         options['ssl'])
    else:
        ssl_context = None

    try:
        wfapi = pan.wfapi.PanWFapi(tag=options['tag'],
                                   api_key=options['api_key'],
                                   hostname=options['hostname'],
                                   timeout=options['timeout'],
                                   http=options['http'],
                                   ssl_context=ssl_context)

    except pan.wfapi.PanWFapiError as msg:
        print('pan.wfapi.PanWFapi:', msg, file=sys.stderr)
        sys.exit(1)

    if options['debug'] > 2:
        print('wfapi.__str__()===>\n', wfapi, '\n<===',
              sep='', file=sys.stderr)

    try:
        hashes = process_hashes(options['hash'])

        if options['submit'] is not None:
            action = 'submit'
            kwargs = {}
            if os.path.isfile(options['submit']):
                kwargs['file'] = options['submit']
            else:
                o = urlparse(options['submit'])
                if options['debug']:
                    print(o, file=sys.stderr)
                if o.scheme == 'file':
                    if o.path and os.path.isfile(o.path):
                        kwargs['file'] = o.path
                    else:
                        print('Invalid URL: file not found:',
                              options['submit'], file=sys.stderr)
                        sys.exit(1)
                else:
                    if o.scheme in ['http', 'https', 'ftp']:
                        kwargs['url'] = options['submit']
                    else:
                        print('Invalid file or URL:',
                              options['submit'], file=sys.stderr)
                        sys.exit(1)

            wfapi.submit(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)

        if options['submit-link'] is not None:
            action = 'submit'
            kwargs = {}
            kwargs['links'] = process_arg(options['submit-link'], list=True)

            wfapi.submit(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)

        if options['change-request']:
            action = 'change-request'
            kwargs = {}
            if len(hashes) > 1:
                print('Only 1 hash allowed for %s' % action, file=sys.stderr)
                sys.exit(1)
            if len(hashes) == 1:
                kwargs['hash'] = hashes[0]
            if options['new-verdict'] is not None:
                kwargs['verdict'] = process_verdict(options['new-verdict'])
            if options['email'] is not None:
                kwargs['email'] = options['email']
            if options['comment'] is not None:
                kwargs['comment'] = process_arg(options['comment'])

            wfapi.change_request(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)

        if options['report']:
            action = 'report'
            kwargs = {}
            if len(hashes) > 1:
                print('Only 1 hash allowed for %s' % action, file=sys.stderr)
                sys.exit(1)
            if len(hashes) == 1:
                kwargs['hash'] = hashes[0]
            if options['format'] is not None:
                kwargs['format'] = options['format']

            wfapi.report(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)
            save_file(wfapi, options)

        if options['verdict']:
            kwargs = {}
            if len(hashes) == 1:
                action = 'verdict'
                kwargs['hash'] = hashes[0]
                wfapi.verdict(**kwargs)
            elif len(hashes) > 1:
                action = 'verdicts'
                kwargs['hashes'] = hashes
                wfapi.verdicts(**kwargs)
            else:
                action = 'verdict'
                wfapi.verdict(**kwargs)

            print_status(wfapi, action)
            print_response(wfapi, options)
            save_file(wfapi, options)

        if options['sample']:
            action = 'sample'
            kwargs = {}
            if len(hashes) > 1:
                print('Only 1 hash allowed for %s' % action, file=sys.stderr)
                sys.exit(1)
            if len(hashes) == 1:
                kwargs['hash'] = hashes[0]

            wfapi.sample(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)
            save_file(wfapi, options)

        if options['pcap']:
            action = 'pcap'
            kwargs = {}
            if len(hashes) > 1:
                print('Only 1 hash allowed for %s' % action, file=sys.stderr)
                sys.exit(1)
            if len(hashes) == 1:
                kwargs['hash'] = hashes[0]
            if options['platform'] is not None:
                kwargs['platform'] = options['platform']

            wfapi.pcap(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)
            save_file(wfapi, options)

        if options['changed']:
            action = 'verdicts_changed'
            kwargs = {}
            if options['date'] is not None:
                kwargs['date'] = options['date']
                try:
                    x = int(options['date'])
                except ValueError:
                    pass
                else:
                    if x < 1:
                        d = date.today()
                        d = d - timedelta(-x)
                        kwargs['date'] = d.isoformat()
                        if options['debug']:
                            print('relative date(%d): %s' % (x, kwargs['date']),
                                  file=sys.stderr)

            wfapi.verdicts_changed(**kwargs)
            print_status(wfapi, action)
            print_response(wfapi, options)
            save_file(wfapi, options)

        if options['testfile']:
            action = 'testfile'

            wfapi.testfile()
            print_status(wfapi, action)
            print_response(wfapi, options)
            save_file(wfapi, options)

    except pan.wfapi.PanWFapiError as msg:
        print_status(wfapi, action, msg)
        print_response(wfapi, options)
        sys.exit(1)

    sys.exit(0)


def process_hashes(list):
    stdin_char = '-'

    hashes = []
    for hash in list:
        lines = []
        if hash == stdin_char:
            lines = sys.stdin.readlines()
        else:
            try:
                f = open(hash)
                lines = f.readlines()
                f.close()
            except IOError:
                # only validate hash from command line
                validate_hash(hash)
                hashes.append(hash)
        if len(lines) > 0:
            [hashes.append(x.rstrip('\r\n')) for x in lines]

    if debug > 1:
        print('hashes:', len(hashes), file=sys.stderr)

    return hashes


def validate_hash(hash):
    if debug > 0:
        return

    x = len(hash)
    if not (x in [32, 64]):
        print('hash length (%d) must be 32 (MD5) or 64 (SHA256)' % x,
              file=sys.stderr)
        sys.exit(1)


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


def process_verdict(verdict):
    verdicts = {
        'benign': pan.wfapi.BENIGN,
        'malware': pan.wfapi.MALWARE,
        'grayware': pan.wfapi.GRAYWARE,
    }

    try:
        int(verdict)
        return verdict
    except ValueError:
        if verdict in verdicts:
            return str(verdicts[verdict])
        return verdict


def parse_opts():
    options = {
        'submit': None,
        'submit-link': None,
        'change-request': False,
        'report': False,
        'verdict': False,
        'sample': False,
        'pcap': False,
        'changed': False,
        'hash': [],
        'platform': None,
        'new-verdict': None,
        'email': None,
        'comment': None,
        'testfile': False,
        'format': None,
        'date': None,
        'dst': None,
        'api_key': None,
        'hostname': None,
        'http': False,
        'ssl': None,
        'cafile': None,
        'capath': None,
        'print_xml': False,
        'print_python': False,
        'print_json': False,
        'print_html': False,
        'debug': 0,
        'tag': None,
        'timeout': None,
        }

    short_options = 'K:h:xpjHDt:T:'
    long_options = ['version', 'help',
                    'submit=', 'submit-link=',
                    'change-request', 'report', 'verdict', 'sample',
                    'pcap', 'changed',
                    'hash=', 'platform=', 'testfile',
                    'new-verdict=', 'email=', 'comment=',
                    'format=', 'date=', 'dst=',
                    'http', 'ssl=', 'cafile=', 'capath=',
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
        elif opt == '--submit':
            options['submit'] = arg
        elif opt == '--submit-link':
            options['submit-link'] = arg
        elif opt == '--change-request':
            options['change-request'] = True
        elif opt == '--report':
            options['report'] = True
        elif opt == '--verdict':
            options['verdict'] = True
        elif opt == '--sample':
            options['sample'] = True
        elif opt == '--pcap':
            options['pcap'] = True
        elif opt == '--changed':
            options['changed'] = True
        elif opt == '--hash':
            options['hash'].append(arg)
        elif opt == '--platform':
            options['platform'] = arg
        elif opt == '--new-verdict':
            options['new-verdict'] = arg
        elif opt == '--email':
            options['email'] = arg
        elif opt == '--comment':
            options['comment'] = arg
        elif opt == '--testfile':
            options['testfile'] = True
        elif opt == '--format':
            options['format'] = arg
        elif opt == '--date':
            options['date'] = arg
        elif opt == '--dst':
            options['dst'] = arg
        elif opt == '-K':
            options['api_key'] = arg
        elif opt == '-h':
            options['hostname'] = arg
        elif opt == '--http':
            options['http'] = True
        elif opt == '--ssl':
            if arg in ['default', 'noverify', 'cacloud']:
                options['ssl'] = arg
            else:
                print('Invalid --ssl option:', arg)
                sys.exit(1)
        elif opt == '--cafile':
            options['cafile'] = arg
        elif opt == '--capath':
            options['capath'] = arg
        elif opt == '-x':
            options['print_xml'] = True
        elif opt == '-p':
            options['print_python'] = True
        elif opt == '-j':
            options['print_json'] = True
        elif opt == '-H':
            options['print_html'] = True
        elif opt == '-D':
            if not options['debug'] < 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
            global debug
            debug += 1
            options['debug'] = debug
        elif opt == '-t':
            if arg:
                options['tag'] = arg
        elif opt == '-T':
            options['timeout'] = arg
        elif opt == '--version':
            print('pan-python', pan.wfapi.__version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if options['debug'] > 2:
        s = pprint.pformat(options, indent=4)
        print(s, file=sys.stderr)

    return options


def create_ssl_context(cafile, capath, ssl_option):
    # PEP 0476
    if (sys.version_info.major == 2 and sys.hexversion >= 0x02070900 or
            sys.version_info.major == 3 and sys.hexversion >= 0x03040300):
        if cafile or capath:
            try:
                ssl_context = ssl.create_default_context(
                    purpose=ssl.Purpose.SERVER_AUTH,
                    cafile=cafile,
                    capath=capath)
            except Exception as e:
                print('cafile or capath invalid: %s' % e, file=sys.stderr)
                sys.exit(1)
        elif ssl_option:
            if ssl_option == 'cacloud':
                ssl_context = pan.wfapi.cloud_ssl_context()
            elif ssl_option == 'noverify':
                ssl_context = ssl._create_unverified_context()
            elif ssl_option == 'default':
                ssl_context = None

        return ssl_context

    print('Warning: Python %d.%d.%d: cafile, capath and ssl ignored' %
          (sys.version_info.major, sys.version_info.minor,
           sys.version_info.micro), file=sys.stderr)

    return None


def print_status(wfapi, action, exception_msg=None):
    print(action, end='', file=sys.stderr)

    if exception_msg is not None:
        print(': %s' % exception_msg, end='', file=sys.stderr)
    else:
        if wfapi.http_code is not None:
            print(': %s' % wfapi.http_code, end='', file=sys.stderr)
        if wfapi.http_reason is not None:
            print(' %s' % wfapi.http_reason, end='', file=sys.stderr)

    print(' [', end='', file=sys.stderr)
    if wfapi.attachment is not None:
        print('attachment="%s"' % wfapi.attachment['filename'], end='',
              file=sys.stderr)
    else:
        body = True if wfapi.response_body is not None else False
        print('response_body=%s' % body, end='', file=sys.stderr)
        if wfapi.response_type is not None:
            print(' response_type=%s' % wfapi.response_type, end='',
                  file=sys.stderr)
        if body:
            print(' length=%d' % len(wfapi.response_body), end='',
                  file=sys.stderr)
    print(']', end='', file=sys.stderr)

    print(file=sys.stderr)


def print_response(wfapi, options):
    if wfapi.response_type is 'html' and wfapi.response_body is not None:
        if options['print_html']:
            print(wfapi.response_body.rstrip())

    elif wfapi.response_type is 'xml' and wfapi.response_body is not None:
        if options['print_xml']:
            print(wfapi.response_body.rstrip())

        if options['print_python'] or options['print_json']:
            if wfapi.xml_element_root is None:
                return

            elem = wfapi.xml_element_root
            tags_forcelist = set(['entry'])

            try:
                conf = pan.config.PanConfig(config=elem,
                                            tags_forcelist=tags_forcelist)
            except pan.config.PanConfigError as msg:
                print('pan.config.PanConfigError:', msg, file=sys.stderr)
                sys.exit(1)

            d = conf.python()

            if d:
                if options['print_python']:
                    print('var1 =', pprint.pformat(d))
                if options['print_json']:
                    print(json.dumps(d, sort_keys=True, indent=2))


def save_file(wfapi, options):
    if wfapi.attachment is None:
        return

    if options['dst'] is not None:
        path = options['dst']
        if os.path.isdir(path):
            path = os.path.join(path, wfapi.attachment['filename'])
    else:
        path = wfapi.attachment['filename']

    try:
        f = open(path, 'wb')
    except IOError as msg:
        print('open %s: %s' % (path, msg), file=sys.stderr)
        return

    try:
        f.write(wfapi.attachment['content'])
    except IOError as msg:
        print('write %s: %s' % (path, msg), file=sys.stderr)
        f.close()
        return

    f.close()
    print('saved %s' % path, file=sys.stderr)


def set_encoding():
    #
    # XXX UTF-8 won't encode to latin-1/ISO8859-1:
    #   UnicodeEncodeError: 'latin-1' codec can't encode character '\u2019'
    #
    # do PYTHONIOENCODING=utf8 equivalent
    #
    encoding = 'utf-8'

    if hasattr(sys.stdin, 'detach'):
        # >= 3.1
        import io

        for s in ('stdin', 'stdout', 'stderr'):
            line_buffering = getattr(sys, s).line_buffering
#            print(s, line_buffering, file=sys.stderr)
            setattr(sys, s, io.TextIOWrapper(getattr(sys, s).detach(),
                                             encoding=encoding,
                                             line_buffering=line_buffering))

    else:
        import codecs

        sys.stdin = codecs.getreader(encoding)(sys.stdin)
        sys.stdout = codecs.getwriter(encoding)(sys.stdout)
        sys.stderr = codecs.getwriter(encoding)(sys.stderr)


def usage():
    usage = '''%s [options]
    --submit path|url     submit file or URL to WildFire for analysis
    --submit-link link    submit links to WildFire for analysis
    --change-request      request review of sample's verdict
    --report              get WildFire report
    --verdict             get WildFire sample verdict
    --sample              get WildFire sample file
    --pcap                get WildFire PCAP files
    --changed             get changed verdicts
    --hash hash           query MD5 or SHA256 hash
    --platform id         platform ID for sandbox environment
    --new-verdict verdict benign|malware|grayware
    --email address       notification e-mail address
    --comment comment     change request explanation
    --testfile            get sample malware test file
    --format format       report output format
    --date date           start date for changed verdicts
                          (YYYY-MM-DD or -days)
    --dst dst             save file to directory or path
    -K api_key            WildFire API key
    -h hostname           WildFire hostname
    -x                    print XML response to stdout
    -p                    print XML response in Python to stdout
    -j                    print XML response in JSON to stdout
    -D                    enable debug (multiple up to -DDD)
    -t tag                .panrc tagname
    -T seconds            urlopen() timeout
    --http                use http URL scheme (default https)
    --ssl opt             SSL verify option: default|noverify
    --cafile path         file containing CA certificates
    --capath path         directory of hashed certificate files
    --version             display version
    --help                display usage
'''
    print(usage % os.path.basename(sys.argv[0]), end='')

if __name__ == '__main__':
    main()

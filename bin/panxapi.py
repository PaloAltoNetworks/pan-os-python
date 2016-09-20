#!/usr/bin/env python

#
# Copyright (c) 2013-2015 Kevin Steves <kevin.steves@pobox.com>
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
from datetime import datetime
import sys
import os
import getopt
import re
import json
import pprint
import logging
import ssl
import signal

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.xapi
import pan.commit
import pan.config

debug = 0


def main():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        # Windows
        pass

    set_encoding()
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(pan.xapi.DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(pan.xapi.DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(pan.xapi.DEBUG1)

#        log_format = '%(levelname)s %(name)s %(message)s'
        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if options['cafile'] or options['capath']:
        ssl_context = create_ssl_context(options['cafile'],
                                         options['capath'])
    else:
        ssl_context = None

    try:
        xapi = pan.xapi.PanXapi(timeout=options['timeout'],
                                tag=options['tag'],
                                use_http=options['use_http'],
                                use_get=options['use_get'],
                                api_username=options['api_username'],
                                api_password=options['api_password'],
                                api_key=options['api_key'],
                                hostname=options['hostname'],
                                port=options['port'],
                                serial=options['serial'],
                                ssl_context=ssl_context)

    except pan.xapi.PanXapiError as msg:
        print('pan.xapi.PanXapi:', msg, file=sys.stderr)
        sys.exit(1)

    if options['debug'] > 2:
        print('xapi.__str__()===>\n', xapi, '\n<===',
              sep='', file=sys.stderr)

    extra_qs_used = False

    try:
        if options['keygen']:
            action = 'keygen'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.keygen(extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)
            if (options['api_username'] and options['api_password'] and
                    options['hostname'] and options['tag']):
                # .panrc
                d = datetime.now()
                print('# %s generated: %s' % (os.path.basename(sys.argv[0]),
                                              d.strftime('%Y/%m/%d %H:%M:%S')))
                print('hostname%%%s=%s' % (options['tag'],
                                           options['hostname']))
                print('api_key%%%s=%s' % (options['tag'], xapi.api_key))
            else:
                print('API key:  "%s"' % xapi.api_key)

        if options['show']:
            action = 'show'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.show(xpath=options['xpath'],
                      extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['get']:
            action = 'get'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.get(xpath=options['xpath'],
                     extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['delete']:
            action = 'delete'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.delete(xpath=options['xpath'],
                        extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['edit']:
            action = 'edit'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.edit(xpath=options['xpath'],
                      element=options['element'],
                      extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['set']:
            action = 'set'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.set(xpath=options['xpath'],
                     element=options['element'],
                     extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['dynamic-update']:
            action = 'dynamic-update'
            kwargs = {
                'cmd': options['cmd'],
                }
            if options['ad_hoc'] is not None:
                extra_qs_used = True
                kwargs['extra_qs'] = options['ad_hoc']
            if len(options['vsys']):
                kwargs['vsys'] = options['vsys'][0]
            xapi.user_id(**kwargs)
            print_status(xapi, action)
            print_response(xapi, options)

        if options['move'] is not None:
            action = 'move'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.move(xpath=options['xpath'],
                      where=options['move'],
                      dst=options['dst'],
                      extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['rename']:
            action = 'rename'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.rename(xpath=options['xpath'],
                        newname=options['dst'],
                        extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['clone']:
            action = 'clone'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.clone(xpath=options['xpath'],
                       xpath_from=options['src'],
                       newname=options['dst'],
                       extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['override']:
            action = 'override'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.override(xpath=options['xpath'],
                          element=options['element'],
                          extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['export'] is not None:
            action = 'export'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            if options['pcapid'] is not None:
                xapi.export(category=options['export'],
                            pcapid=options['pcapid'],
                            search_time=options['stime'],
                            serialno=options['serial'],
                            extra_qs=options['ad_hoc'])
            else:
                xapi.export(category=options['export'],
                            from_name=options['src'],
                            extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)
            if options['pcap_listing']:
                pcap_listing(xapi, options['export'])
            save_attachment(xapi, options)

        if options['log'] is not None:
            action = 'log'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            xapi.log(log_type=options['log'],
                     nlogs=options['nlogs'],
                     skip=options['skip'],
                     filter=options['filter'],
                     interval=options['interval'],
                     timeout=options['job_timeout'],
                     extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['report'] is not None:
            action = 'report'
            if options['ad_hoc'] is not None:
                extra_qs_used = True
            vsys = options['vsys'][0] if len(options['vsys']) else None
            xapi.report(reporttype=options['report'],
                        reportname=options['name'],
                        vsys=vsys,
                        interval=options['interval'],
                        timeout=options['job_timeout'],
                        extra_qs=options['ad_hoc'])
            print_status(xapi, action)
            print_response(xapi, options)

        if options['op'] is not None:
            action = 'op'
            kwargs = {
                'cmd': options['op'],
                'cmd_xml': options['cmd_xml'],
                }
            if options['ad_hoc'] is not None:
                extra_qs_used = True
                kwargs['extra_qs'] = options['ad_hoc']
            if len(options['vsys']):
                kwargs['vsys'] = options['vsys'][0]
            xapi.op(**kwargs)
            print_status(xapi, action)
            print_response(xapi, options)

        if (options['commit'] or options['commit_all']):
            if options['cmd']:
                cmd = options['cmd']
                if options['cmd_xml']:
                    cmd = xapi.cmd_xml(cmd)
            else:
                c = pan.commit.PanCommit(validate=options['validate'],
                                         force=options['force'],
                                         commit_all=options['commit_all'],
                                         merge_with_candidate=
                                         options['merge'])

                for part in options['partial']:
                    if part == 'device-and-network-excluded':
                        c.device_and_network_excluded()
                    elif part == 'policy-and-objects-excluded':
                        c.policy_and_objects_excluded()
                    elif part == 'shared-object-excluded':
                        c.shared_object_excluded()
                    elif part == 'no-vsys':
                        c.no_vsys()
                    elif part == 'vsys':
                        c.vsys(options['vsys'])

                if options['serial'] is not None:
                    c.device(options['serial'])
                if options['group'] is not None:
                    c.device_group(options['group'])
                if options['commit_all'] and options['vsys']:
                    c.vsys(options['vsys'][0])

                cmd = c.cmd()

            kwargs = {
                'cmd': cmd,
                'sync': options['sync'],
                'interval': options['interval'],
                'timeout': options['job_timeout'],
                }
            if options['ad_hoc'] is not None:
                extra_qs_used = True
                kwargs['extra_qs'] = options['ad_hoc']
            if options['commit_all']:
                kwargs['action'] = 'all'

            action = 'commit'
            xapi.commit(**kwargs)
            print_status(xapi, action)
            print_response(xapi, options)

        if not extra_qs_used and options['ad_hoc'] is not None:
            action = 'ad_hoc'
            xapi.ad_hoc(qs=options['ad_hoc'],
                        xpath=options['xpath'],
                        modify_qs=options['modify'])
            print_status(xapi, action)
            print_response(xapi, options)

    except pan.xapi.PanXapiError as msg:
        print_status(xapi, action, str(msg))
        print_response(xapi, options)
        sys.exit(1)

    sys.exit(0)


def passwd_prompt():
    import getpass

    try:
        x = getpass.getpass('Password: ')
    except EOFError:
        return None
    except KeyboardInterrupt:
        sys.exit(0)

    return x


def parse_opts():
    options = {
        'delete': False,
        'edit': False,
        'get': False,
        'keygen': False,
        'show': False,
        'set': False,
        'dynamic-update': False,
        'commit': False,
        'validate': False,
        'force': False,
        'partial': [],
        'sync': False,
        'vsys': [],
        'commit_all': False,
        'ad_hoc': None,
        'modify': False,
        'op': None,
        'export': None,
        'log': None,
        'report': None,
        'name': None,
        'src': None,
        'dst': None,
        'move': None,
        'rename': False,
        'clone': False,
        'override': False,
        'api_username': None,
        'api_password': None,
        'hostname': None,
        'port': None,
        'serial': None,
        'group': None,
        'merge': False,
        'nlogs': None,
        'skip': None,
        'filter': None,
        'interval': None,
        'job_timeout': None,
        'stime': None,
        'pcapid': None,
        'api_key': None,
        'cafile': None,
        'capath': None,
        'print_xml': False,
        'print_result': False,
        'print_python': False,
        'print_json': False,
        'print_text': False,
        'cmd_xml': False,
        'pcap_listing': False,
        'recursive': False,
        'use_http': False,
        'use_get': False,
        'debug': 0,
        'tag': None,
        'xpath': None,
        'element': None,
        'cmd': None,
        'timeout': None,
        }

    valid_where = ['after', 'before', 'top', 'bottom']

    short_options = 'de:gksS:U:C:A:o:l:h:P:K:xpjrXHGDt:T:'
    long_options = ['version', 'help',
                    'ad-hoc=', 'modify', 'validate', 'force', 'partial=',
                    'sync', 'vsys=', 'src=', 'dst=', 'move=', 'rename',
                    'clone', 'override=', 'export=', 'log=', 'recursive',
                    'cafile=', 'capath=', 'ls', 'serial=',
                    'group=', 'merge', 'nlogs=', 'skip=', 'filter=',
                    'interval=', 'timeout=',
                    'stime=', 'pcapid=', 'text',
                    'report=', 'name=',
                    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-d':
            options['delete'] = True
        elif opt == '-e':
            options['edit'] = True
            options['element'] = get_element(arg)
        elif opt == '-g':
            options['get'] = True
        elif opt == '-k':
            options['keygen'] = True
        elif opt == '-s':
            options['show'] = True
        elif opt == '-S':
            options['set'] = True
            options['element'] = get_element(arg)
        elif opt == '-U':
            options['dynamic-update'] = True
            options['cmd'] = get_element(arg)
        elif opt == '-C':
            options['commit'] = True
            options['cmd'] = get_element(arg)
        elif opt == '--validate':
            options['validate'] = True
        elif opt == '--force':
            options['force'] = True
        elif opt == '--partial':
            if arg:
                l = get_parts(arg)
                [options['partial'].append(s) for s in l]
        elif opt == '--sync':
            options['sync'] = True
        elif opt == '--vsys':
            if arg:
                l = get_vsys(arg)
                [options['vsys'].append(s) for s in l]
        elif opt == '-A':
            options['commit_all'] = True
            options['cmd'] = get_element(arg)
        elif opt == '--ad-hoc':
            options['ad_hoc'] = arg
        elif opt == '--modify':
            options['modify'] = True
        elif opt == '-o':
            options['op'] = get_element(arg)
        elif opt == '--export':
            options['export'] = arg
        elif opt == '--log':
            options['log'] = arg
        elif opt == '--report':
            options['report'] = arg
        elif opt == '--name':
            options['name'] = arg
        elif opt == '--src':
            options['src'] = arg
        elif opt == '--dst':
            options['dst'] = arg
        elif opt == '--move':
            if arg not in valid_where:
                print('Invalid where: "%s"' % arg, file=sys.stderr)
                sys.exit(1)
            options['move'] = arg
        elif opt == '--rename':
            options['rename'] = True
        elif opt == '--clone':
            options['clone'] = True
        elif opt == '--override':
            options['override'] = True
            options['element'] = get_element(arg)
        elif opt == '-l':
            try:
                (options['api_username'],
                 options['api_password']) = arg.split(':', 1)
            except ValueError:
                options['api_username'] = arg
                options['api_password'] = passwd_prompt()
        elif opt == '-P':
            options['port'] = arg
        elif opt == '--serial':
            options['serial'] = arg
        elif opt == '--group':
            options['group'] = arg
        elif opt == '--merge':
            options['merge'] = True
        elif opt == '--nlogs':
            options['nlogs'] = arg
        elif opt == '--skip':
            options['skip'] = arg
        elif opt == '--filter':
            options['filter'] = arg
        elif opt == '--interval':
            options['interval'] = arg
        elif opt == '--timeout':
            options['job_timeout'] = arg
        elif opt == '--stime':
            options['stime'] = arg
        elif opt == '--pcapid':
            options['pcapid'] = arg
        elif opt == '-h':
            options['hostname'] = arg
        elif opt == '-K':
            options['api_key'] = arg
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
        elif opt == '-r':
            options['print_result'] = True
        elif opt == '--text':
            options['print_text'] = True
        elif opt == '-X':
            options['cmd_xml'] = True
        elif opt == '--ls':
            options['pcap_listing'] = True
        elif opt == '--recursive':
            options['recursive'] = True
        elif opt == '-H':
            options['use_http'] = True
        elif opt == '-G':
            options['use_get'] = True
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
            print('pan-python', pan.xapi.__version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if len(args) > 0:
        s = get_element(args.pop(0))
        options['xpath'] = s.rstrip('\r\n')
        if len(args) > 0:
            print('Extra options after xpath:', args, file=sys.stderr)

    if options['debug'] > 2:
        s = pprint.pformat(options, indent=4)
        print(s, file=sys.stderr)

    if options['print_result'] and not (options['print_xml'] or
                                        options['print_json'] or
                                        options['print_python']):
        options['print_xml'] = True

    return options


def create_ssl_context(cafile, capath):
    if (sys.version_info.major == 2 and sys.hexversion >= 0x02070900 or
            sys.version_info.major == 3 and sys.hexversion >= 0x03020000):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.verify_mode = ssl.CERT_REQUIRED
        # added 3.4
        if hasattr(context, 'check_hostname'):
            context.check_hostname = True
        try:
            context.load_verify_locations(cafile=cafile, capath=capath)
        except Exception as e:
            print('cafile or capath invalid: %s' % e, file=sys.stderr)
            sys.exit(1)

        return context

    print('Warning: Python %d.%d: cafile and capath ignored' %
          (sys.version_info.major, sys.version_info.minor),
          file=sys.stderr)

    return None


def get_vsys(s):
    list = []
    vsys = s.split(',')
    for v in vsys:
        if v:
            if v.isdigit():
                list.append('vsys' + v)
            else:
                list.append(v)
    return list


def get_parts(s):
    list = []
    parts = s.split(',')
    for part in parts:
        if part:
            if not pan.commit.valid_part(part):
                print('Invalid part: "%s"' % part, file=sys.stderr)
                sys.exit(1)
            list.append(part)
    return list


def get_element(s):
    stdin_char = '-'

    if s == stdin_char:
        element = sys.stdin.readlines()
    elif os.path.isfile(s):
        try:
            f = open(s)
        except IOError as msg:
            print('open %s: %s' % (s, msg), file=sys.stderr)
            sys.exit(1)
        element = f.readlines()
        f.close()
    else:
        element = s

    element = ''.join(element)
    if debug > 1:
        print('element: \"%s\"' % element, file=sys.stderr)

    return element


def print_status(xapi, action, exception_msg=None):
    print(action, end='', file=sys.stderr)
    if xapi.status_code is not None:
        code = ' [code=\"%s\"]' % xapi.status_code
    else:
        code = ''
    if xapi.status is not None:
        print(': %s%s' % (xapi.status, code), end='', file=sys.stderr)
    if exception_msg is not None and exception_msg:
        print(': "%s"' % exception_msg.rstrip(), end='', file=sys.stderr)
    elif xapi.status_detail is not None:
        print(': "%s"' % xapi.status_detail.rstrip(), end='', file=sys.stderr)
    print(file=sys.stderr)


def xml_python(xapi, result=False):
    xpath = None
    if result:
        if (xapi.element_result is None or
                not len(xapi.element_result)):
            return None
        elem = xapi.element_result
        # select all child elements
        xpath = '*'
    else:
        if xapi.element_root is None:
            return None
        elem = xapi.element_root

    try:
        conf = pan.config.PanConfig(config=elem)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    d = conf.python(xpath)
    return d


def print_response(xapi, options):
    if options['print_xml']:
        if options['print_result']:
            s = xapi.xml_result()
        else:
            s = xapi.xml_root()
        if s is not None:
            print(s.lstrip('\r\n').rstrip())

    if options['print_python'] or options['print_json']:
        d = xml_python(xapi, options['print_result'])
        if d:
            if options['print_python']:
                print('var1 =', pprint.pformat(d))
            if options['print_json']:
                print(json.dumps(d, sort_keys=True, indent=2))

    if options['print_text'] and xapi.text_document is not None:
        print(xapi.text_document, end='')


def save_attachment(xapi, options):
    if xapi.export_result is None:
        return

    if options['src'] is not None:
        # pcap
        src_dir, src_file = os.path.split(options['src'])
    else:
        # 6.0 threat-pcap
        # device-state
        src_dir = None
        src_file = xapi.export_result['file']

    path = ''
    path_done = False

    if options['dst'] is not None:
        path = options['dst']
        if not os.path.isdir(path):
            path_done = True

    if not path_done:
        if (options['recursive'] and src_dir and
                re.search(r'^\d{8,8}$', src_dir)):
            path = os.path.join(path, src_dir)
            if not os.path.isdir(path):
                try:
                    os.mkdir(path)
                except OSError as msg:
                    print('mkdir %s: %s' % (path, msg),
                          file=sys.stderr)
                    # fallthrough, return on open fail
        path = os.path.join(path, src_file)

    try:
        f = open(path, 'wb')
    except IOError as msg:
        print('open %s: %s' % (path, msg), file=sys.stderr)
        return

    try:
        f.write(xapi.export_result['content'])
    except IOError as msg:
        print('write %s: %s' % (path, msg), file=sys.stderr)
        f.close()
        return

    f.close()
    print('exported %s: %s' % (xapi.export_result['category'], path),
          file=sys.stderr)


def pcap_listing(xapi, category):
    d = xml_python(xapi, result=True)

    if d and 'dir-listing' in d:
        pcap_listing = d['dir-listing']
        if pcap_listing is None:
            print('No %s directories' % category)
        elif 'file' in pcap_listing:
            file = pcap_listing['file']
            if isinstance(file, str):
                file = [file]
            size = len(file)
            print('%d %s files:' % (size, category))
            for item in sorted(file):
                print('    %s' % item)
        elif 'dir' in pcap_listing:
            dir = pcap_listing['dir']
            if isinstance(dir, str):
                dir = [dir]
            size = len(dir)
            print('%d %s directories:' % (size, category))
            for item in sorted(dir):
                print('    %s/' % item)


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
    usage = '''%s [options] [xpath]
    -d                    delete object at xpath
    -e element            edit XML element at xpath
    -g                    get candidate config at xpath
    -k                    generate API key
    -s                    show active config at xpath
    -S element            set XML element at xpath
    -U cmd                execute dynamic update command
    -C cmd                commit candidate configuration
    --validate            validate candidate configuration
    --force               force commit when conflict
    --partial part        commit specified part
    --sync                synchronous commit
    -A cmd                commit-all (Panorama)
    --ad-hoc query        perform ad hoc request
    --modify              insert known fields in ad hoc query
    -o cmd                execute operational command
    --export category     export files
    --log log-type        retrieve log files
    --report report-type  retrieve reports (dynamic|predefined|custom)
    --name report-name    report name
    --src src             clone source node xpath
                          export source file/path/directory
    --dst dst             move/clone destination node name
                          rename new name
                          export destination file/path/directory
    --move where          move after, before, bottom or top
    --rename              rename object at xpath to dst
    --clone               clone object at xpath, src xpath
    --override element    override template object at xpath
    --vsys vsys           VSYS for dynamic update/partial commit/
                          operational command/report
    -l api_username[:api_password]
    -h hostname
    -P port               URL port number
    --serial number       serial number for Panorama redirection/
                          commit-all/threat-pcap
    --group name          device group for commit-all
    --merge               merge with candidate for commit-all
    --nlogs num           retrieve num logs
    --skip num            skip num logs
    --filter filter       log selection filter
    --interval seconds    log/commit/report job query interval
    --timeout seconds     log/commit/report job query timeout
    --stime time          search time for threat-pcap
    --pcapid id           threat-pcap ID
    -K api_key
    -x                    print XML response to stdout
    -p                    print XML response in Python to stdout
    -j                    print XML response in JSON to stdout
    -r                    print result content when printing response
    --text                print text response to stdout
    -X                    convert text command to XML
    --ls                  print formatted PCAP listing to stdout
    --recursive           recursive export
    -H                    use http URL scheme (default https)
    -G                    use HTTP GET method (default POST)
    -D                    enable debug (multiple up to -DDD)
    -t tag                .panrc tagname
    -T seconds            urlopen() timeout
    --cafile path         file containing CA certificates
    --capath path         directory of hashed certificate files
    --version             display version
    --help                display usage
'''
    print(usage % os.path.basename(sys.argv[0]), end='')

if __name__ == '__main__':
    main()

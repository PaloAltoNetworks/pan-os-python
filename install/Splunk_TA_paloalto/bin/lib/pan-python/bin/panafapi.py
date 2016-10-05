#!/usr/bin/env python

#
# Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
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
import datetime
import getopt
import json
import logging
import os
import pprint
import sys

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.afapi

debug = 0


def main():
    options = parse_opts()

    if options['debug']:
        logger = logging.getLogger()
        if options['debug'] == 3:
            logger.setLevel(pan.afapi.DEBUG3)
        elif options['debug'] == 2:
            logger.setLevel(pan.afapi.DEBUG2)
        elif options['debug'] == 1:
            logger.setLevel(pan.afapi.DEBUG1)

        log_format = '%(message)s'
        handler = logging.StreamHandler()
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    try:
        afapi = pan.afapi.PanAFapi(panrc_tag=options['panrc_tag'],
                                   api_key=options['api_key'],
                                   api_version=options['api_version'],
                                   hostname=options['hostname'],
                                   timeout=options['timeout'],
                                   verify_cert=options['ssl'])

    except pan.afapi.PanAFapiError as e:
        print('pan.afapi.PanAFapi:', e, file=sys.stderr)
        sys.exit(1)

    if options['json_request'] is None:
        options['json_request'] = '{}'
        options['json_request_obj'] = {}

    if False:
        pass

    elif options['export']:
        export(afapi, options)

    elif options['sample_analysis']:
        sample_analysis(afapi, options)

    elif options['samples']:
        search_results(afapi, options,
                       afapi.samples_search_results)

    elif options['sessions'] and options['histogram']:
        search_results(afapi, options,
                       afapi.sessions_histogram_search_results)

    elif options['sessions'] and options['aggregate']:
        search_results(afapi, options,
                       afapi.sessions_aggregate_search_results)

    elif options['sessions']:
        search_results(afapi, options,
                       afapi.sessions_search_results)

    elif options['session'] is not None:
        session(afapi, options)

    elif options['top_tags']:
        search_results(afapi, options,
                       afapi.top_tags_search_results)

    elif options['tags']:
        tags(afapi, options)

    elif options['tag'] is not None:
        tag(afapi, options)

    sys.exit(0)


def export(afapi, options):
    try:
        action = 'export'
        r = afapi.export(data=options['json_request'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)


def sample_analysis(afapi, options):
    try:
        action = 'sample-analysis'
        r = afapi.sample_analysis(data=options['json_request'],
                                  sampleid=options['hash'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)


def tag(afapi, options):
    try:
        action = 'tag'
        r = afapi.tag(tagname=options['tag'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)


def tags(afapi, options):
    try:
        action = 'tags'
        query = {}

        request = options['json_request']
        try:
            obj = json.loads(request)
            if options['num_results'] is not None:
                obj['pageSize'] = options['num_results']
            if options['scope'] is not None:
                obj['scope'] = options['scope']
            request = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        r = afapi.tags(data=request)

        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)


def session(afapi, options):
    try:
        action = 'session'
        r = afapi.session(sessionid=options['session'])
        print_status(action, r)
        print_response(r, options)
        exit_for_http_status(r)

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)


def search_results(afapi,
                   options,
                   search):
    request = options['json_request']

    if options['num_results'] is not None:
        try:
            obj = json.loads(request)
            obj['size'] = options['num_results']
            request = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    if options['scope'] is not None:
        try:
            obj = json.loads(request)
            obj['scope'] = options['scope']
            request = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    try:
        for r in search(data=request, terminal=options['terminal']):
            print_status(r.name, r)
            if debug > 2:
                print_response(r, options)
        if debug <= 2:
            print_response(r, options)

    except pan.afapi.PanAFapiError as e:
        print_exception(search.__name__, e)
        sys.exit(1)


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

    if r.json is not None:
        if 'message' in r.json:
            print(' "%s"' % r.json['message'],
                  end='', file=sys.stderr)

        if 'af_complete_percentage' in r.json:
            print(' %s%%' % r.json['af_complete_percentage'],
                  end='', file=sys.stderr)

        if 'hits' in r.json:
            hits = len(r.json['hits'])
            print(' hits=%d' % hits, end='', file=sys.stderr)
        elif 'tags' in r.json:
            print(' tags=%d' % len(r.json['tags']),
                  end='', file=sys.stderr)
        elif 'top_tags' in r.json:
            print(' top_tags=%d' % len(r.json['top_tags']),
                  end='', file=sys.stderr)
        elif 'export_list' in r.json:
            print(' export_list=%d' % len(r.json['export_list']),
                  end='', file=sys.stderr)

        if 'total' in r.json:
            print(' total=%d' % r.json['total'],
                  end='', file=sys.stderr)
        elif 'total_count' in r.json:
            print(' total_count=%d' % r.json['total_count'],
                  end='', file=sys.stderr)

        if 'took' in r.json and r.json['took'] is not None:
            d = datetime.timedelta(milliseconds=r.json['took'])
            print(' time=%s' % str(d)[:-3],
                  end='', file=sys.stderr)

        if 'af_message' in r.json:
            print(' "%s"' % r.json['af_message'],
                  end='', file=sys.stderr)

    print(file=sys.stderr)


def print_response(r, options):
    if r.http_text is None:
        return

    if r.http_headers is not None:
        x = r.http_headers.get('content-type')
        if x is None:
            return

    if x.startswith('text/html'):
        # XXX
        print(r.http_text)

    elif x.startswith('application/json'):
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

    print(pprint.pformat(obj, indent=4))


def print_json(obj, isjson=False):
    if isjson:
        try:
            obj = json.loads(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            print(obj, file=sys.stderr)
            sys.exit(1)

    print(json.dumps(obj, sort_keys=True, indent=4,
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
        'sessions': False,
        'aggregate': False,
        'histogram': False,
        'session': None,
        'samples': False,
        'sample_analysis': False,
        'top_tags': False,
        'tags': False,
        'tag': None,
        'export': False,
        'json_requests': [],
        'json_request': None,
        'json_request_obj': None,
        'num_results': None,
        'scope': None,
        'hash': None,
        'terminal': False,
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

    short_options = 'AHK:V:h:pjHDt:T:r:n:'
    long_options = [
        'sessions', 'session=', 'samples', 'sample-analysis',
        'top-tags', 'tags', 'tag=', 'export',
        'scope=', 'hash=', 'terminal',
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
        elif opt == '--sessions':
            options['sessions'] = True
        elif opt == '-A':
            options['aggregate'] = True
        elif opt == '-H':
            options['histogram'] = True
        elif opt == '--session':
            options['session'] = arg
        elif opt == '--samples':
            options['samples'] = True
        elif opt == '--sample-analysis':
            options['sample_analysis'] = True
        elif opt == '--top-tags':
            options['top_tags'] = True
        elif opt == '--tags':
            options['tags'] = True
        elif opt == '--tag':
            options['tag'] = arg
        elif opt == '--export':
            options['export'] = True
        elif opt == '-r':
            options['json_requests'].append(process_arg(arg))
        elif opt == '-n':
            try:
                options['num_results'] = int(arg)
            except ValueError:
                print('Invalid num:', arg, file=sys.stderr)
                sys.exit(1)
        elif opt == '--scope':
            options['scope'] = arg
        elif opt == '--hash':
            x = process_arg(arg)
            options['hash'] = x.rstrip('\r\n')
        elif opt == '--terminal':
            options['terminal'] = True
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
            print('pan-python', pan.afapi.__version__)
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if options['json_requests']:
        obj = {}
        for r in options['json_requests']:
            try:
                x = json.loads(r)
            except ValueError as e:
                print('%s: %s' % (e, r), file=sys.stderr)
                sys.exit(1)
            obj.update(x)

        try:
            options['json_request'] = json.dumps(obj)
            options['json_request_obj'] = obj
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    if options['debug'] > 2:
        s = pprint.pformat(options, indent=4)
        print(s, file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
    --sessions            search AutoFocus sessions
    -A                    get aggregate of sessions
    -H                    get histogram of sessions
    --session id          get AutoFocus session
    --samples             search AutoFocus samples
    --sample-analysis     get AutoFocus sample analysis report
    --top-tags            search AutoFocus top tags
    --tags                search AutoFocus tags
    --tag name            get AutoFocus tag
    --export              export AutoFocus list
    -r json               JSON API request (multiple -r's allowed)
    -n num                request num results
    --scope scope         search scope
    --hash hash           sample hash
    --terminal            get only final search result
    -t tag                .panrc tagname
    -K api_key            AutoFocus API key
    -V api_version        AutoFocus API version (default %s)
    -h hostname           AutoFocus hostname
    -p                    print response in Python to stdout
    -j                    print response in JSON to stdout
    -D                    enable debug (multiple up to -DDD)
    --ssl opt             SSL verify option: verify|noverify
    -T seconds            HTTP connect timeout
    --version             display version
    --help                display usage
'''
    print(usage % (os.path.basename(sys.argv[0]),
          pan.afapi.DEFAULT_API_VERSION), end='')

if __name__ == '__main__':
    main()

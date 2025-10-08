# call this via "python[3] script name"
import argparse
import json
import os
import zlib
import base64
import random
import time

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer # Python 2
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer # Python 3

# Keep track of data received at each path
data = {}

metadata = {
    'posts': 0,
    'fail_after': 0,
    'fail_every': -1,
    'decompress': False,
    'userpwd': '',
    'validate_hec': False,
    'hec_validation_error_code': 400,
    'hec_validation_error_message': 'invalid HEC payload',
    'hec_fail_after': -1,
    'hec_fail_every': -1,
    'hec_fail_message': 'simulated HEC format error',
}


try:
    JSONDecodeError = json.JSONDecodeError
except AttributeError:  # pragma: no cover - python2 compatibility
    JSONDecodeError = ValueError

try:
    basestring
except NameError:  # pragma: no cover - python3 compatibility
    basestring = (str, bytes)


def _extract_msgnums_from_obj(obj, msgnums):
    """Helper to recursively gather msgnum values from nested payloads."""
    if isinstance(obj, dict):
        if 'msgnum' in obj:
            msgnums.append(obj['msgnum'])
        if 'value' in obj:
            _extract_msgnums_from_obj(obj['value'], msgnums)
        if 'streams' in obj and isinstance(obj['streams'], list):
            for item in obj['streams']:
                _extract_msgnums_from_obj(item, msgnums)
        if 'records' in obj and isinstance(obj['records'], list):
            for item in obj['records']:
                _extract_msgnums_from_obj(item, msgnums)
        if 'event' in obj:
            event_obj = obj['event']
            if isinstance(event_obj, basestring):  # type: ignore[name-defined]
                try:
                    event_obj = json.loads(event_obj)
                except (ValueError, TypeError):
                    event_obj = None
            _extract_msgnums_from_obj(event_obj, msgnums)
    elif isinstance(obj, list):
        for item in obj:
            _extract_msgnums_from_obj(item, msgnums)


def extract_msgnums(raw_data):
    msgnums = []
    try:
        parsed = json.loads(raw_data)
    except (ValueError, TypeError):
        for line in raw_data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed_line = json.loads(line)
            except (ValueError, TypeError):
                continue
            _extract_msgnums_from_obj(parsed_line, msgnums)
    else:
        _extract_msgnums_from_obj(parsed, msgnums)
    return msgnums


def validate_hec_payload(raw_data):
    summary = {'msgnums': []}
    events = []
    try:
        payload = json.loads(raw_data)
    except (ValueError, TypeError, JSONDecodeError):
        payload = None

    decoded_entries = []

    if isinstance(payload, dict):
        decoded_entries = [payload]
    elif isinstance(payload, list):
        decoded_entries = payload
    else:
        decoded_entries = []

    if not decoded_entries:
        lines = [line.strip() for line in raw_data.split('\n') if line.strip()]
        for line in lines:
            try:
                decoded_entries.append(json.loads(line))
            except (ValueError, TypeError, JSONDecodeError):
                return False, 'invalid JSON payload for HEC validation', summary

    for entry in decoded_entries:
        if not isinstance(entry, dict):
            return False, 'HEC payload entries must be JSON objects', summary
        if 'event' not in entry:
            return False, 'HEC payload missing required "event" field', summary
        event_value = entry['event']
        events.append(entry)
        if isinstance(event_value, dict) and 'msgnum' in event_value:
            summary['msgnums'].append(event_value['msgnum'])
        elif isinstance(event_value, basestring):  # type: ignore[name-defined]
            try:
                event_json = json.loads(event_value)
                _extract_msgnums_from_obj(event_json, summary['msgnums'])
            except (ValueError, TypeError):
                pass
        elif isinstance(event_value, list):
            _extract_msgnums_from_obj(event_value, summary['msgnums'])

    summary['hec_events'] = events
    if not summary['msgnums']:
        summary['msgnums'] = extract_msgnums(raw_data)
    return True, '', summary


class MyHandler(BaseHTTPRequestHandler):
    """
    POST'd data is kept in the data global dict.
    Keys are the path, values are dictionaries containing the raw payload and
    extracted metadata. Two post requests to
    <host>:<port>/post/endpoint means data looks like...
        {"/post/endpoint": [
            {"raw": "{\\"msgnum\\":\\"00001\\"}", "summary": {"msgnums": ["00001"]}},
            {"raw": "{\\"msgnum\\":\\"00002\\"}", "summary": {"msgnums": ["00002"]}}
        ]}

    GET requests return all data posted to that endpoint as a json list of
    objects. Each object contains `raw` and `summary` keys so callers can select
    the representation they need. `summary` typically includes a `msgnums`
    array.
    """

    def validate_auth(self):
        # header format for basic authentication
        # 'Authorization: Basic <base 64 encoded uid:pwd>'
        if 'Authorization' not in self.headers:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'missing "Authorization" header')
            return False

        auth_header = self.headers['Authorization']
        _, b64userpwd = auth_header.split()
        userpwd = base64.b64decode(b64userpwd).decode('utf-8')
        if userpwd != metadata['userpwd']:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'invalid auth: {0}'.format(userpwd))
            return False

        return True

    def do_POST(self):
        metadata['posts'] += 1

        if metadata['userpwd']:
            if not self.validate_auth():
                return

        if metadata['fail_with_400_after'] != -1 and metadata['posts'] > metadata['fail_with_400_after']:
            if metadata['fail_with_delay_secs']:
                print("sleeping for: {0}".format(metadata['fail_with_delay_secs']))
                time.sleep(metadata['fail_with_delay_secs'])
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'BAD REQUEST')
            return

        if metadata['fail_with_401_or_403_after'] != -1 and metadata['posts'] > metadata['fail_with_401_or_403_after']:
            status = random.choice([401, 403])
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b'BAD REQUEST')
            return

        if metadata['posts'] > 1 and metadata['fail_every'] != -1 and metadata['posts'] % metadata['fail_every'] == 0:
            if metadata['fail_with_delay_secs']:
                print("sleeping for: {0}".format(metadata['fail_with_delay_secs']))
                time.sleep(metadata['fail_with_delay_secs'])
            code = metadata['fail_with'] if metadata['fail_with'] else 500
            self.send_response(code)
            self.end_headers()
            self.wfile.write(b'INTERNAL ERROR')
            return

        content_length = int(self.headers['Content-Length'] or 0)
        raw_data = self.rfile.read(content_length)

        if metadata['decompress']:
            post_data = zlib.decompress(raw_data, 31)
        else:
            post_data = raw_data

        decoded_payload = post_data.decode('utf-8')
        summary = {'msgnums': extract_msgnums(decoded_payload)}

        if metadata['validate_hec']:
            is_valid, reason, hec_summary = validate_hec_payload(decoded_payload)
            if not is_valid:
                validation_msg = metadata['hec_validation_error_message']
                if reason:
                    validation_msg = '{0}: {1}'.format(validation_msg, reason)
                self._send_hec_error(validation_msg)
                return
            summary.update(hec_summary)
            if self._should_fail_hec_injection():
                self._send_hec_error(metadata['hec_fail_message'])
                return

        if self.path not in data:
            data[self.path] = []
        data[self.path].append({'raw': decoded_payload, 'summary': summary})

        res = json.dumps({'msg': 'ok'}).encode('utf8')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(res))
        self.end_headers()

        self.wfile.write(res)
        return

    def _send_hec_error(self, message):
        try:
            code = int(metadata['hec_validation_error_code'])
        except (TypeError, ValueError):
            code = 400
        if code < 400 or code > 499:
            code = 400
        payload = json.dumps({'error': message}).encode('utf8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _should_fail_hec_injection(self):
        if not metadata['validate_hec']:
            return False
        posts = metadata['posts']
        fail_after = metadata.get('hec_fail_after', -1)
        fail_every = metadata.get('hec_fail_every', -1)
        if fail_after != -1 and posts > fail_after:
            return True
        if fail_every != -1 and posts > 0 and posts % fail_every == 0:
            return True
        return False

    def do_GET(self):
        if self.path in data:
            result = data[self.path]
        else:
            result = []

        res = json.dumps(result).encode('utf8')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(res))
        self.end_headers()

        self.wfile.write(res)
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Archive and delete core app log files')
    parser.add_argument('-p', '--port', action='store', type=int, default=8080, help='port')
    parser.add_argument('--port-file', action='store', type=str, default='', help='file to store listen port number')
    parser.add_argument('-i', '--interface', action='store', type=str, default='localhost', help='port')
    parser.add_argument('--fail-after', action='store', type=int, default=0, help='start failing after n posts')
    parser.add_argument('--fail-every', action='store', type=int, default=-1, help='fail every n posts')
    parser.add_argument('--fail-with', action='store', type=int, default=500, help='on failure, fail with this code')
    parser.add_argument('--fail-with-400-after', action='store', type=int, default=-1, help='fail with 400 after n posts')
    parser.add_argument('--fail-with-401-or-403-after', action='store', type=int, default=-1, help='fail with 401 or 403 after n posts')
    parser.add_argument('--fail-with-delay-secs', action='store', type=int, default=0, help='fail with n secs of delay')
    parser.add_argument('--decompress', action='store_true', default=False, help='decompress posted data')
    parser.add_argument('--userpwd', action='store', default='', help='only accept this user:password combination')
    parser.add_argument('--validate-hec', action='store_true', default=False, help='validate payloads as Splunk HEC events')
    parser.add_argument('--hec-validation-error-code', action='store', type=int, default=400, help='HTTP code for HEC validation failures')
    parser.add_argument('--hec-validation-error-message', action='store', default='invalid HEC payload', help='Message returned when HEC validation fails')
    parser.add_argument('--hec-fail-after', action='store', type=int, default=-1, help='after n posts, simulate HEC validation failure')
    parser.add_argument('--hec-fail-every', action='store', type=int, default=-1, help='every n posts, simulate HEC validation failure')
    parser.add_argument('--hec-fail-message', action='store', default='simulated HEC format error', help='error message for simulated HEC failures')
    args = parser.parse_args()
    metadata['fail_after'] = args.fail_after
    metadata['fail_every'] = args.fail_every
    metadata['fail_with'] = args.fail_with
    metadata['fail_with_400_after'] = args.fail_with_400_after
    metadata['fail_with_401_or_403_after'] = args.fail_with_401_or_403_after
    metadata['fail_with_delay_secs'] = args.fail_with_delay_secs
    metadata['decompress'] = args.decompress
    metadata['userpwd'] = args.userpwd
    metadata['validate_hec'] = args.validate_hec
    metadata['hec_validation_error_code'] = args.hec_validation_error_code
    metadata['hec_validation_error_message'] = args.hec_validation_error_message
    metadata['hec_fail_after'] = args.hec_fail_after
    metadata['hec_fail_every'] = args.hec_fail_every
    metadata['hec_fail_message'] = args.hec_fail_message
    server = HTTPServer((args.interface, args.port), MyHandler)
    lstn_port = server.server_address[1]
    pid = os.getpid()
    print('starting omhttp test server at {interface}:{port} with pid {pid}'
          .format(interface=args.interface, port=lstn_port, pid=pid))
    if args.port_file != '':
        f = open(args.port_file, "w")
        f.write(str(lstn_port))
        f.close()
    server.serve_forever()

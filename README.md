# Pacemaker
Attempts to abuse OpenSSL *clients* that are vulnerable to [Heartblead][0]
([CVE-2014-0160][1]). Compatible with Python 2 and 3.

## Am I vulnerable?
Run the server:

    python pacemaker.py

In your client, open https://localhost:4433/ (replace the hostname if needed).
For example:

    curl https://localhost:4433/

The client will always fail to connect:

    curl: (35) Unknown SSL protocol error in connection to localhost:4433

If you are not vulnerable, the server outputs something like:

    Connection from: 127.0.0.1:40736
    Possibly not vulnerable

If you *are* vulnerable, you will see something like:

    Connection from: 127.0.0.1:40738
    Client returned 16384 (0x4000) bytes
    0000: 18 03 03 40 00 02 40 00 2d 03 03 52 34 c6 6d 86  ...@..@.-..R4.m.
    0010: 8d e8 40 97 da ee 7e 21 c4 1d 2e 9f e9 60 5f 05  ..@...~!.....`_.
    0020: b0 ce af 7e b7 95 8c 33 42 3f d5 00 c0 30 00 00  ...~...3B?...0..
    0030: 05 00 0f 00 01 01 00 00 00 00 00 00 00 00 00 00  ................
    0040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    *

Note that there were 16 KiB of leaked bytes, the output moddeled after `xxd` and
replaces subsequent lines of NUL bytes with an `*`.

An example where more "interesting" memory gets leaked using
`wget -O /dev/null https://google.com https://localhost:4433`:

    Connection from: 127.0.0.1:41914
    Client returned 16384 (0x4000) bytes
    0000: 18 03 03 40 00 02 ff ff 2d 03 03 52 34 c6 6d 86  ...@....-..R4.m.
    0010: 8d e8 40 97 da ee 7e 21 c4 1d 2e 9f e9 60 5f 05  ..@...~!.....`_.
    0020: b0 ce af 7e b7 95 8c 33 42 3f d5 00 c0 30 00 00  ...~...3B?...0..
    0030: 05 00 0f 00 01 01 65 0d 0a 43 6f 6e 74 65 6e 74  ......e..Content
    0040: 2d 54 79 70 65 3a 20 74 65 78 74 2f 68 74 6d 6c  -Type: text/html
    0050: 3b 20 63 68 61 72 73 65 74 3d 55 54 46 2d 38 0d  ; charset=UTF-8.
    ...
    0b50: 01 05 05 07 02 01 16 2d 68 74 74 70 73 3a 2f 2f  .......-https://
    0b60: 77 77 77 2e 67 65 6f 74 72 75 73 74 2e 63 6f 6d  www.geotrust.com
    0b70: 2f 72 65 73 6f 75 72 63 65 73 2f 72 65 70 6f 73  /resources/repos
    0b80: 69 74 6f 72 79 30 0d 06 09 2a 86 48 86 f7 0d 01  itory0...*.H....
    0b90: 01 05 05 00 03 81 81 00 76 e1 12 6e 4e 4b 16 12  ........v..nNK..
    0ba0: 86 30 06 b2 81 08 cf f0 08 c7 c7 71 7e 66 ee c2  .0.........q~f..
    0bb0: ed d4 3b 1f ff f0 f0 c8 4e d6 43 38 b0 b9 30 7d  ..;.....N.C8..0}
    0bc0: 18 d0 55 83 a2 6a cb 36 11 9c e8 48 66 a3 6d 7f  ..U..j.6...Hf.m.
    0bd0: b8 13 d4 47 fe 8b 5a 5c 73 fc ae d9 1b 32 19 38  ...G..Z\s....2.8
    0be0: ab 97 34 14 aa 96 d2 eb a3 1c 14 08 49 b6 bb e5  ..4.........I...
    0bf0: 91 ef 83 36 eb 1d 56 6f ca da bc 73 63 90 e4 7f  ...6..Vo...sc...
    0c00: 7b 3e 22 cb 3d 07 ed 5f 38 74 9c e3 03 50 4e a1  {>".=.._8t...PN.
    0c10: af 98 ee 61 f2 84 3f 12 00 00 00 00 00 00 00 00  ...a..?.........
    0c20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    *

## Tested clients
The following clients have been tested against 1.0.1f and leaked memory before
the handshake:

 - MariaDB 5.5.36
 - wget 1.15 (leaks memory of earlier connections)
 - curl 7.36.0
 - git 1.9.1 (tested clone / push, 54 non-NUL bytes were leaked)
 - nginx 1.4.7 (in proxy mode, 54 non-NUL bytes were leaked)

# ssltest.py
This repository also contains a working version that targets servers. ssltest.py
was created by Jared Stafford (<jspenguin@jspenguin.org>), all due credits are
to him! It was retrieved from http://s3.jspenguin.org/ssltest.py.

At the moment, the script is only compatible with Python 2.

  [0]: http://heartbleed.com/
  [1]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160

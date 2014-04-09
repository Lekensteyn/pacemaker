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

Unfortunately, I was not able to get more useful bytes, it seem that the memory
is cleared. The same applies to `wget`. For now I have to conclude that clients
are not vulnerable in the same way as servers. It does open a DoS hole though.

# ssltest.py
This repository also contains a working version that targets servers. ssltest.py
was created by Jared Stafford (<jspenguin@jspenguin.org>), all due credits are
to him! It was retrieved from http://s3.jspenguin.org/ssltest.py.

At the moment, the script is only compatible with Python 2.

  [0]: http://heartbleed.com/
  [1]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160

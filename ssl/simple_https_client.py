#!/usr/bin/env python
from __future__ import print_function
import ssl
import socket

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('root.cert')
context.load_cert_chain('client.cert', keyfile='client.key')
#proxy = xmlrpcclient.ServerProxy('https://localhost:11311', context=context)
conn = context.wrap_socket(socket.socket(socket.AF_INET))
conn.connect(('localhost',12345))
print('connected')
data = conn.read()
print('read: [%s]' % data)

#!/usr/bin/env python
from __future__ import print_function
import os
import ssl
import socket

keydir = 'keys'
mode = 'good'
capath = os.path.join(keydir,mode,'public')
certfile = os.path.join(keydir,mode,'client','client.cert')
keyfile = os.path.join(keydir,mode,'client','client.pem')

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(capath=capath)
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

conn = context.wrap_socket(socket.socket(socket.AF_INET))
conn.connect(('localhost',12345))
print('connected')
data = conn.read()
print('read: [%s]' % data)
conn.send('hola')

#!/usr/bin/env python
from __future__ import print_function
import os
import ssl
import socket
from simple_https_helper import validate_cert

keydir = 'tmp'
role = 'good'
node = 'listener'
mode = '.client'
topic = '/chatter'

capath = os.path.join(keydir,role,'public')
certfile = os.path.join(keydir,role,'nodes',node,node + mode + '.cert')
keyfile  = os.path.join(keydir,role,'nodes',node,node + mode + '.pem')

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(capath=capath)
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

conn = context.wrap_socket(socket.socket(socket.AF_INET))
conn.connect(('localhost',12345))
print('Connected')

# try:
is_valid = validate_cert(cert=conn.getpeercert(binary_form=True), topic=topic)
# except:
#     is_valid = False

if is_valid:
    data = conn.read()
    print('read: [%s]' % data)
    conn.send('hola')
    print('Closed: All done')
else:
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()
    print('Closed: Access Denied')



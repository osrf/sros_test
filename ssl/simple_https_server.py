#!/usr/bin/env python
from __future__ import print_function
import os
import ssl
import socket

keydir = 'keys'
mode = 'good'
capath = os.path.join(keydir,mode,'public')
certfile = os.path.join(keydir,mode,'server','server.cert')
keyfile = os.path.join(keydir,mode,'server','server.pem')

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(capath=capath)
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

bindsocket = socket.socket()
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bindsocket.bind(('localhost',12345))
bindsocket.listen(5)

while True:
    try:
        newsocket, fromaddr = bindsocket.accept()
        print('accepted')
        conn = context.wrap_socket(newsocket, server_side=True)
        conn.send('hello')
        data = conn.read()
        print('read: [%s]' % data)
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        print('closed')
    except KeyboardInterrupt:
        print('\n\nadios amigo\n')
        break
    except ssl.CertificateError as e:
        print('ssl certificate exception: %s' % e)

bindsocket.shutdown(socket.SHUT_RDWR)
bindsocket.close()
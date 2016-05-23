#!/usr/bin/env python
from __future__ import print_function
import ssl
import socket

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_OPTIONAL
context.load_verify_locations('/home/mquigley/.ros/keys/root.cer')
context.load_cert_chain('/home/mquigley/.ros/keys/talker.server.cert', keyfile='/home/mquigley/.ros/keys/talker.server.key')
bindsocket = socket.socket()
bindsocket.bind(('localhost',12345))
bindsocket.listen(5)
while True:
    newsocket, fromaddr = bindsocket.accept()
    print('accepted')
    connstream = context.wrap_socket(newsocket, server_side=True)
    print('wrapped')
    connstream.send('hello')
    connstream.shutdown(socket.SHUT_RDWR)
    connstream.close()
    print('closed')

#!/usr/bin/env python
from __future__ import print_function
import ssl
import socket
import sys

def servername_callback(sock, desired_server_name, context):
    print("client is requesting to talk to [%s]" % desired_server_name)
    if desired_server_name != 'master.server':
        print("get outta here")
        return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
    return None # accept it

prefix = '' #evil.'
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(prefix+'root.cert')
context.load_cert_chain(prefix+'server.cert', keyfile=(prefix+'server.key'))
context.set_servername_callback(servername_callback)
bindsocket = socket.socket()
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bindsocket.bind(('localhost',12345))
bindsocket.listen(5)

while True:
    try:
        newsocket, fromaddr = bindsocket.accept()
        print('accepted')
        connstream = context.wrap_socket(newsocket, server_side=True)
        cert = connstream.getpeercert()
        ssl.match_hostname(cert, 'master.client')
        print('client name matched OK')
        print('sending secret message')
        connstream.send('hello')
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()
        print('closed')
    except KeyboardInterrupt:
        print('\n\nadios amigo\n')
        break
    except ssl.CertificateError as e:
        print('ssl certificate exception: %s' % e)
bindsocket.shutdown(socket.SHUT_RDWR)
bindsocket.close()

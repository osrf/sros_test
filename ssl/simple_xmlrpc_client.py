#!/usr/bin/env python
from __future__ import print_function
#import ssl
import xmlrpclib as xmlrpcclient

#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#context.verify_mode = ssl.CERT_OPTIONAL
#context.load_verify_locations('test.cert') #/home/mquigley/.ros/keys/root.cer')
#context.load_cert_chain('/home/mquigley/.ros/keys/master.server.cert', keyfile='/home/mquigley/.ros/keys/master.server.key')
proxy = xmlrpcclient.ServerProxy('http://localhost:11310') #, context=context)
print(proxy.getCertificates('world'))

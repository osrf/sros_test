#!/usr/bin/env python
from __future__ import print_function
from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler

server = SimpleXMLRPCServer(("localhost", 11310), SimpleXMLRPCRequestHandler, False)

# Register a function under a different name
def getCertificates(node_name):
    print("request: getCertificates(%s)" % node_name)
    return "world"

server.register_function(getCertificates, 'getCertificates')
server.serve_forever()

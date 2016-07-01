from __future__ import print_function
from cryptography import hazmat, x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from apparmor.aare import re
from apparmor.common import convert_regexp

def in_subtree(subtree, topic):
    for uri in subtree:
        regex_obj = re.compile(convert_regexp(uri.value))
        if regex_obj.search(topic):
            return True
    return False

def validate_cert(cert, topic):
    cert = x509.load_der_x509_certificate(cert, default_backend())
    name_constraints = cert.extensions.get_extension_for_class(x509.NameConstraints)
    if name_constraints.critical:
        if name_constraints.value.excluded_subtrees:
            deny = in_subtree(name_constraints.value.excluded_subtrees, topic)
        else:
            deny = False
        if deny: return False

        if name_constraints.value.permitted_subtrees:
            allow = in_subtree(name_constraints.value.permitted_subtrees, topic)
        else:
            allow = False
        return allow
    else:
        return True
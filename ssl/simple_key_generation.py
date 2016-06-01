#!/usr/bin/python

from __future__ import print_function
from OpenSSL import crypto, SSL
import os
import yaml
import getpass
import datetime

SROS_PASSPHRASE = 'SROS_PASSPHRASE'

class KeyBlob:
    def __init__(self, key_name, key_config):
        self.key_name = key_name
        self.key_config = key_config

    def _generate_cert(self):
        cert = crypto.X509()
        cert_config = self.key_config['cert']

        cert.get_subject().C = cert_config['subject']['country']
        cert.get_subject().ST = cert_config['subject']['state']
        cert.get_subject().L = cert_config['subject']['locality']
        cert.get_subject().O = cert_config['subject']['organization']
        cert.get_subject().OU = cert_config['subject']['organizational_unit']
        cert.get_subject().CN = cert_config['subject']['common_name']
        cert.set_serial_number(cert_config['serial_number'])

        if isinstance(cert_config['notBefore'], int):
            cert.gmtime_adj_notBefore(cert_config['notBefore'])
        elif isinstance(cert_config['notBefore'], datetime.date):
            cert.set_notBefore(cert_config['notBefore'].strftime('%Y%m%d%H%M%SZ'))
        else:
            cert.set_notBefore(cert_config['notBefore'])

        if isinstance(cert_config['notAfter'], int):
            cert.gmtime_adj_notAfter(cert_config['notAfter'])
        elif isinstance(cert_config['notAfter'], datetime.date):
            cert.set_notAfter(cert_config['notAfter'].strftime('%Y%m%d%H%M%SZ'))
        else:
            cert.set_notAfter(cert_config['notAfter'])

        self.cert = cert

    def _generate_key(self):
        self.pkey = crypto.PKey()
        type = {
            'rsa': crypto.TYPE_RSA,
            'dsa': crypto.TYPE_DSA,}[self.key_config['type']]
        bits = self.key_config['bits']
        self.pkey.generate_key(type, bits)

    def create_root_cert(self):

        self._generate_key()
        self._generate_cert()

        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.pkey)
        self.cert.sign(self.pkey, self.key_config['digest'])

    def create_singed_cert(self, ca_blob):

        self._generate_key()
        self._generate_cert()

        self.cert.set_issuer(ca_blob.cert.get_subject())
        self.cert.set_pubkey(self.pkey)
        self.cert.sign(ca_blob.pkey, ca_blob.key_config['digest'])

    def dump_cert(self, cert_dir):
        cert_path = os.path.join(cert_dir, self.key_name + '.cert')
        open(cert_path, "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert))

    def dump_key(self, key_dir, passphrase=None):
        key_path  = os.path.join(key_dir, self.key_name + '.pem')
        open(key_path, "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pkey, self.key_config['cipher'], passphrase))


def check_path(path):
    if not os.path.exists(path):
        os.makedirs(path)


def get_new_passphrase(key_name):
    if (SROS_PASSPHRASE in os.environ):
        return os.environ[SROS_PASSPHRASE]
    else:
        while(True):
            passphrase = getpass.getpass(prompt='Enter pass phrase for %s: '.format(key_name), stream=None)
            passphrase_ = getpass.getpass(prompt='Verifying - Enter pass phrase for %s: '.format(key_name), stream=None)
            if (passphrase == passphrase_):
                break
    return passphrase


def load_config(path):
    with open(path, 'r') as stream:
        try:
            config = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    return config


def create_root_keys(key_dir, key_blob):
    check_path(key_dir)
    key_blob.create_root_cert()
    passphrase = None
    if 'cipher' in key_blob.key_config:
        passphrase = get_new_passphrase(key_blob.key_name)
    key_blob.dump_cert(key_dir)
    key_blob.dump_key(key_dir, passphrase)


def create_singed_keys(key_dir, key_blob, ca_blob):
    check_path(key_dir)
    key_blob.create_singed_cert(ca_blob)
    passphrase = None
    if 'cipher' in key_blob.key_config:
        passphrase = get_new_passphrase(key_blob.key_name)
    key_blob.dump_cert(key_dir)
    key_blob.dump_key(key_dir, passphrase)


def simple_key_generation(keys_dir, config_path):
    check_path(keys_dir)

    config = load_config(config_path)
    master_name = "master"
    master_config = config['keys'][master_name]
    master_dir = os.path.join(keys_dir, master_name)
    master_blob = KeyBlob(master_name, master_config)
    keys = dict()

    if (config['keys'][master_name]['issuer'] is None):
        create_root_keys(master_dir, master_blob)
        keys[master_name] = master_blob

    elif (config['keys'][master_name]['issuer'] in config['keys']):
        root_name = config['keys']['master']['issuer']
        root_config = config['keys'][root_name]
        root_blob = KeyBlob(root_name, root_config)
        root_dir = os.path.join(keys_dir, root_name)
        create_root_keys(root_dir, root_blob)
        keys[root_name] = root_blob

        create_singed_keys(master_dir, master_blob, root_blob)
        keys[master_name] = master_blob

    nodes = ['client', 'server']
    node_config = config['keys']['nodes']
    start = node_config['cert']['serial_number']

    for serial_number, node_name in enumerate(nodes, start):
        node_config['cert']['serial_number'] = serial_number
        node_blob = KeyBlob(node_name, node_config)
        node_dir = os.path.join(keys_dir, node_name)
        create_singed_keys(node_dir, node_blob, master_blob)
        keys[node_name] = node_blob

simple_key_generation("./tmp", "sros_config.yml")

#!/usr/bin/python

from __future__ import print_function
from OpenSSL import crypto, SSL
import os
import yaml
import getpass
import datetime
import collections

SROS_PASSPHRASE = 'SROS_PASSPHRASE'

class KeyBlob:
    def __init__(self, key_name, key_config):
        self.key_name = key_name
        self.key_config = key_config
        self.passphrase = None
        self.cert_path = None
        self.key_path = None


    def _sort_extension_logic(self):
        x509_extensions = self.key_config['x509_extensions']
        x509_extensions = collections.OrderedDict(sorted(x509_extensions.items()))

        if 'authorityKeyIdentifier' in x509_extensions:
            authorityKeyIdentifier = x509_extensions.pop('authorityKeyIdentifier')
            x509_extensions['authorityKeyIdentifier'] = authorityKeyIdentifier

        self.key_config['x509_extensions'] = x509_extensions


    def _add_extensions(self, ca_blob):
        if self.key_config['x509_extensions'] is not None:
            self._sort_extension_logic()
            x509_extensions = self.key_config['x509_extensions']

            for type_name in x509_extensions:
                critical = x509_extensions[type_name]['critical']
                value = ", ".join(x509_extensions[type_name]['value'])
                subject = self.cert
                issuer = ca_blob.cert
                extension = crypto.X509Extension(type_name, critical, value, subject, issuer)
                self.cert.add_extensions([extension])


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


    def create_cert(self, ca_blob=None):

        self._generate_key()
        self._generate_cert()

        if ca_blob is None:
            self.cert.set_issuer(self.cert.get_subject())
            self.cert.set_pubkey(self.pkey)
            self._add_extensions(self)
            self.cert.sign(self.pkey, self.key_config['digest'])
        else:
            self.cert.set_issuer(ca_blob.cert.get_subject())
            self.cert.set_pubkey(self.pkey)
            self._add_extensions(ca_blob)
            self.cert.sign(ca_blob.pkey, ca_blob.key_config['digest'])


    def dump_cert(self, cert_path=None):
        if cert_path is None:
            cert_path = self.cert_path
        open(cert_path, "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert))


    def dump_key(self, key_path=None):
        if key_path is None:
            key_path = self.key_path
        open(key_path, "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pkey, self.key_config['cipher'], self.passphrase))


    def get_new_passphrase(self):
        if 'cipher' not in self.key_config:
            self.passphrase = None
        elif (SROS_PASSPHRASE in os.environ):
            self.passphrase = os.environ[SROS_PASSPHRASE]
        else:
            while (True):
                passphrase = getpass.getpass(prompt='Enter pass phrase for %s: '.format(self.key_name), stream=None)
                passphrase_ = getpass.getpass(prompt='Verifying - Enter pass phrase for %s: '.format(self.key_name),
                                              stream=None)
                if (passphrase == passphrase_):
                    break
            self.passphrase = passphrase


def check_path(path):
    if not os.path.exists(path):
        os.makedirs(path)


def load_config(path):
    with open(path, 'r') as stream:
        try:
            config = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    return config


def create_keys(key_dir, key_blob, ca_blob=None):
    check_path(key_dir)
    key_blob.create_cert(ca_blob)
    key_blob.get_new_passphrase()
    key_blob.cert_path = os.path.join(key_dir, key_blob.key_name + '.cert')
    key_blob.key_path  = os.path.join(key_dir, key_blob.key_name + '.pem')
    key_blob.dump_cert()
    key_blob.dump_key()


def rehash(hash_dir, keys_dict):
    check_path(hash_dir)
    hash_list = []
    for key_name, key_blob in keys_dict.iteritems():
        subject_name_hash = key_blob.cert.subject_name_hash()
        hash = format(subject_name_hash, '02x')
        hash_dict = {'hash':hash,
                     'link_path':os.path.join(hash_dir, hash + '.0'),
                     'cert_path':key_blob.cert_path,
                     'key_name':key_name}
        if os.path.exists(hash_dict['link_path']):
            os.unlink(hash_dict['link_path'])
        hash_list.append(hash_dict)

    for hash_dict in hash_list:
        try:
            os.symlink(hash_dict['cert_path'], hash_dict['link_path'])
        except:
            raise ValueError("\nSubject Name Hashes from your certs are colliding!\n"
                             "Please make sure all CA certificates subjects are unique!\n"
                             "In no particular order...\n"
                             "Offending cert: {}\n".format(hash_dict['key_name']) +
                             "Offending hash: {}\n".format(hash_dict['hash']))


def simple_key_generation(keys_dir, config_path):
    keys_dir = os.path.abspath(keys_dir)
    config_path = os.path.abspath(config_path)
    check_path(keys_dir)

    config = load_config(config_path)
    master_name = "master"
    master_config = config['keys'][master_name]
    master_dir = os.path.join(keys_dir, master_name)
    master_blob = KeyBlob(master_name, master_config)
    keys = dict()

    if (config['keys'][master_name]['issuer'] is None):
        create_keys(master_dir, master_blob)
        keys[master_name] = master_blob

    elif (config['keys'][master_name]['issuer'] in config['keys']):
        root_name = config['keys']['master']['issuer']
        root_config = config['keys'][root_name]
        root_blob = KeyBlob(root_name, root_config)
        root_dir = os.path.join(keys_dir, root_name)
        create_keys(root_dir, root_blob)
        keys[root_name] = root_blob

        create_keys(master_dir, master_blob, root_blob)
        keys[master_name] = master_blob

    hash_dir = os.path.join(keys_dir, 'public')
    rehash(hash_dir, keys)

    node_names = ['master','talker', 'listener']
    mode_names = ['client','server']
    node_config = config['keys']['nodes']
    serial_number = node_config['cert']['serial_number']

    for node in node_names:
        node_dir = os.path.join(keys_dir, node)
        for mode in mode_names:
            node_name = node + '.' + mode
            node_config['cert']['serial_number'] = serial_number
            node_blob = KeyBlob(node_name, node_config)
            create_keys(node_dir, node_blob, master_blob)
            keys[node_name] = node_blob
            serial_number += 1


if __name__ == "__main__":
    simple_key_generation("./tmp", "sros_config.yml")

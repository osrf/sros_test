#!/usr/bin/python

from __future__ import print_function
from cryptography import hazmat, x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa

from OpenSSL import crypto, SSL
import os
import shutil
import sys
import yaml
import getpass
import datetime
import collections

SROS_ROOT_PASSPHRASE = 'SROS_ROOT_PASSPHRASE'
SROS_PASSPHRASE = 'SROS_PASSPHRASE'

class KeyBlob:
    '''
    This class is used to load or generate keys and certificates with openssl
    '''
    def __init__(self, key_name, key_config):
        '''
        Initializes and sets class attributes
        :param key_name: string of key name
        :param key_config: dict of key configuration
        '''
        self.key_name = key_name
        self.key_config = key_config
        self.passphrase = None
        self.cert_path = None
        self.key_path = None
        self.cert = None
        self.key = None


    # def _sort_extension_logic(self):
    #     '''
    #     Reorders x509_extensions dict so that extensions are applied in a proper order
    #     :return: None
    #     '''
    #     x509_extensions = self.key_config['x509_extensions']
    #     x509_extensions = collections.OrderedDict(sorted(x509_extensions.items()))
    #
    #     if 'authorityKeyIdentifier' in x509_extensions:
    #         authorityKeyIdentifier = x509_extensions.pop('authorityKeyIdentifier')
    #         x509_extensions['authorityKeyIdentifier'] = authorityKeyIdentifier
    #
    #     self.key_config['x509_extensions'] = x509_extensions
    #
    #
    # def _add_extensions(self, ca_blob):
    #     '''
    #     Adds extensions to certificate
    #     :param ca_blob: KeyBlob of ca used when extension may need issuer's cert
    #     :return: None
    #     '''
    #     if self.key_config['x509_extensions'] is not None:
    #         self._sort_extension_logic()
    #         x509_extensions = self.key_config['x509_extensions']
    #
    #         for type_name in x509_extensions:
    #             if x509_extensions[type_name] is not None:
    #                 critical = x509_extensions[type_name]['critical']
    #                 value = ", ".join(x509_extensions[type_name]['value'])
    #                 subject = self.cert
    #                 issuer = ca_blob.cert
    #                 extension = crypto.X509Extension(type_name, critical, value, subject, issuer)
    #                 self.cert.add_extensions([extension])


    def _generate_cert_builder(self):
        '''
        Generates X509 certificate builder and applies subject and expiration info
        :return: None
        '''

        cert_config = self.key_config['cert']

        attributes = []
        for attribute_key in cert_config['subject']:
            oid = getattr(NameOID, attribute_key)
            value = unicode(cert_config['subject'][attribute_key])
            attribute = x509.NameAttribute(oid, value)
            attributes.append(attribute)
        subject = x509.Name(attributes)

        utcnow = datetime.datetime.utcnow()
        if isinstance(cert_config['not_valid_before'], int):
            not_before_datetime = utcnow + datetime.timedelta(seconds=cert_config['not_valid_before'])
        else:
            not_before_datetime = cert_config['not_valid_before']
        if isinstance(cert_config['not_valid_after'], int):
            not_after_datetime = utcnow + datetime.timedelta(seconds=cert_config['not_valid_after'])
        else:
            not_after_datetime = cert_config['not_valid_after']

        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).serial_number(
            cert_config['serial_number']
        ).not_valid_before(
            not_before_datetime
        ).not_valid_after(
            not_after_datetime
        )

        return cert_builder


    def generate_key(self):
        '''
        Generates key pair using type and length specified in key_config
        :return: None
        '''

        if self.key_config['key_type'] == 'rsa':
            self.key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_config['key_size'],
                backend=default_backend()
            )
        elif self.key_config['key_type'] == 'dsa':
            self.key = dsa.generate_private_key(
                key_size=self.key_config['key_size'],
                backend=default_backend()
            )
        else:
            raise ValueError("\nFailed to generate key, no key_type key type provided!\n"
                             "Offending key name: {}\n".format(self.key_name))


    def _get_fingerprint_algorithm(self):
        if self.key_config['fingerprint_algorithm'] is not None:
            fingerprint_algorithm = getattr(hashes, self.key_config['fingerprint_algorithm'])()
            return fingerprint_algorithm
        else:
            raise ValueError("\nNo fingerprint algorithm is specified!\n"
                             "Offending key name: {}\n".format(self.key_name))


    def create_cert(self, ca_blob=None):
        '''
        Create certificate and singe using key pair
        :param ca_blob: KeyBlob used and CA, when None the certificate will be self singed
        :return: None
        '''

        cert_builder = self._generate_cert_builder()

        if ca_blob is None:
            self.cert = cert_builder.issuer_name(
                cert_builder._subject_name
            ).public_key(
                self.key.public_key()
            ).sign(self.key, self._get_fingerprint_algorithm(), default_backend())
            # self._add_extensions(self)
        else:
            self.cert = cert_builder.issuer_name(
                ca_blob.cert.subject
            ).public_key(
                self.key.public_key()
            ).sign(ca_blob.key, ca_blob._get_fingerprint_algorithm(), default_backend())
            # self._add_extensions(self)


    def dump_cert(self, cert_path=None):
        '''
        Save certificate to disk
        :param cert_path: full certificate file path to write to
        :return: None
        '''
        if cert_path is None:
            cert_path = self.cert_path
        with open(cert_path, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))


    def dump_key(self, key_path=None):
        '''
        Save private key to disk
        :param key_path: full key file path to write to
        :return: None
        '''
        if key_path is None:
            key_path = self.key_path

        if self.key_config['encryption_algorithm'] is None:
            encryption_algorithm = serialization.NoEncryption
        else:
            encryption_algorithm = getattr(serialization, self.key_config['encryption_algorithm'])(self.passphrase)

        with open(key_path, "wb") as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm,
            ))


    def load_cert(self, cert_path=None):
        '''
        Load certificate from disk
        :param cert_path: full certificate file path to load from
        :return: None
        '''
        if cert_path is None:
            cert_path = self.cert_path
        with open(cert_path, 'rb') as f:
            self.cert = x509.load_pem_x509_certificate(f.read(), default_backend())


    def load_key(self, key_path=None):
        '''
        Load private key from disk
        :param key_path: full key file path to load from
        :return: None
        '''
        if key_path is None:
            key_path = self.key_path
        with open(key_path, 'rb') as f:
            self.key = serialization.load_pem_private_key(
                f.read(),
                password = self.passphrase,
                backend = default_backend())


    def get_new_passphrase(self, env):
        '''
        Get new passphrase either from matching environment variable or promt from user input.
        Only does so if encryption_algorithm has been specified.
        :param env: name of environment variable to check for passphrase
        :return: None
        '''
        if 'encryption_algorithm' not in self.key_config:
            self.passphrase = None
        elif (env in os.environ):
            self.passphrase = os.environ[env]
        else:
            while (True):
                passphrase = getpass.getpass(prompt='Enter pass phrase for {}: '.format(self.key_name), stream=None)
                passphrase_ = getpass.getpass(prompt='Verifying - Enter pass phrase for {}: '.format(self.key_name),
                                              stream=None)
                if (passphrase == passphrase_):
                    break
            self.passphrase = passphrase


    def check_keys_match(self):
        '''
        Check if public and private keys are a valid key pair
        :return: True if key pairs match, False otherwise
        '''
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.use_privatekey(self.pkey)
        ctx.use_certificate(self.cert)
        try:
            ctx.check_privatekey()
        except SSL.Error:
            return False
        return True


def check_path(path):
    '''
    Check for path, and create it if non existing
    :param path:
    :return: None
    '''
    if not os.path.exists(path):
        os.makedirs(path)


def load_config(path):
    '''
    Load and parse configuration file
    :param path: file path to configuration file
    :return: dict representation of config structure
    '''
    with open(path, 'r') as stream:
        try:
            config = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    return config


def get_keys(key_dir, key_blob, ca_blob=None):
    '''
    Loads or creates and save keys and certificates using initialized KeyBlob and with specified CA
    loading or creating is determined by config
    :param key_dir: folder path to store keys and certificates
    :param key_blob: KeyBlob used to generate and save keys and certificates
    :param ca_blob: KeyBlob of CA used to sign generated certificates
    :return: None
    '''
    check_path(key_dir)
    key_blob.cert_path = os.path.join(key_dir, key_blob.key_name + '.cert')
    key_blob.key_path  = os.path.join(key_dir, key_blob.key_name + '.pem')

    over_write_cert = key_blob.key_config['key_type'] is not None
    over_write_key = key_blob.key_config['cert'] is not None

    if ca_blob is None:
        env = SROS_ROOT_PASSPHRASE
    else:
        env = SROS_PASSPHRASE

    if over_write_key:
        key_blob.generate_key()
        key_blob.get_new_passphrase(env)
        key_blob.dump_key()
    else:
        if 'encryption_algorithm' in key_blob.key_config:
            key_blob.get_new_passphrase(env)
        key_blob.load_key()

    if over_write_cert:
        key_blob.create_cert(ca_blob)
        key_blob.dump_cert()
    else:
        key_blob.load_cert()

    # if not key_blob.check_keys_match():
    #     raise ValueError("\nFailed to load certificate, does not match private key!\n"
    #                      "New key pair was generated, public keys from old certificates do not match.\n"
    #                      "Offending cert: {}\n".format(key_blob.cert_path) +
    #                      "Offending key: {}\n".format(key_blob.key_path))


def rehash(hash_dir, keys_dict, clean=False):
    '''
    Rehash given keys and create symbolic links to CA certificate within given directory
    :param hash_dir: path to directory to create symbolic links
    :param keys_dict: dict of KeBlobs create symbolic links for
    :param clean: bool used to delete and thus clean hash_dir
    :return: None
    '''
    if os.path .exists(hash_dir) and clean:
        shutil.rmtree(hash_dir)
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
    '''
    Generates structure keys and certificates using configuration file
    :param keys_dir: path to directory to store generated files
    :param config_path: path to configuration file
    :return:
    '''
    keys_dir = os.path.abspath(keys_dir)
    config_path = os.path.abspath(config_path)
    check_path(keys_dir)

    config = load_config(config_path)
    master_name = "master"
    master_config = config['keys'][master_name]
    master_dir = os.path.join(keys_dir, master_name)
    master_blob = KeyBlob(master_name, master_config)
    keys = dict()

    if (config['keys'][master_name]['issuer_name'] is None):
        get_keys(master_dir, master_blob)
        keys[master_name] = master_blob

    elif (config['keys'][master_name]['issuer_name'] in config['keys']):
        root_name = config['keys']['master']['issuer_name']
        root_config = config['keys'][root_name]
        root_blob = KeyBlob(root_name, root_config)
        root_dir = os.path.join(keys_dir, root_name)
        get_keys(root_dir, root_blob)
        keys[root_name] = root_blob

        get_keys(master_dir, master_blob, root_blob)
        keys[master_name] = master_blob

    hash_dir = os.path.join(keys_dir, 'public')
    # rehash(hash_dir, keys, clean=True)

    node_names = ['master','talker', 'listener']
    mode_names = ['client','server']
    node_config = config['keys']['nodes']
    serial_number = node_config['cert']['serial_number']

    for node in node_names:
        node_dir = os.path.join(keys_dir, node)
        for mode in mode_names:
            node_name = node + '.' + mode
            node_config['cert']['serial_number'] = serial_number
            node_config['cert']['subject']['COMMON_NAME'] = node_name
            node_blob = KeyBlob(node_name, node_config)
            get_keys(node_dir, node_blob, master_blob)
            keys[node_name] = node_blob
            serial_number += 1


def _get_parser():
    '''
    Construct and configure an Argument Parser
    :return: configured ArgumentParser
    '''
    import argparse
    parser = argparse.ArgumentParser(description='Generate keystore directory from configuration file.')

    parser.add_argument("-k","--keys_dir",
                      dest="keys_dir", default="./tmp/good", action="store",
                      help="Define keystore directory to write to", metavar="DIR")
    parser.add_argument("-c","--config_file",
                      dest="config_file", default="sros_config.yml", action="store",
                      help="Define configuration file to load from", metavar="CONFIG")
    return parser


def main(argv=sys.argv):
    '''
    Generate keystore directory from configuration file
    :param argv: arguments for keystore configuration
    :return: None
    '''
    parser = _get_parser()
    args = parser.parse_args(argv[1:])
    simple_key_generation(args.keys_dir, args.config_file)


if __name__ == '__main__':
    main()
#!/usr/bin/python

from __future__ import print_function
from OpenSSL import crypto, SSL
import os
import yaml
import getpass
import datetime

SROS_PASSPHRASE = 'SROS_PASSPHRASE'


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


def generate_cert(key_config, ca_config=None):
    cert = crypto.X509()
    cert_config = key_config['cert']

    cert.get_subject().C  = cert_config['subject']['country']
    cert.get_subject().ST = cert_config['subject']['state']
    cert.get_subject().L  = cert_config['subject']['locality']
    cert.get_subject().O  = cert_config['subject']['organization']
    cert.get_subject().OU = cert_config['subject']['organizational_unit']
    cert.get_subject().CN = cert_config['subject']['common_name']
    cert.set_serial_number(cert_config['serial_number'])

    if isinstance(cert_config['notBefore'],int):
        cert.gmtime_adj_notBefore(cert_config['notBefore'])
    elif isinstance(cert_config['notBefore'],datetime.date):
        cert.set_notBefore(cert_config['notBefore'].strftime('%Y%m%d%H%M%SZ'))
    else:
        cert.set_notBefore(cert_config['notBefore'])

    if isinstance(cert_config['notAfter'], int):
        cert.gmtime_adj_notAfter(cert_config['notAfter'])
    elif isinstance(cert_config['notAfter'], datetime.date):
        cert.set_notAfter(cert_config['notAfter'].strftime('%Y%m%d%H%M%SZ'))
    else:
        cert.set_notAfter(cert_config['notAfter'])

    return cert


def generate_key(key_config):
    pkey = crypto.PKey()
    type = {
        'rsa': crypto.TYPE_RSA,
        'dsa': crypto.TYPE_DSA,}[key_config['type']]
    bits = key_config['bits']
    pkey.generate_key(type, bits)
    return pkey


def save_keys(cert, pkey, key_dir, key_name, cipher=None, passphrase=None):
    cert_path = os.path.join(key_dir, key_name + '.cert')
    key_path  = os.path.join(key_dir, key_name + '.pem')

    open(cert_path, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(key_path, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey, cipher, passphrase))


def create_root_keys(key_name, key_dir, key_config):
    check_path(key_dir)

    # create a key pair
    pkey = generate_key(key_config)

    # create a cert
    cert = generate_cert(key_config)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(pkey)
    cert.sign(pkey, key_config['digest'])
    if 'cipher' in key_config:
        passphrase = get_new_passphrase(key_name)
        save_keys(cert, pkey, key_dir, key_name, key_config['cipher'], passphrase)
    else:
        save_keys(cert, pkey, key_dir, key_name)
    return cert, pkey


def create_singed_keys(key_name, key_dir, key_config, ca_cert, ca_pkey, ca_config):
    check_path(key_dir)

    # create a key pair
    pkey = generate_key(key_config)

    # create a cert
    cert = generate_cert(key_config, ca_config)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(pkey)
    cert.sign(ca_pkey, key_config['digest'])
    if 'cipher' in key_config:
        passphrase = get_new_passphrase(key_name)
        save_keys(cert, pkey, key_dir, key_name, key_config['cipher'], passphrase)
    else:
        save_keys(cert, pkey, key_dir, key_name)
    return cert, pkey


def simple_key_generation(keys_dir, config_path):
    check_path(keys_dir)

    config = load_config(config_path)
    master_name = "master"
    keys = dict()

    if (config['keys'][master_name]['issuer'] is None):
        master_config = config['keys'][master_name]
        master_dir = os.path.join(keys_dir, master_name)
        master_cert, master_pkey = create_root_keys(master_name, master_dir, master_config)
        keys[master_name] = {'cert': master_cert, 'pkey': master_pkey}

    elif (config['keys'][master_name]['issuer'] in config['keys']):
        root_name = config['keys']['master']['issuer']
        root_dir = os.path.join(keys_dir, root_name)
        root_config = config['keys'][root_name]
        root_cert, root_pkey = create_root_keys(root_name, root_dir, root_config)
        keys[root_name] = {'cert': root_cert, 'pkey': root_pkey, 'config': root_config}

        master_config = config['keys'][master_name]
        master_dir = os.path.join(keys_dir, master_name)
        master_cert, master_pkey = create_singed_keys(master_name, master_dir, master_config,
                                                      keys[root_name]['cert'],
                                                      keys[root_name]['pkey'],
                                                      keys[root_name]['config'])
        keys[master_name] = {'cert': master_cert, 'pkey': master_pkey, 'config': master_config}

    nodes = ['client', 'server']
    node_config = config['keys']['nodes']

    for node_name in nodes:
        node_dir = os.path.join(keys_dir, node_name)
        node_cert, node_pkey = create_singed_keys(node_name, node_dir, node_config,
                                                      keys[master_name]['cert'],
                                                      keys[master_name]['pkey'],
                                                      keys[master_name]['config'])
        keys[node_name] = {'cert': node_cert, 'pkey': node_pkey, 'config': node_config}


simple_key_generation("./tmp", "sros_config.yml")

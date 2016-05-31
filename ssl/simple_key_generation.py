#!/usr/bin/python

from OpenSSL import crypto, SSL
import os

def check_path(path):
    if not os.path.exists(path):
        os.makedirs(path)

def default_self_cert():
    cert = crypto.X509()
    cert.get_subject().C  = "ZZ"
    cert.get_subject().ST = "Sate"
    cert.get_subject().L  = "Locality"
    cert.get_subject().O  = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "Common Name"
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    return cert

def default_keys():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    return pkey

def save_keys(cert, pkey, key_dir, key_name, cipher=None, passphrase=None):
    cert_path = os.path.join(key_dir, key_name + '.cert')
    key_path  = os.path.join(key_dir, key_name + '.pem')

    open(cert_path, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(key_path, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey, cipher, passphrase))


def create_root_keys(key_dir, key_name, cipher=None, passphrase=None):
    """
    Generate a self singed certificate authority
    :param root_dir:
    :param cipher:
    :param passphrase:
    :return:
    """
    check_path(key_dir)

    # create a key pair
    pkey = default_keys()

    # create a cert
    cert = default_self_cert()
    cert.set_pubkey(pkey)
    cert.sign(pkey, 'sha256')

    save_keys(cert, pkey, key_dir, key_name, cipher, passphrase)
    return cert, pkey

def create_singed_keys(key_dir, key_name, ca_cert, ca_pkey, cipher=None, passphrase=None):
    """
    Generate singed keys from certificate authority
    :param root_dir:
    :param cipher:
    :param passphrase:
    :return:
    """
    check_path(key_dir)

    # create a key pair
    pkey = default_keys()

    # create a cert
    cert = default_self_cert()
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(pkey)
    cert.sign(ca_pkey, 'sha256')

    save_keys(cert, pkey, key_dir, key_name, cipher, passphrase)
    return cert, pkey

def simple_key_generation(keys_dir):
    """
    Generate key structure
    :param keys_dir: destination path for key structure
    :return: none
    """
    check_path(keys_dir)
    cipher = "des"

    root_name = "root"
    root_passphrase = root_name
    root_dir = os.path.join(keys_dir, root_name)
    root_cert, root_pkey = create_root_keys(root_dir, root_name,
                                            cipher=cipher,
                                            passphrase=root_passphrase)

    master_name = "master"
    master_passphrase = master_name
    master_dir = os.path.join(keys_dir, master_name)
    master_cert, master_pkey = create_singed_keys(master_dir, master_name,
                                                  root_cert, root_pkey,
                                                  cipher=cipher,
                                                  passphrase=master_passphrase)

    client_name = "client"
    client_passphrase = client_name
    client_dir = os.path.join(keys_dir, client_name)
    client_cert, client_pkey = create_singed_keys(client_dir, client_name,
                                                  master_cert, master_pkey,
                                                  cipher=cipher,
                                                  passphrase=client_passphrase)
    server_name = "server"
    server_passphrase = server_name
    server_dir = os.path.join(keys_dir, server_name)
    server_cert, server_pkey = create_singed_keys(server_dir, server_name,
                                                  master_cert, master_pkey,
                                                  cipher=cipher,
                                                  passphrase=server_passphrase)

simple_key_generation("./tmp")

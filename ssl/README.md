# SSL examples using python
This is a collection of simple examples using python and SSL, this includes:

* simple key and certificate generation using OpenSSL's crypto library
* simple client and server authentication using generated Certificate Authority chain

These examples have been constructed with sros in mind as a later use case.

## Generating keys
First off, we'll need to create public and private key pairs, as well matching certificates. This will include constructing Certificate Authority chain, one with a root CA that is self singed, then a master CA singed by the root. The master CA is then used to singe additional certificates used by servers and clients. This root and intermediate master CA is designed so that we could reference a higher CA if need be.

* root: primary CA, used as the foundation of trust
    * master: intermediary CA, used for singing node certificates
        * nodes: all end-entity certificates used by server and clients for SSL handshaking

As apposed to using OpenSSL's CLI to tediously create our key pairs and certificates, we'll programmatically generate them using python. To define our configuration, we'll specify our chain structure and settings using a yaml file. This is convent as we can use yaml syntax to re-reference common attributes by merging maps of values defined earlier in the structurer, keeping the configuration short and simple. Within the 'sros_config.yml' file, the CA hierarchy is defined, including subject fields, valid time frames, encryption methods, as well as matching x509 extensions parameters specific for each level in the CA chain.

To generate the keys within the local directory, we can call the key generation script. This will parse the 'sros_config.yml' file and make the API calls to OpenSSL's crypto library to generate the keys and certificates. Depending on the cipher you've defined in the config file, you will be prompted to provide a pass phrase to encrypt the respective private key when saving it to disk. To things easer for yourself, you can temperately store your secrets passphrases as an local environment variable in your shell session:

``` terminal
SROS_ROOT_PASSPHRASE=root
SROS_PASSPHRASE=sros
./simple_key_generation.py
```

## Using keys
Know that we have our keys and certificates, we can test them using a simple server and client example using Python's system SSL library to wrap the socket communication. By first launching the server in one terminal, and then the client in a second, we can send a encrypted data over the network. You will be requested for the passphrase used to encrypt the private key so that it may be loaded into the SSL context for the TLS socket.

``` terminal
# terminal 1
./simple_https_server.py
Enter PEM pass phrase:
accepted
read: [hola]
closed
```
```
# terminal 2
./simple_https_client.py
Enter PEM pass phrase:
connected
read: [hello]
```

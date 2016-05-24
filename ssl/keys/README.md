put certificates for complete chain authority in public folder
from the public folder run:
for i in *.cert; do ln -s $i `openssl x509 -noout -subject_hash -in $i`.0; done
to create a copy of each cert file, but now with the cert's hash as it's own file name
then point -CApath to folder to verify chain of trust for new received certificates

refences:
http://southbrain.com/south/2012/01/openssl-100-new-capath-hashes.html
https://www.openssl.org/docs/manmaster/apps/s_client.html

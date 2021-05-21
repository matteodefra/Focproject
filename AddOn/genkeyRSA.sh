#/usr/bin/bash

# marc private key
openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 -out marc/marcRSA.pem

# nick private key

openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 -out nick/nickRSA.pem


# marc public key

openssl pkey -in marc/marcRSA.pem -out marc_pubRSA.pem -pubout

# nick public key

openssl pkey -in nick/nickRSA.pem -out nick_pubRSA.pem -pubout


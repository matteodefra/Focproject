#/usr/bin/bash

# marc private key

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 -out marc/marcRSA.pem

# nick private key

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 -out nick/nickRSA.pem


# marc public key

openssl pkey -in marc/marc.pem -out marc_pubRSA.pem -pubout

# nick public key

openssl pkey -in nick/nick.pem -out nick_pubRSA.pem -pubout


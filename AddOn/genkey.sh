#/usr/bin/bash

openssl genpkey -paramfile dhp.pem -out nick/nick.pem
openssl genpkey -paramfile dhp.pem -out marc/marc.pem

openssl pkey -in nick/nick.pem -pubout -out nick_pub.pem
openssl pkey -in marc/marc.pem -pubout -out marc_pub.pem

cp marc_pub.pem nick
mv nick/marc_pub.pem nick/peer.pem

cp nick_pub.pem marc
mv marc/nick_pub.pem marc/peer.pem

openssl genpkey -paramfile dhp.pem -out serverDHkey.pem
openssl pkey -in serverDHkey.pem -pubout -out serverDHpubkey.pem

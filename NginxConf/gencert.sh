#!/bin/sh
# create self-signed server certificate:
read -p "Enter your domain [www.example.com]: " DOMAIN
echo "Create server key..."
openssl genrsa -des3 -out ssl.key 2048
echo "Create server certificate signing request..."
SUBJECT="/C=US/ST=Mars/L=iTranswarp/O=iTranswarp/OU=iTranswarp/CN=$DOMAIN"
openssl req -new -subj $SUBJECT -key ssl.key -out ssl.csr
echo "Remove password..."
mv ssl.key ssl.origin.key
openssl rsa -in ssl.origin.key -out ssl.key
echo "Sign SSL certificate..."
openssl x509 -req -days 3650 -in ssl.csr -signkey ssl.key -out ssl.crt
echo "Update certificate success"
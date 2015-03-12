#!/bin/bash

rm -rf test_certs
mkdir test_certs

# First make the root CA
mkdir -p test_certs/rootCA/{certs,crl,newcerts,private}
touch test_certs/rootCA/index.txt
echo "01" > test_certs/rootCA/crlnumber
echo 1000 > test_certs/rootCA/serial
openssl req -new -config rootCA.cnf -keyout test_certs/rootCA/private/cakey.pem -out test_certs/rootCA/careq.pem
openssl ca -config rootCA.cnf -notext -create_serial -selfsign -batch -key apenoot -extensions v3_ca -out test_certs/rootCA/cacert.pem -infiles test_certs/rootCA/careq.pem

# Certificates 1-17 are all signed by the CA, except 14
for i in $(seq 1 13); do
    # Generate a CSR
    openssl req -new -config ${i}.cnf -out ${i}.csr -nodes -keyout test_certs/${i}-key.pem
    # Sign the CSR. We need our own config here because we want copy_extensions on so we can preserve SubjectAltNames
    openssl ca -config ${i}.cnf -batch -notext -key apenoot -policy policy_anything -out test_certs/${i}-cert.pem -infiles ${i}.csr
done

# 14 is to be signed by a completely different CA.
mkdir -p test_certs/14_CA/{certs,crl,newcerts,private}
touch test_certs/14_CA/index.txt
echo "01" > test_certs/14_CA/crlnumber
echo 1000 > test_certs/14_CA/serial
openssl req -new -config 14.cnf -nodes -keyout test_certs/14_CA/private/cakey.pem -out test_certs/14_CA/careq.pem
openssl ca -config 14.cnf -notext -create_serial -selfsign -batch -key apenoot -extensions v3_ca -out test_certs/14_CA/cacert.pem -infiles test_certs/14_CA/careq.pem
openssl req -new -config 14_tail.cnf -out 14.csr -nodes -keyout test_certs/14-key.pem
openssl ca -config 14_tail.cnf -notext -batch -key apenoot -policy policy_anything -out test_certs/14-cert.pem -infiles 14.csr

for i in $(seq 15 17); do
    # Generate a CSR
    openssl req -new -config ${i}.cnf -out ${i}.csr -nodes -keyout test_certs/${i}-key.pem
    # Sign the CSR. We need our own config here because we want copy_extensions on so we can preserve SubjectAltNames
    openssl ca -config ${i}.cnf -batch -notext -key apenoot -policy policy_anything -out test_certs/${i}-cert.pem -infiles ${i}.csr
done

# Hack certificate 15 by changing 5 characters near the end of the certificate to AAAAA.
# Obviously if they are already AAAAA then this wont work, but that is pretty unlikely.
# Do not change the last 3 since base64 coding would require us to work out the length of the file and add appropriate number of = signs
cat test_certs/15-cert.pem | sed '1!G;h;$!d' | sed '2 s@\(.*\).....\(...\)@\1AAAAA\2@' | sed '1!G;h;$!d' > test_certs/15-cert.tmp && mv test_certs/15-cert.tmp test_certs/15-cert.pem

# Hack certificate 11 to add in some embedded NULLs. The openssl req utility cannot do this, but we can...
# First, convert PEM -> DER so we can hack on it
openssl req -in 11.csr -out 11.der -outform DER
# Then substitute  \0\0\0\0 for the word NULL
hexdump -ve '1/1 "%.2X"' 11.der | sed 's/4E554C4C/00000000/g' | xxd -r -p > 11-modified.der
# Next we must update the signature. First, get the stuff which is hashed
openssl asn1parse -in 11-modified.der -inform der -strparse 4 -out 11-hashdata.der
# Then sign it using our private key
openssl dgst -sha256 -sign test_certs/11-key.pem -out 11-signature.der 11-hashdata.der
# Then grab the bit of the modified file which is not the signature and overwrite the original certificate
head -c $(( $(cat 11-modified.der | wc -c) - 256 )) 11-modified.der > 11.der
# Next, append the new signature
cat 11-signature.der >> 11.der
# Convert back to PEM
openssl req -outform PEM -inform DER -in 11.der -out 11.csr
# Then re-sign it as if nothing unusual has just happened. Easy.
openssl ca -config 11.cnf -batch -key apenoot -policy policy_anything -out test_certs/11-cert.pem -infiles 11.csr

# Certificates 18-22 are all about intermediaries
for i in $(seq 18 22); do
    # First, generate the intermediary
    mkdir -p test_certs/${i}_CA/{certs,crl,newcerts,private}
    touch test_certs/${i}_CA/index.txt
    echo "01" > test_certs/${i}_CA/crlnumber
    echo 1000 > test_certs/${i}_CA/serial
    openssl req -new -config ${i}.cnf -nodes -keyout test_certs/${i}_CA/private/cakey.pem -out test_certs/${i}_CA/careq.pem
    openssl ca -config ${i}.cnf -notext -create_serial -batch -key apenoot -extensions v3_ca -out test_certs/${i}_CA/cacert.pem -infiles test_certs/${i}_CA/careq.pem
    
    # Generate a CSR (All of these tests relate to the intermediate CA, not the certificate at the end of the chain
    openssl req -new -config ${i}_tail.cnf -out ${i}.csr -nodes -keyout test_certs/${i}-key.pem
    # Sign the CSR. We need our own config here because we want copy_extensions on so we can preserve SubjectAltNames
    openssl ca -config ${i}_tail.cnf -notext -batch -key apenoot -policy policy_anything -out test_certs/${i}-tail-cert.pem -infiles ${i}.csr
    # Finally put the CA and the server cert into one file
    cat test_certs/${i}-tail-cert.pem test_certs/${i}_CA/cacert.pem  > test_certs/${i}-cert.pem
done

# Certificates 23-24 are about CRLs
for i in $(seq 23 24); do
    openssl req -new -config ${i}.cnf -out ${i}.csr -nodes -keyout test_certs/${i}-key.pem
    openssl ca -config ${i}.cnf -batch -notext -key apenoot -policy policy_anything -out test_certs/${i}-cert.pem -infiles ${i}.csr
done

# Certificate 23 has a CRL but has not been revoked
# Certificate 24 has a CRL and HAS been revoked
openssl ca -config 24.cnf -revoke test_certs/24-cert.pem -batch -notext -key apenoot

# Certificates 25-27 needs their own CA
for i in $(seq 25 27); do
    # First, generate the intermediary
    mkdir -p test_certs/${i}_CA/{certs,crl,newcerts,private}
    touch test_certs/${i}_CA/index.txt
    echo "01" > test_certs/${i}_CA/crlnumber
    echo 1000 > test_certs/${i}_CA/serial
    openssl req -new -config ${i}.cnf -nodes -keyout test_certs/${i}_CA/private/cakey.pem -out test_certs/${i}_CA/careq.pem
    openssl ca -config ${i}.cnf -notext -create_serial -batch -key apenoot -extensions v3_ca -out test_certs/${i}_CA/cacert.pem -infiles test_certs/${i}_CA/careq.pem
    
    # Generate a CSR (All of these tests relate to the intermediate CA, not the certificate at the end of the chain
    openssl req -new -config ${i}_tail.cnf -out ${i}.csr -nodes -keyout test_certs/${i}-key.pem
    # Sign the CSR. We need our own config here because we want copy_extensions on so we can preserve SubjectAltNames
    openssl ca -config ${i}_tail.cnf -notext -batch -key apenoot -policy policy_anything -out test_certs/${i}-tail-cert.pem -infiles ${i}.csr
    # Finally put the CA and the server cert into one file
    cat test_certs/${i}-tail-cert.pem test_certs/${i}_CA/cacert.pem  > test_certs/${i}-cert.pem
done

# Revoke the 27 CA certificate from the root
openssl ca -config 27.cnf -revoke test_certs/27_CA/cacert.pem -batch -notext -key apenoot

# Revoke the 26 tail certificate from the 26 CA
openssl ca -config 26_tail.cnf -revoke test_certs/26-tail-cert.pem -batch -notext -key apenoot

# Generate the root CRL
openssl ca -config 23.cnf -gencrl -out test_certs/rootCA-crl.pem

# Generate the 25-27 CA CRLS
for i in $(seq 25 27); do
    openssl ca -config ${i}_tail.cnf -gencrl -out test_certs/${i}-crl.pem
done



# Finally, generate the certificates for all the pre-existing tests:
# The server
openssl req -new -config server.cnf -out server.csr -nodes -keyout test_certs/server-key.pem
openssl ca -config server.cnf -batch -notext -key apenoot -policy policy_anything -out test_certs/server-cert.pem -infiles server.csr
# The client
openssl req -new -config client.cnf -out client.csr -nodes -keyout test_certs/client-key.pem
openssl ca -config client.cnf -batch -notext -key apenoot -policy policy_anything -out test_certs/client-cert.pem -infiles client.csr

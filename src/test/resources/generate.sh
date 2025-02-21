#!/bin/bash
echo -n 'Hello, World!' > payload.txt

# Generate keys (16K is max it does)
ssh-keygen -t rsa -b 16384 -N '' -f rsa4k -C "RSA 16384 test plain key"
ssh-keygen -t ed25519 -N '' -f ed25519 -C "Ed25519 test plain key"
ssh-keygen -t ecdsa -b 256 -N '' -f p256 -C "P256 test plain key"
ssh-keygen -t ecdsa -b 384 -N '' -f p384 -C "P384 test plain key"
ssh-keygen -t ecdsa -b 521 -N '' -f p521 -C "P521 test plain key"

# sign
for f in rsa4k ed25519 p256 p384 p521; do
  ssh-keygen -Y sign -n file -f $f payload.txt && mv -v payload.txt.sig $f.pub.sig
done

# generate CA keys
ssh-keygen -t rsa -b 4096 -N '' -f ca_rsa4k -C "RSA 4096 test ca key"
ssh-keygen -t ed25519 -N '' -f ca_ed25519 -C "Ed25519 test ca key"
ssh-keygen -t ecdsa -b 256 -N '' -f ca_p256 -C "P256 test ca key"
ssh-keygen -t ecdsa -b 384 -N '' -f ca_p384 -C "P384 test ca key"
ssh-keygen -t ecdsa -b 521 -N '' -f ca_p521 -C "P521 test ca key"


# Issue certificates and sign

for k in rsa4k ed25519 p256 p384 p521; do
  for ca in ca_rsa4k ca_ed25519 ca_p256 ca_p384 ca_p521; do
    ssh-keygen -s ${ca} -n "${k}@example.com" -I "Test subject with ${k}" ${k}.pub
    mv -v ${k}-cert.pub ${k}_${ca}-cert.pub
    cp -v ${k} ${k}_${ca}
    ssh-keygen -Y sign -n file -f ${k}_${ca}-cert.pub  payload.txt && mv -v payload.txt.sig ${k}_${ca}.pub.sig
  done
done

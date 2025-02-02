package com.hardssh.provider;

import pro.javacard.ssh.SSHIdentity;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class SSHKeyFactorySpi extends KeyFactorySpi {
    public SSHKeyFactorySpi() {
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof EncodedKeySpec blob) {
            var i = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(blob.getEncoded())).getKey();
            if (i.isKey()) {
                return i;
            } else {
                throw new InvalidKeySpecException("Not a valid public key");
            }
        }
        throw new InvalidKeySpecException("Unsupported key spec");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        throw new UnsupportedOperationException("Private keys are not handled by this provider");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        throw new UnsupportedOperationException("Key specs are not handled by this provider");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        throw new UnsupportedOperationException("Key translation is not handled by this provider");
    }

}

package com.hardssh.provider;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;

import java.security.PublicKey;
import java.util.Objects;

public record SSHSIGSigningParameters(String namespace, SSHIdentity identity,
                                      String hash) implements SSHSIGAlgorithmParameterSpec {

    public SSHSIGSigningParameters(PublicKey publicKey, String namespace) {
        this(namespace, SSHPublicKey.fromJavaKey(publicKey), "SHA-512");
    }

    public SSHSIGSigningParameters {
        Objects.requireNonNull(identity, "signer can not be null");
        Objects.requireNonNull(namespace, "namespace can not be null");
        if (namespace.isBlank()) {
            throw new IllegalArgumentException("namespace can not be blank");
        }
        Objects.requireNonNull(hash, "hash can not be null");
        if (!SSHSIGSignatureSpi.javahash2ssh.keySet().contains(hash)) {
            throw new IllegalArgumentException("hash must be either SHA-256 or SHA-512");
        }
    }
}

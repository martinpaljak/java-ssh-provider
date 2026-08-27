// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.provider;

import pro.javacard.ssh.openssh.SSHSIG;

import java.util.Objects;

public record SSHSIGVerificationParameters(String namespace, String hash) implements SSHSIGAlgorithmParameterSpec {

    public SSHSIGVerificationParameters(String namespace) {
        this(namespace, "SHA-512");
    }

    public SSHSIGVerificationParameters {
        Objects.requireNonNull(hash, "hash can not be null");
        SSHSIG.Hash.fromJava(hash);
    }
}

package com.hardssh.provider;

import pro.javacard.ssh.SSHIdentity;

import java.io.Serial;
import java.nio.file.Path;
import java.security.PrivateKey;

public class SSHAgentPrivateKey implements PrivateKey {
    @Serial
    private static final long serialVersionUID = -1339182214225875712L;

    // NOTE: not private intentionally
    transient final SSHIdentity identity;
    transient final Path socket;

    SSHAgentPrivateKey(SSHIdentity identity, Path socket) {
        this.identity = identity;
        this.socket = socket;
    }

    @Override
    public String getAlgorithm() {
        return identity.getKey().getAlgorithm();
    }

    public SSHIdentity getIdentity() {
        return identity;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public String toString() {
        return "SSHAgentKey[" + identity.getKey().getFingerprint() + "]";
    }
}

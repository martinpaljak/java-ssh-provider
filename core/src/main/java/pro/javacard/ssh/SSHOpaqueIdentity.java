// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.utils.Helpers;

import java.nio.ByteBuffer;
import java.util.Arrays;

// Opaque identity for unknown key types - enables passthrough without full parsing
@SuppressWarnings("ArrayRecordComponent")
public record SSHOpaqueIdentity(String type, byte[] payload) implements SSHIdentity {

    public static SSHOpaqueIdentity fromBuffer(String type, ByteBuffer src) {
        var payload = new byte[src.remaining()];
        src.get(payload);
        return new SSHOpaqueIdentity(type, payload);
    }
    @Override
    public String getSSHType() {
        // NOTE: the type here must not be (and is not with our use) the type in the actual encoded payload
        // For OpenSSH use, this _is_ the encoded (private) key, but for "generic certificate" we use it is a metatype
        return type;
    }

    @Override
    public byte[] getHash() {
        return Helpers.sha256(payload);
    }

    @Override
    public byte[] toBytes() {
        return payload.clone();
    }

    @Override
    public SSHPublicKey getKey() {
        throw new IllegalStateException("OpaqueIdentity does not have a (known) key");
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof SSHIdentity that) {
            return Arrays.equals(getHash(), that.getHash());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getHash());
    }
}

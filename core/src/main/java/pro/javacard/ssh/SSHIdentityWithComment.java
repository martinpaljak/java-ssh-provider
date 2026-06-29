// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import java.util.Objects;
import java.util.Optional;

// A wrapper around an SSHIdentity that includes a comment. It equals with the wrapped identity, sans comment.
public record SSHIdentityWithComment<T extends SSHIdentity>(T identity, String comment) implements SSHIdentity {

    public SSHIdentityWithComment {
        Objects.requireNonNull(identity);

        // NOTE: might not be "correct" but is probably DWIM, as the only place where comments are
        // normally located is at the end of the line in files like known_hosts
        if (comment != null && comment.isBlank()) {
            comment = null;
        }
    }

    @Override
    public String getSSHType() {
        return identity.getSSHType();
    }

    @Override
    public byte[] toBytes() {
        return identity.toBytes();
    }

    @Override
    public byte[] getHash() {
        return identity.getHash();
    }

    @Override
    public SSHPublicKey getKey() {
        return identity.getKey();
    }

    @Override
    public String asString() {
        return comment == null ? identity.asString() : identity().asString() + " " + comment;
    }

    @Override
    public Optional<String> getComment() {
        return Optional.ofNullable(comment);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof SSHIdentity that) {
            return identity.equals(that);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return identity.hashCode();
    }
}

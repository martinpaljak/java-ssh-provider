// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHIdentityWithComment;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

public final class IdentitiesAnswer extends AgentMessage<IdentitiesAnswer> {

    private final static int MAX_IDENTITIES = 100;
    private final Set<SSHIdentityWithComment<?>> identities;

    public IdentitiesAnswer(Collection<? extends SSHIdentity> identities) {
        super(SSH_AGENT_IDENTITIES_ANSWER);
        //this.identities = new LinkedHashSet<>(identities);
        this.identities = identities.stream().map(e -> e.withComment(e.getComment().orElse(null))).collect(LinkedHashSet::new, LinkedHashSet::add, LinkedHashSet::addAll);
    }

    public Set<SSHIdentityWithComment<?>> getIdentities() {
        return identities;
    }

    public static IdentitiesAnswer fromByteBuffer(ByteBuffer buffer) {
        var identities = new LinkedHashSet<SSHIdentityWithComment<?>>();
        var nkeys = SSHWireFormat.get_uint32(buffer);
        if (nkeys < 0 || nkeys > MAX_IDENTITIES) {
            throw new IllegalArgumentException("Invalid number of keys: " + nkeys);
        }
        for (var i = 0; i < nkeys; i++) {
            var key = SSHWireFormat.get_bytes(buffer);
            var comment = SSHWireFormat.get_string(buffer);

            var pub = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(key));
            identities.add(pub.withComment(comment));
        }
        return new IdentitiesAnswer(identities);
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_uint32(identities.size());
            for (var identity : identities) {
                bin.ssh_bytes(identity.toBytes());
                bin.ssh_string(identity.getComment().orElse(""));
            }
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.nio.ByteBuffer;

public final class RemoveIdentity extends AgentMessage<RemoveIdentity> {

    private final SSHIdentity identity;

    public RemoveIdentity(SSHIdentity identity) {
        super(SSH_AGENTC_REMOVE_IDENTITY);
        this.identity = identity;
    }

    public SSHIdentity getIdentity() {
        return identity;
    }

    @Override
    public byte[] toBytes() {
        return SSHWireFormat.bytes(identity.toBytes());
    }

    public static RemoveIdentity fromByteBuffer(ByteBuffer buffer) {
        var blob = SSHWireFormat.get_bytes(buffer);
        var pub = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(blob));
        return new RemoveIdentity(pub);
    }
}

// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHOpaqueIdentity;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;

// NOTE: this is a restricted version of the message,
// as we only parse and support what we use ourselves (plain cert)
public final class AddIdentity extends AgentMessage<AddIdentity> {
    public static final String WEBKEY_ANY_CERT = "any-cert@webkey.ee";

    private final String type;
    private final SSHIdentity identity;

    public SSHIdentity getIdentity() {
        return identity;
    }

    public AddIdentity(String type, SSHIdentity id) {
        super(SSH_AGENTC_ADD_IDENTITY);
        this.type = Objects.requireNonNull(type);
        this.identity = Objects.requireNonNull(id);
    }

    public static AddIdentity fromByteBuffer(ByteBuffer buffer) {
        var type = SSHWireFormat.get_safe_string(buffer);
        var payload = SSHWireFormat.get_bytes(buffer);
        var comment = SSHWireFormat.get_string(buffer);
        if (WEBKEY_ANY_CERT.equals(type)) {
            var pub = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(payload));
            return new AddIdentity(type, pub.withComment(comment));
        } else {
            // NOTE: the only place where opaque should be instantiated.
            return new AddIdentity(type, new SSHOpaqueIdentity(type, payload).withComment(comment));
        }
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(type);
            bin.ssh_bytes(identity.toBytes());
            bin.ssh_string(identity.getComment().orElse(""));
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

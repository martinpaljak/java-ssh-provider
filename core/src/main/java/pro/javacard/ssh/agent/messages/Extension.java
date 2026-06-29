// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;

public final class Extension extends AgentMessage<Extension> {

    private final String type;
    private final byte[] payload;

    public Extension(String type, byte[] payload) {
        super(SSH_AGENTC_EXTENSION);
        this.type = type;
        this.payload = payload;
    }

    public Extension(String type, SSHSerializable<?> payload) {
        this(type, payload.toBytes());
    }

    public String getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload.clone();
    }

    public static Extension fromByteBuffer(ByteBuffer buffer) {
        var ext = SSHWireFormat.get_safe_string(buffer);
        byte[] payload = new byte[buffer.remaining()];
        buffer.get(payload);

        return new Extension(ext, payload);
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(type);
            bin.write(payload);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

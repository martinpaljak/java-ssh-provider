// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ExtensionResponse extends AgentMessage<ExtensionResponse> {
    final String type;
    final byte[] payload;

    public ExtensionResponse(String type, byte[] payload) {
        super(SSH_AGENT_EXTENSION_RESPONSE);
        this.type = type;
        this.payload = payload;
    }

    public ExtensionResponse(String type, SSHSerializable<?> payload) {
        this(type, payload.toBytes());
    }

    public String getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload.clone();
    }

    public static ExtensionResponse fromByteBuffer(ByteBuffer buffer) {
        var ext = SSHWireFormat.get_safe_string(buffer);
        var payload = new byte[buffer.remaining()];
        buffer.get(payload);
        return new ExtensionResponse(ext, payload);
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

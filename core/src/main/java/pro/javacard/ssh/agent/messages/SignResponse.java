// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.nio.ByteBuffer;

public final class SignResponse extends AgentMessage<SignResponse> {
    private final SSHSignature signature;

    public SignResponse(SSHSignature signature) {
        super(SSH_AGENT_SIGN_RESPONSE);
        this.signature = signature;
    }

    public SSHSignature getSignature() {
        return signature;
    }

    public static SignResponse fromByteBuffer(ByteBuffer buffer) {
        byte[] signature_bytes = SSHWireFormat.get_bytes(buffer);
        var signature = SSHSignature.PARSER.fromBytes(signature_bytes);
        return new SignResponse(signature);
    }

    @Override
    public byte[] toBytes() {
        return SSHWireFormat.bytes(signature.toBytes());
    }
}

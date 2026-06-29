// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.dtbs.DTBSPayload;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;

public final class SignRequest extends AgentMessage<SignRequest> {

    final SSHIdentity identity;
    final byte[] dtbs;
    final int flags;
    final DTBSPayload<?> parsed;

    // Signature flags
    public final static int SSH_AGENT_RSA_SHA2_256 = 2;
    public final static int SSH_AGENT_RSA_SHA2_512 = 4;

    public SignRequest(SSHIdentity identity, byte[] dtbs, int flags) {
        super(SSH_AGENTC_SIGN_REQUEST);
        this.identity = identity;
        this.dtbs = dtbs;
        this.flags = flags;
        this.parsed = DTBSPayload.PARSER(ByteBuffer.wrap(dtbs));
    }

    public SSHIdentity getIdentity() {
        return identity;
    }

    public DTBSPayload<?> getParsed() {
        return parsed;
    }

    public static final Parser<SignRequest> PARSER = SignRequest::fromByteBuffer;

    public static SignRequest fromByteBuffer(ByteBuffer buffer) {
        var key = SSHWireFormat.get_bytes(buffer);
        var dtbs = SSHWireFormat.get_bytes(buffer);
        var flags = buffer.getInt();

        var pub = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(key));

        return new SignRequest(pub, dtbs, flags);
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_bytes(identity.toBytes());
            bin.ssh_bytes(dtbs);
            bin.ssh_uint32(flags);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return parsed.pattern() + " with " + identity.getKey().getFingerprint();
    }
}

// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.nio.ByteBuffer;

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent
public class SessionBindExtension implements SSHSerializable<SessionBindExtension> {
    public static final String SESSION_BIND = "session-bind@openssh.com";

    public static final Parser<SessionBindExtension> PARSER = SessionBindExtension::fromByteBuffer;

    final byte[] sessionId;
    final SSHIdentity identity;
    final SSHSignature signature;
    final boolean forwarded;

    public SessionBindExtension(byte[] sessionId, SSHIdentity identity, SSHSignature signature, boolean forwarded) {
        this.sessionId = sessionId;
        this.identity = identity;
        this.signature = signature;
        this.forwarded = forwarded;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public boolean isForwarded() {
        return forwarded;
    }

    public SSHIdentity getIdentity() {
        return identity;
    }

    public static SessionBindExtension fromByteBuffer(ByteBuffer buffer) {
        var hostkey = SSHWireFormat.get_bytes(buffer);
        var pub = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(hostkey));
        var sessionId = SSHWireFormat.get_bytes(buffer);
        var sig_bytes = SSHWireFormat.get_bytes(buffer);
        var sig = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sig_bytes));
        var forwarding = SSHWireFormat.get_boolean(buffer);
        return new SessionBindExtension(sessionId, pub, sig, forwarding);
    }

    @Override
    public byte[] toBytes() {
        // We only parse this currently
        throw new UnsupportedOperationException("Not implemented");
    }
}

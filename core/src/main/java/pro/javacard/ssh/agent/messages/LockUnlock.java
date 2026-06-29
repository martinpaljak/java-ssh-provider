// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.utils.SSHWireFormat;

import java.nio.ByteBuffer;

public final class LockUnlock extends AgentMessage<LockUnlock> {
    private final String password;

    public LockUnlock(String password, boolean lock) {
        super(lock ? AgentMessage.SSH_AGENTC_LOCK : AgentMessage.SSH_AGENTC_UNLOCK);
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public static LockUnlock fromByteBuffer(ByteBuffer buffer, boolean lock) {
        var password = SSHWireFormat.get_string(buffer);
        return new LockUnlock(password, lock);
    }

    @Override
    public byte[] toBytes() {
        return SSHWireFormat.string(password);
    }
}

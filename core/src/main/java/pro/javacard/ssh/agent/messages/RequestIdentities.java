// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

public final class RequestIdentities extends AgentMessage<RequestIdentities> {

    public RequestIdentities() {
        super(SSH_AGENTC_REQUEST_IDENTITIES);
    }

    @Override
    public byte[] toBytes() {
        return new byte[0]; // Explicitly override to avoid warning in super
    }
}

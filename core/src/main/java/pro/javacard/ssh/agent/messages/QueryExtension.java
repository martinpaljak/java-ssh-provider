// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.utils.SSHSerializable;

public final class QueryExtension implements SSHSerializable<QueryExtension> {
    public static final String QUERY = "query";
    // NOTE: defined in SSH Agent protocol (3.8.1. Query extension)
    // but not used/implemented by OpenSSH

    public QueryExtension() {
    }

    @Override
    public byte[] toBytes() {
        return new byte[0];
    }
}

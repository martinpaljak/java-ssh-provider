// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.utils;

import java.nio.ByteBuffer;

// Contract: Arrays.equals(X.toBytes(), PARSER.fromByteBuffer(X.toBytes()).toBytes())
public interface SSHSerializable<T> {
    interface Parser<T extends SSHSerializable<T>> {
        T fromByteBuffer(ByteBuffer src);

        default T fromBytes(byte[] src) {
            return fromByteBuffer(ByteBuffer.wrap(src));
        }
    }

    byte[] toBytes();
}

// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.dtbs;

import pro.javacard.ssh.openssh.SSHPatternMatcher;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.nio.ByteBuffer;
import java.util.List;

@SuppressWarnings("ArrayRecordComponent")
public sealed interface DTBSPayload<T> extends SSHSerializable<T> permits CertificatePayload, GenericPayload, UserAuthPayload, SSHSIGPayload {
    String pattern();

    byte[] dtbs();

    static DTBSPayload<?> PARSER(ByteBuffer buffer) {
        var parsers = List.of(
                SSHSIGPayload.PARSER,
                CertificatePayload.PARSER,
                UserAuthPayload.PARSER,
                GenericPayload.PARSER
        );

        var position = buffer.position();
        for (var parser : parsers) {
            try {
                var payload = parser.fromByteBuffer(buffer);
                if (payload != null) {
                    return payload;
                }
            } catch (IllegalArgumentException e) {
                // Ignore
            } finally {
                buffer.position(position); // Reset buffer position
            }
        }
        throw new IllegalArgumentException("No valid parser found for the given buffer");
    }

    default boolean matches(List<String> patterns) {
        return SSHPatternMatcher.matches(pattern(), patterns);
    }

    @Override
    default byte[] toBytes() {
        // XXX: bytes wrapping?
        return SSHWireFormat.bytes(dtbs());
    }
}

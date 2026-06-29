// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.dtbs;

import pro.javacard.ssh.openssh.SSHSIG;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Logger;

@SuppressWarnings("ArrayRecordComponent")
public record SSHSIGPayload(byte[] dtbs, String namespace, byte[] reserved, String hash_algorithm,
                            byte[] hash) implements DTBSPayload<SSHSIGPayload> {
    private static final Logger log = Logger.getLogger(SSHSIGPayload.class.getName());

    public static final Parser<SSHSIGPayload> PARSER = SSHSIGPayload::fromByteBuffer;

    // Described in https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L79
    public static SSHSIGPayload fromByteBuffer(ByteBuffer buffer) {
        var start = buffer.position();
        var magic = new byte[SSHSIG.MAGIC_LEN];
        buffer.get(magic);
        if (!Arrays.equals(SSHSIG.MAGIC(), magic)) {
            throw new IllegalArgumentException("Invalid magic: %s".formatted(Helpers.toHex(magic)));
        }
        var namespace = SSHWireFormat.get_string(buffer);
        var reserved = SSHWireFormat.get_bytes(buffer);
        if (reserved.length != 0) {
            log.warning("Reserved field is not empty: %s".formatted(Helpers.toHex(reserved)));
        }
        var hash_algorithm = SSHWireFormat.get_string(buffer);
        var hash = SSHWireFormat.get_bytes(buffer);
        byte[] data = new byte[buffer.position() - start];
        buffer.position(start);
        buffer.get(data);
        return new SSHSIGPayload(data, namespace, reserved, hash_algorithm, hash);
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.write(SSHSIG.MAGIC());
            bin.ssh_string(namespace);
            bin.ssh_bytes(reserved);
            bin.ssh_string(hash_algorithm);
            bin.ssh_bytes(hash);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String pattern() {
        return "sshsig:" + namespace;
    }
}

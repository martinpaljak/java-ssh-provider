// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.utils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public final class SSHWireFormat {
    public static final int MAX_MESSAGE_LENGTH = Short.MAX_VALUE * 8; // 256KB

    private SSHWireFormat() {
    }

    public static class SSHWireOutputStream extends OutputStream {
        final DataOutputStream data;
        final ByteArrayOutputStream bos;

        SSHWireOutputStream(ByteArrayOutputStream out) {
            bos = out;
            data = new DataOutputStream(out);
        }

        public void ssh_uint32(int i) throws IOException {
            if (i < 0) {
                throw new IllegalArgumentException("must be positive: " + i);
            }
            data.writeInt(i);
        }

        public void ssh_uint32(long i) throws IOException {
            if (i < 0 || i > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("must be positive and fit in 32 bits: " + i);
            }
            data.writeInt((int) i);
        }

        @Override
        public void write(int b) throws IOException {
            data.write(b);
        }

        public void ssh_bytes(byte[] d) throws IOException {
            ssh_uint32(d.length);
            write(d);
        }

        public void ssh_string(String s) throws IOException {
            ssh_bytes(s.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public void flush() throws IOException {
            data.flush();
        }

        public byte[] bytes() {
            return bos.toByteArray();
        }
    }

    public static SSHWireOutputStream create() {
        return new SSHWireOutputStream(new ByteArrayOutputStream());
    }

    public static byte[] bytes(byte[] bytes) {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_bytes(bytes);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] string(String s) {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(s);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String get_string(ByteBuffer buffer) {
        var str = get_bytes(buffer);
        return new String(str, StandardCharsets.UTF_8);
    }

    // Meant for "relatively short" ASCII strings that could be logged
    // This means type identifiers mostly.
    public static String get_safe_string(ByteBuffer buffer) {
        var bytes = get_bytes(buffer);
        if (bytes.length > 256) {
            throw new IllegalArgumentException("String too long: " + bytes.length);
        }
        for (var b : bytes) {
            if (b < 32 || b > 126) {
                throw new IllegalArgumentException("Invalid character in string: " + Integer.toHexString(b));
            }
        }
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    public static int get_uint32(ByteBuffer buffer) {
        var i = buffer.getInt();
        if (i < 0) {
            throw new IllegalArgumentException("i must be positive");
        }
        return i;
    }

    public static byte[] get_bytes(ByteBuffer buffer) {
        var len = buffer.getInt();
        if (len < 0 || len > MAX_MESSAGE_LENGTH) {
            throw new IllegalArgumentException("Invalid length: for chunk " + len);
        }
        var str = new byte[len];
        buffer.get(str);
        return str;
    }

    public static boolean get_boolean(ByteBuffer buffer) {
        // RFC 4251 section 5: Boolean value
        // All non-zero values MUST be interpreted as TRUE; however,
        // applications MUST NOT store values other than 0 and 1.
        return buffer.get() != 0;
    }
}

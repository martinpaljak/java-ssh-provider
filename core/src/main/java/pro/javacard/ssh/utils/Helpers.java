// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

public final class Helpers {

    private Helpers() {
    }

    public static byte[] sha256(byte[] data) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] random(int length) {
        try {
            var bytes = new byte[length];
            SecureRandom.getInstanceStrong().nextBytes(bytes);
            return bytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String dump_next(ByteBuffer buffer, int n) {
        buffer.mark();
        if (buffer.position() + n > buffer.limit()) {
            n = buffer.limit() - buffer.position();
        }
        var d = new byte[n];
        buffer.get(d);
        buffer.reset();
        return "Next %d bytes: %s".formatted(n, toHex(d));
    }

    public static byte[] reverse(byte[] d) {
        var r = new byte[d.length];
        for (var i = 0; i < d.length; i++) {
            r[i] = d[d.length - 1 - i];
        }
        return r;
    }

    public static <K, V> K reverse(Map<K, V> map, V value) {
        return map.entrySet().stream().filter(e -> e.getValue().equals(value)).map(Map.Entry::getKey).findFirst().orElseThrow();
    }

    public static EdECPublicKey ed25519_bytes2pubkey(byte[] bytes) {
        // RCF 8032 5.1.2 and 5.1.3
        try {
            var kf = KeyFactory.getInstance("EdDSA");
            var xOdd = (bytes[bytes.length - 1] & 0x80) == 0x80;
            bytes[bytes.length - 1] &= 0x7F; // mask out the high bit
            var y = new BigInteger(1, reverse(bytes));
            var paramSpec = new NamedParameterSpec("Ed25519");
            var pubSpec = new EdECPublicKeySpec(paramSpec, new EdECPoint(xOdd, y));
            return (EdECPublicKey) kf.generatePublic(pubSpec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Can not handle ed25519");
        }
    }

    public static ECParameterSpec getCurveParams(String stdName) {
        // Get the named parameters using standard AlgorithmParameters
        AlgorithmParameters params;
        try {
            params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(stdName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new RuntimeException("Error getting curve parameters: " + e.getMessage());
        }
    }

    public static byte[] concatenate(byte[]... args) {
        int length = 0, pos = 0;
        for (var arg : args) {
            length += arg.length;
        }
        var result = new byte[length];
        for (var arg : args) {
            System.arraycopy(arg, 0, result, pos, arg.length);
            pos += arg.length;
        }
        return result;
    }

    // Right-align byte array to the specified size, padding with 0 from left if needed,
    // taking only rightmost bytes if more than len present
    public static byte[] leftpad(byte[] bytes, int len) {
        var nv = new byte[len];
        if (bytes.length < len) {
            System.arraycopy(bytes, 0, nv, len - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - len, nv, 0, len);
        }
        return nv;
    }

    public static String toHex(ByteBuffer buffer) {
        var d = new byte[buffer.limit()];
        buffer.get(0, d);
        return toHex(d);
    }

    // Remove leading 0x00 byte from a positive bignum
    // Assumes the bignum length must be even number of bytes
    public static byte[] positive(byte[] bytes) {
        if (bytes[0] == 0 && bytes.length % 2 == 1) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    public static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64(String s) {
        return Base64.getDecoder().decode(s);
    }

    public static String base64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static String toHex(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    public static byte[] fromHex(String hex) {
        return HexFormat.of().parseHex(hex);
    }

    public static byte[] der2rs(byte[] der, int componentLen) {
        ByteBuffer buffer = ByteBuffer.wrap(der);
        if (buffer.get() != 0x30) {
            throw new IllegalArgumentException("Expected SEQUENCE tag");
        }
        int len = get_der_len(buffer);
        if (len != buffer.remaining()) {
            throw new IllegalArgumentException("Length mismatch");
        }
        byte[] r = get_der_bigint(buffer);
        byte[] s = get_der_bigint(buffer);
        return concatenate(leftpad(r, componentLen), leftpad(s, componentLen));
    }

    private static int get_der_len(ByteBuffer buffer) {
        int b1 = buffer.get() & 0xFF;

        // Short form
        if ((b1 & 0x80) == 0) {
            return b1;
        }

        // Only support single-byte long form (0x81)
        if (b1 != 0x81) {
            throw new IllegalArgumentException("Only single-byte long form DER length supported");
        }
        return buffer.get() & 0xFF;
    }

    private static byte[] get_der_bigint(ByteBuffer buffer) {
        if (buffer.get() != 0x02) {
            throw new IllegalArgumentException("Expected INTEGER tag");
        }
        int length = get_der_len(buffer);
        byte[] value = new byte[length];
        buffer.get(value);

        // Remove padding zero byte if present
        if (length > 1 && value[0] == 0x00 && (value[1] & 0x80) != 0) {
            return Arrays.copyOfRange(value, 1, value.length);
        }
        return value;
    }

    private static byte[] with_der_len(byte[] data) {
        int length = data.length;
        if (length < 128) {
            return concatenate(new byte[]{(byte) length}, data);
        } else if (length <= 255) {
            return concatenate(new byte[]{(byte) 0x81, (byte) length}, data);
        } else {
            throw new IllegalArgumentException("Length too large for single-byte encoding");
        }
    }

    public static byte[] rs2der(byte[] r, byte[] s) {
        BigInteger br = new BigInteger(1, r);
        BigInteger bs = new BigInteger(1, s);

        byte[] dr = with_der_len(br.toByteArray());
        byte[] ds = with_der_len(bs.toByteArray());

        return concatenate(new byte[]{0x30}, with_der_len(concatenate(concatenate(new byte[]{0x02}, dr), concatenate(new byte[]{0x02}, ds))));
    }
}

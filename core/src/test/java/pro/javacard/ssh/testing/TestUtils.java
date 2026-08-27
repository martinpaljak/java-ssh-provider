// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.testing;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

public final class TestUtils {
    public static byte[] randomBytes(int len) {
        try {
            byte[] bytes = new byte[len];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(bytes);
            return bytes;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair makeKeyPair(String algorithm) {
        try {
            switch (algorithm) {
                case "RSA":
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(2048);
                    return kpg.generateKeyPair();
                case "secp256r1":
                case "secp384r1":
                case "secp521r1":
                    kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(new ECGenParameterSpec(algorithm));
                    return kpg.generateKeyPair();
                case "Ed25519":
                    kpg = KeyPairGenerator.getInstance("Ed25519");
                    return kpg.generateKeyPair();
                default:
                    throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    // Test fixtures live in this module; their packages aren't opened to other modules.
    public static InputStream resource(String name) {
        return Objects.requireNonNull(TestUtils.class.getResourceAsStream(name), name);
    }

    public static String resourceString(String name) throws IOException {
        return new String(resource(name).readAllBytes(), StandardCharsets.UTF_8);
    }

    public static void check_remaining(ByteBuffer buffer, int start, int expected) {
        if (buffer.position() != start + expected) {
            throw new IllegalArgumentException("Length mismatch: expect to be at position " + (start + expected) + " but is at " + buffer.position());
        }
    }

    public static void main(String[] args) {
        var kp = makeKeyPair("secp256r1");
        System.out.println(((ECPrivateKey)kp.getPrivate()).getS().toString(16));
    }
}

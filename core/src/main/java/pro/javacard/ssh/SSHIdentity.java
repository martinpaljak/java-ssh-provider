// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public sealed interface SSHIdentity permits SSHCertificate, SSHIdentityWithComment, SSHOpaqueIdentity, SSHPublicKey, SSHX509Certificate {
    Logger log = Logger.getLogger(SSHIdentity.class.getName());

    // Parses a SSHPublicKey or SSHCertificate _without_ the comment
    static SSHIdentity fromByteBuffer(ByteBuffer buffer) throws IllegalArgumentException {
        // Peek the type
        buffer.mark();
        var type = SSHWireFormat.get_safe_string(buffer);
        buffer.reset();
        log.log(Level.FINE, "loading identity: %s".formatted(type));

        if (KeyConf.cert.containsKey(type)) {
            var cert = SSHCertificate.PARSER.fromByteBuffer(buffer);
            try {
                // Verify signature
                if (!cert.getSignature().verify(cert.dtbs(), cert.getSignatureKey())) {
                    log.severe("Certificate signature verification failed");
                    // NOTE: might want to create a custom exception
                    throw new IllegalArgumentException("Certificate signature verification failed");
                }
                return cert;
            } catch (GeneralSecurityException e) {
                log.severe("Certificate signature verification errored: %s".formatted(e.getMessage()));
                throw new IllegalArgumentException("Certificate signature verification errored");
            }
        } else if (SSHX509Certificate.x509cert2ssheky.containsKey(type)) {
            return SSHX509Certificate.PARSER.fromByteBuffer(buffer);
        } else if (KeyConf.sshtype.containsKey(type)) {
            return SSHPublicKey.PARSER.fromByteBuffer(buffer);
        } else {
            log.warning("Unknown SSH key type: " + type + ", treating as opaque");
            return SSHOpaqueIdentity.fromBuffer(type, buffer);
        }
    }

    // Parse a plain public key. These come from safe sources (local filesystem)
    static SSHIdentity fromString(String line) throws IllegalArgumentException {
        line = line.trim();

        final var regex = "^(\\S+)\\s+(\\S+)(?:\\s+(.*))?\\R?$";

        var pattern = Pattern.compile(regex);
        var matcher = pattern.matcher(line);
        if (matcher.matches()) {
            log.log(Level.FINE, "loading string identity: %s".formatted(matcher.group(1)));
            var key = Base64.getDecoder().decode(matcher.group(2));
            var buffer = ByteBuffer.wrap(key);
            var identity = fromByteBuffer(buffer);
            if (matcher.groupCount() > 2) {
                return identity.withComment(matcher.group(3));
            } else {
                return identity;
            }
        } else {
            throw new IllegalArgumentException("Invalid identity line: " + line);
        }
    }

    static SSHIdentity from(Object o) {
        return switch (o) {
            case SSHIdentity identity -> identity;
            case PublicKey pub -> SSHPublicKey.fromJavaKey(pub);
            case X509Certificate x509 -> SSHX509Certificate.fromJava(x509);
            case String string -> SSHIdentity.fromString(string);
            case byte[] blob -> SSHIdentity.fromByteBuffer(ByteBuffer.wrap(blob));
            case InputStream in -> {
                try {
                    yield SSHIdentity.fromString(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
            case Path path -> {
                try {
                    yield SSHIdentity.fromString(Files.readString(path));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
            default -> throw new IllegalArgumentException("Invalid object: " + o);
        };
    }

    // Returns the type of the identity (key or cert type)
    String getSSHType();

    // Returns the SHA-256 hash of the contained entity
    byte[] getHash();

    // Converts the identity to a byte array, without comment
    byte[] toBytes();

    default String asString() {
        return getSSHType() + " " + Helpers.base64(toBytes());
    }

    // The key itself or the key of the certificate
    // NOTE: we leave getPublicKey() for SSHCertificate for it to be able to subclass Certificate
    SSHPublicKey getKey();

    default Optional<String> getComment() {
        return Optional.empty();
    }

    default String getFingerprint() {
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(getHash());
    }

    // Add a comment to any identity.
    default SSHIdentityWithComment<? extends SSHIdentity> withComment(String comment) {
        // NOTE: multiple withComment() calls will always wrap the original identity
        return new SSHIdentityWithComment<>(this instanceof SSHIdentityWithComment<?> with ? with.identity() : this, comment);
    }

    // Returns the true type of the identity, even if wrapped with a comment
    default SSHIdentity real() {
        return this instanceof SSHIdentityWithComment<?> with ? with.identity() : this;
    }

    // Type mangling helpers
    default <T extends SSHIdentity> Optional<T> as(Class<T> clazz) {
        //var real = this instanceof SSHIdentityWithComment<?> with ? with.identity() : this;
        var real = real();
        return clazz.isInstance(real) ? Optional.of(clazz.cast(real)) : Optional.empty();
    }

    default boolean isKey() {
        return as(SSHPublicKey.class).isPresent();
    }

    default Optional<SSHPublicKey> asKey() {
        return as(SSHPublicKey.class);
    }

    default boolean isX509() {
        return as(SSHX509Certificate.class).isPresent();
    }

    default Optional<SSHX509Certificate> asX509() {
        return as(SSHX509Certificate.class);
    }

    default boolean isCert() {
        return as(SSHCertificate.class).isPresent();
    }

    default Optional<SSHCertificate> asCert() {
        return as(SSHCertificate.class);
    }
}

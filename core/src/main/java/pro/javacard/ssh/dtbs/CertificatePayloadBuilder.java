// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.dtbs;

import pro.javacard.ssh.*;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public final class CertificatePayloadBuilder {
    public static final int DEFAULT_NONCE_LENGTH = 16;

    private String type;
    private byte[] nonce = Helpers.random(DEFAULT_NONCE_LENGTH);
    private SSHPublicKey publicKey;
    private BigInteger serial = BigInteger.ZERO;
    private int certType;
    private String id;
    private List<String> principals;
    private long after = 0;
    private Instant afterInstant = Instant.EPOCH;
    private long before = -1;
    private Instant beforeInstant = Instant.MAX;
    private Map<String, byte[]> options;
    private Map<String, byte[]> extensions;
    private byte[] reserved = new byte[0];
    private SSHPublicKey signKey;

    public CertificatePayloadBuilder() {
        this.principals = new ArrayList<>();
        this.options = new LinkedHashMap<>();
        this.extensions = new LinkedHashMap<>();
    }

    public CertificatePayloadBuilder nonce(byte[] nonce) {
        this.nonce = nonce.clone();
        return this;
    }

    public CertificatePayloadBuilder publicKey(SSHPublicKey publicKey) {
        this.publicKey = publicKey;
        this.type = KeyConf.fromSSH(publicKey.getSSHType()).certType;
        return this;
    }

    public CertificatePayloadBuilder serial(BigInteger serial) {
        this.serial = serial;
        return this;
    }

    public CertificatePayloadBuilder certType(SSHCertificate.Type certType) {
        this.certType = switch (certType) {
            case USER -> 1;
            case HOST -> 2;
        };
        return this;
    }

    public CertificatePayloadBuilder id(String id) {
        this.id = id;
        return this;
    }

    public CertificatePayloadBuilder principals(List<String> principals) {
        this.principals = new ArrayList<>(principals);
        return this;
    }

    public CertificatePayloadBuilder addPrincipal(String principal) {
        this.principals.add(principal);
        return this;
    }

    @SuppressWarnings("UnusedMethod")
    private CertificatePayloadBuilder after(long after) {
        this.after = after;
        return this;
    }

    public CertificatePayloadBuilder after(Instant after) {
        if (after.isBefore(Instant.EPOCH))
            throw new IllegalArgumentException("After must be after epoch");
        if (after.isAfter(beforeInstant))
            throw new IllegalArgumentException("After must be before before");
        this.after = after.getEpochSecond();
        this.afterInstant = after;
        return this;
    }

    @SuppressWarnings("UnusedMethod")
    private CertificatePayloadBuilder before(long before) {
        this.before = before;
        return this;
    }

    public CertificatePayloadBuilder before(Instant before) {
        if (before.isBefore(afterInstant))
            throw new IllegalArgumentException("Before must be after after");
        if (before.equals(Instant.MAX)) {
            this.before = -1;
        } else {
            this.before = before.getEpochSecond();
        }
        beforeInstant = before;
        return this;
    }

    public CertificatePayloadBuilder options(Map<String, byte[]> options) {
        this.options = new LinkedHashMap<>(options);
        return this;
    }

    public CertificatePayloadBuilder addOption(String key, byte[] value) {
        this.options.put(key, value);
        return this;
    }

    public CertificatePayloadBuilder extensions(Map<String, byte[]> extensions) {
        this.extensions = new LinkedHashMap<>(extensions);
        return this;
    }

    public CertificatePayloadBuilder addExtension(String key, byte[] value) {
        this.extensions.put(key, value);
        return this;
    }

    public CertificatePayloadBuilder signKey(SSHPublicKey signKey) {
        this.signKey = signKey;
        return this;
    }

    public CertificatePayloadBuilder reserved(byte[] reserved) {
        this.reserved = reserved.clone();
        return this;
    }

    private byte[] serializeOptions(Map<String, byte[]> options) throws IOException {
        try (var stream = SSHWireFormat.create()) {
            for (var entry : options.entrySet()) {
                stream.ssh_string(entry.getKey());
                stream.ssh_bytes(entry.getValue());
            }
            return stream.bytes();
        }
    }

    public CertificatePayload build() {
        // Validate required fields
        if (type == null) throw new IllegalStateException("Type must be set");
        if (publicKey == null) throw new IllegalStateException("Public key must be set");
        if (serial == null) throw new IllegalStateException("Serial must be set");
        if (certType == 0) throw new IllegalStateException("Certificate type must be set");
        if (id == null) throw new IllegalStateException("ID must be set");
        if (signKey == null) throw new IllegalStateException("Sign key must be set");


        try (var stream = SSHWireFormat.create()) {
            stream.ssh_string(type);
            stream.ssh_bytes(nonce);
            // Serialize the public key _contents_ (not the key itself, which includes the type header)
            stream.write(publicKey.getContainer().toBytes());

            // Write serial as uint64 (8 bytes)
            stream.write(Helpers.leftpad(serial.toByteArray(), 8));

            // Write cert type as uint32
            stream.ssh_uint32(certType);

            // Write key id
            stream.ssh_string(id);

            // Write principals
            try (var principalsStream = SSHWireFormat.create()) {
                for (String principal : principals) {
                    principalsStream.ssh_string(principal);
                }
                stream.ssh_bytes(principalsStream.bytes());
            }

            // Write valid after and before as uint64
            byte[] afterBytes = new byte[8];
            ByteBuffer.wrap(afterBytes).putLong(after);
            stream.write(afterBytes);

            byte[] beforeBytes = new byte[8];
            ByteBuffer.wrap(beforeBytes).putLong(before);
            stream.write(beforeBytes);

            // Write critical options
            stream.ssh_bytes(serializeOptions(options));

            // Write extensions
            stream.ssh_bytes(serializeOptions(extensions));

            // Write reserved field (empty string)
            stream.ssh_bytes(reserved);

            // Write signature key (with type)
            stream.ssh_bytes(signKey.toBytes());

            byte[] dtbs = stream.bytes();

            return new CertificatePayload(
                    dtbs,
                    type,
                    nonce,
                    publicKey,
                    serial,
                    SSHCertificate.Type.of(certType),
                    id,
                    principals,
                    after,
                    before,
                    options,
                    extensions,
                    signKey
            );
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize certificate payload", e);
        }
    }

    // Signer decides the signature format.
    public CompletableFuture<SSHCertificate> sign(SSHSigner signer) {
        var payload = build();
        var signature = signer.sign(payload.dtbs());
        return signature.thenApply(sig -> {
            System.out.println("Signature: " + Helpers.toHex(sig.toBytes()));
            SSHSignature sig2 = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sig.toBytes()));
            System.out.println("Signature: " + sig2);
            var certbytes = Helpers.concatenate(payload.dtbs(), SSHWireFormat.bytes(sig.toBytes()));
            //var certbytes = Helpers.concatenate(payload.dtbs(), sig.toBytes());
            var cert = SSHCertificate.fromByteBuffer(ByteBuffer.wrap(certbytes));
            //try {
            // Verify the certificate signature to match the key embedded in payload
            // cert.verify(signKey);
            return cert;
            //} catch (GeneralSecurityException e) {
            //    System.out.println("Failed to verify certificate: " + e.getMessage());
            //    throw new RuntimeException(e.getCause());
            //}
        });
    }
}
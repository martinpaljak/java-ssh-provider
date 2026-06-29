// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.dtbs;

import pro.javacard.ssh.KeyConf;
import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.openssh.SSHPatternMatcher;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;

@SuppressWarnings("ArrayRecordComponent")
public record CertificatePayload(byte[] dtbs, String type, byte[] nonce, SSHPublicKey publicKey, BigInteger serial,
                                 SSHCertificate.Type certType,
                                 String id, List<String> principals, long after, long before,
                                 Map<String, byte[]> options, Map<String, byte[]> extensions,
                                 SSHPublicKey signKey) implements DTBSPayload<CertificatePayload> {
    private static final Logger log = Logger.getLogger(CertificatePayload.class.getName());
    //    string    type
    //    string    nonce
    //    ... key values
    //    uint64    serial
    //    uint32    type
    //    string    key id
    //    string    valid principals
    //    uint64    valid after
    //    uint64    valid before
    //    string    critical options
    //    string    extensions
    //    string    reserved
    //    string    signature key

    public CertificatePayload {
        if (before < -1 || before == 0) {
            throw new IllegalArgumentException("Invalid before: " + before);
        }
        if (after < 0 || (before != -1 && after > before)) {
            throw new IllegalArgumentException("Invalid after: " + after);
        }
    }

    static Map<String, byte[]> parse_options(ByteBuffer buffer) {
        var options = new LinkedHashMap<String, byte[]>();

        for (var i = 0; i < 20 && buffer.hasRemaining(); i++) {
            var k = SSHWireFormat.get_safe_string(buffer);
            var v = SSHWireFormat.get_bytes(buffer);
            log.finer("Extension %s=%s".formatted(k, Helpers.toHex(v)));
            options.put(k, v);
        }
        return options;
    }

    public static final Parser<CertificatePayload> PARSER = buffer -> {
        int start = buffer.position();
        var type = SSHWireFormat.get_safe_string(buffer);

        var nonce = SSHWireFormat.get_bytes(buffer);

        // read the key
        var keytype = KeyConf.fromCert(type);
        var key = SSHPublicKey.parse(keytype, buffer);

        var serial = new byte[8];
        buffer.get(serial);

        int cert_type = buffer.getInt();
        var key_id = SSHWireFormat.get_string(buffer);

        var principals_len = buffer.getInt();
        var principals_end = buffer.position() + principals_len;
        List<String> principals = new ArrayList<>();
        while (buffer.position() < principals_end) {
            var principal = SSHWireFormat.get_string(buffer);
            principals.add(principal);
        }

        var after = buffer.getLong();
        if (after < 0) {
            throw new IllegalArgumentException("Invalid after: " + after);
        }
        var before = buffer.getLong();
        if (before < -1 || before == 0) {
            throw new IllegalArgumentException("Invalid before: " + before);
        }

        var critical_bytes = SSHWireFormat.get_bytes(buffer);
        var critical_options = parse_options(ByteBuffer.wrap(critical_bytes));

        var extension_bytes = SSHWireFormat.get_bytes(buffer);
        var extensions = parse_options(ByteBuffer.wrap(extension_bytes));


        var reserved = SSHWireFormat.get_bytes(buffer);
        if (reserved.length != 0) {
            log.warning("Reserved is not empty: " + Helpers.toHex(reserved));
        }

        var signature_key = SSHWireFormat.get_bytes(buffer);
        var sig_key = SSHPublicKey.PARSER.fromByteBuffer(ByteBuffer.wrap(signature_key));
        byte[] dtbs = new byte[buffer.position() - start];
        buffer.position(start);
        buffer.get(dtbs);
        return new CertificatePayload(dtbs, type, nonce, key, new BigInteger(1, serial), SSHCertificate.Type.of(cert_type), key_id,
                principals, after, before, critical_options, extensions, sig_key);
    };


    public Instant notBefore() {
        return Instant.ofEpochSecond(after);
    }

    public Instant notAfter() {
        return before == -1 ? Instant.MAX : Instant.ofEpochSecond(before);
    }

    @Override
    public byte[] toBytes() {
        return dtbs();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof CertificatePayload other) {
            return Arrays.equals(dtbs, other.dtbs);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(dtbs);
    }

    @Override
    public String pattern() {
        return "cert:" + id;
    }

    // Matches when any principal matches
    @Override
    public boolean matches(List<String> patterns) {
        for (var s : principals) {
            if (SSHPatternMatcher.matches("cert:" + s, patterns)) {
                return true;
            }
        }
        return false;
    }

}

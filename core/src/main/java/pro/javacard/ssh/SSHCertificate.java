// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.dtbs.CertificatePayload;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.Serial;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

// Defined in https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
// NOTE: it implements PublicKey to be able to pass it to Signature.initVerify and Signature.initSign for SSHSIG purposes
// NOTE: it extends Certificate mostly for purity, not for actual use (most software will barf on non-X509 certificates)
public final class SSHCertificate extends Certificate implements SSHIdentity, PublicKey, SSHSerializable<SSHCertificate> {
    @Serial
    private static final long serialVersionUID = 3413623631804034714L;

    private static final Logger log = Logger.getLogger(SSHCertificate.class.getName());

    private final byte[] cert; // Full certificate blob
    private final int dtbs_len; // Data to be signed length, relative to cert beginning
    private final byte[] objectHash;

    private final transient CertificatePayload payload;

    // All above payload is covered by this signature
    private final transient SSHSignature sig;

    public static final Parser<SSHCertificate> PARSER = SSHCertificate::fromByteBuffer;

    @Override
    public SSHPublicKey getKey() {
        return payload.publicKey();
    }

    @Override
    public byte[] toBytes() {
        return cert.clone();
    }

    @Override
    public byte[] getHash() {
        return objectHash.clone();
    }

    @Override
    public String getSSHType() {
        return payload.type();
    }

    public enum Type {
        USER, HOST;

        public static Type of(int type) {
            return switch (type) {
                case 1 -> SSHCertificate.Type.USER;
                case 2 -> SSHCertificate.Type.HOST;
                default -> throw new IllegalArgumentException("Unknown SSH Certificate type: " + type);
            };
        }
    }

    public static SSHCertificate of(SSHIdentity i) {
        return i.as(SSHCertificate.class).orElse(null);
    }

    SSHCertificate(CertificatePayload payload, byte[] blob, int dtbs_len, SSHSignature sig) {
        super("SSH");
        this.payload = payload;
        this.cert = blob.clone();
        this.dtbs_len = dtbs_len;
        this.sig = sig;
        this.objectHash = Helpers.sha256(cert);
    }

    public byte[] dtbs() {
        return Arrays.copyOf(cert, dtbs_len);
    }

    public SSHSignature getSignature() {
        return sig;
    }

    public SSHPublicKey getSignatureKey() {
        return payload.signKey();
    }

    public List<String> getPrincipals() {
        return payload.principals();
    }

    public CertificatePayload getPayload() {
        return payload;
    }

    public static SSHCertificate fromByteBuffer(ByteBuffer buffer) {
        var start = buffer.position();
        var payload = CertificatePayload.PARSER.fromByteBuffer(buffer);
        // from PROTOCOL.certkeys: "signature is computed over all preceding fields
        // from the initial string up to, and including the signature key."
        var dtbs_len = buffer.position() - start;
        var sig_bytes = SSHWireFormat.get_bytes(buffer);
        var sig = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sig_bytes));
        log.finest("Signature: %s".formatted(sig));
        var end = buffer.position();
        var full_cert = new byte[end - start];
        buffer.position(start);
        buffer.get(full_cert);
        return new SSHCertificate(payload, full_cert, dtbs_len, sig);
    }

    public boolean valid(Clock clock) {
        var now = clock.instant().getEpochSecond();
        log.finest("now: %d before: %d after: %d".formatted(now, payload.before(), payload.after()));
        return payload.after() <= now && (payload.before() == -1 || now <= payload.before());
    }

    // From java.security.cert.Certificate
    @Override
    public PublicKey getPublicKey() {
        return payload.publicKey();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        if (!payload.signKey().equals(SSHPublicKey.fromJavaKey(key))) {
            throw new SignatureException("Verification key does not match the signing key in the certificate");
        }
        if (!getSignature().verify(dtbs(), key)) {
            throw new SignatureException("Signature verification failed");
        }
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        throw new NoSuchProviderException("Signature provider must always be the SSHProvider");
    }

    // From Certificate AND PublicKey
    // We return the certificate as in SSH context a certificate is a "signed public key"
    @Override
    public byte[] getEncoded() {
        return cert.clone();
    }

    // From PublicKey
    @Override
    public String getAlgorithm() {
        return getKey().getAlgorithm();
    }

    @Override
    public String getFormat() {
        return "SSH";
    }

    // From Object
    @Override
    public String toString() {
        return "SSHCertificate[%s for %s with %s by %s]".formatted(payload.type(), payload.id(), payload.publicKey().getFingerprint(), getSignatureKey().getFingerprint());
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof SSHIdentity that) {
            return Arrays.equals(objectHash, that.getHash());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(objectHash);
    }

}

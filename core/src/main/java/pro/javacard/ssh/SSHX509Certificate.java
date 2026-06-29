// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serial;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Map;
import java.util.Set;

// X509Certificate wrapper that is also a SSHIdentity
// Unlike SSHCertificate, this class is not substitutable for a PublicKey
// See https://datatracker.ietf.org/doc/html/rfc6187#section-2.1
public final class SSHX509Certificate extends X509Certificate implements SSHIdentity, SSHSerializable<SSHX509Certificate> {
    @Serial
    private static final long serialVersionUID = -8586752507683058047L;

    private final transient X509Certificate x509;
    private final transient String type;

    static final Map<String, String> x509cert2ssheky = Map.of(
            "x509v3-rsa2048-sha256", "ssh-rsa",
            "x509v3-ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256",
            "x509v3-ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384",
            "x509v3-ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"
    );

    public SSHX509Certificate(String type, X509Certificate x509) {
        super();
        this.type = type;
        this.x509 = x509;
    }

    public static final SSHSerializable.Parser<SSHX509Certificate> PARSER = SSHX509Certificate::fromByteBuffer;

    public static SSHX509Certificate fromJava(X509Certificate x509) {
        // get the type
        SSHPublicKey sshpub = SSHPublicKey.fromJavaKey(x509.getPublicKey());
        var certtype = Helpers.reverse(x509cert2ssheky, sshpub.getSSHType());
        return new SSHX509Certificate(certtype, x509);
    }

    public static SSHX509Certificate fromByteBuffer(ByteBuffer src) {
        var type = SSHWireFormat.get_safe_string(src);
        var numder = src.getInt();
        if (numder != 1) {
            throw new IllegalArgumentException("Must have exactly one certificate");
        }
        var der = SSHWireFormat.get_bytes(src);
        var numocsp = src.getInt();
        if (numocsp != 0) {
            throw new IllegalArgumentException("Must have zero OCSP responses");
        }
        log.finest("X509Certificate type: %s".formatted(type));
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            return new SSHX509Certificate(type, x509);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(type);
            bin.ssh_uint32(1); // Single certificate
            bin.ssh_bytes(x509.getEncoded());
            bin.ssh_uint32(0); // No OCSP
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public String getSSHType() {
        return type;
    }

    @Override
    public byte[] getHash() {
        try {
            return Helpers.sha256(x509.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SSHPublicKey getKey() {
        return SSHPublicKey.fromJavaKey(x509.getPublicKey());
    }

    @Override
    public String toString() {
        return "X509Certificate: %s".formatted(x509.getSubjectX500Principal().toString());
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        x509.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        x509.checkValidity(date);
    }

    @Override
    public int getVersion() {
        return x509.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return x509.getSerialNumber();
    }

    @SuppressWarnings("deprecation")
    @Override
    public Principal getIssuerDN() {
        return x509.getIssuerDN();
    }

    @SuppressWarnings("deprecation")
    @Override
    public Principal getSubjectDN() {
        return x509.getSubjectDN();
    }

    @Override
    public Date getNotBefore() {
        return x509.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return x509.getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return x509.getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return x509.getSignature();
    }

    @Override
    public String getSigAlgName() {
        return x509.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return x509.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return x509.getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return x509.getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return x509.getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return x509.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        return x509.getBasicConstraints();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return x509.getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        x509.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        x509.verify(key, sigProvider);
    }

    @Override
    public PublicKey getPublicKey() {
        return x509.getPublicKey();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return x509.hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return x509.getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return x509.getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return x509.getExtensionValue(oid);
    }
}

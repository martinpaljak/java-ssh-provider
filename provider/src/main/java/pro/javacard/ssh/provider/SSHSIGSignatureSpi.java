// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.provider;

import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.SSHSigner;
import pro.javacard.ssh.openssh.SSHSIG;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.logging.Logger;

public final class SSHSIGSignatureSpi extends SignatureSpi {
    private static final Logger log = Logger.getLogger(SSHSIGSignatureSpi.class.getName());

    static final String DEFAULT_HASH = "SHA-512";

    final SSHProvider sshprovider = new SSHProvider();

    private enum State {
        UNINITIALIZED,
        PARAMETERIZED,
        SIGN,
        VERIFY
    }

    private State state = State.UNINITIALIZED;
    private MessageDigest digest;
    private SSHSIG.Hash hash;
    private SSHSIGAlgorithmParameterSpec params;
    private SSHPublicKey publicKey;
    private PrivateKey privateKey;
    private SSHIdentity identity;

    SSHSIGSignatureSpi() {
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        // Allow verification without parameters, but give a fat warning
        if (state == State.UNINITIALIZED) {
            log.severe("Initializing verification without providing at least namespace. This is NOT recommended!");
        }
        try {
            // Special case: SSHCertificate (as reported by SSHKeyStore)
            if (publicKey instanceof SSHIdentity id) {
                this.publicKey = id.getKey();
                this.identity = id;
            } else {
                this.publicKey = SSHPublicKey.fromJavaKey(publicKey);
                this.identity = this.publicKey;
            }
            this.hash = SSHSIG.Hash.fromJava(params == null ? DEFAULT_HASH : params.hash());
            this.digest = hash.digest();
        } catch (IllegalArgumentException e) {
            throw new InvalidKeyException(e);
        }
        state = State.VERIFY;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (state != State.PARAMETERIZED) {
            throw new InvalidKeyException("Namespace not set, call engineSetParameter first");
        }
        this.hash = SSHSIG.Hash.fromJava(params.hash());
        this.digest = hash.digest();
        // TLC - make sure all is covered
        if (privateKey instanceof SSHAgentPrivateKey agentkey) {
            this.identity = agentkey.identity;
        } else if (params instanceof SSHSIGSigningParameters sigspec) {
            this.identity = sigspec.identity();
        } else {
            throw new InvalidKeyException("No identity provided");
        }
        this.privateKey = privateKey;
        state = State.SIGN;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (state == State.SIGN || state == State.VERIFY) {
            digest.update(b);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (state == State.SIGN || state == State.VERIFY) {
            digest.update(b, off, len);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (state != State.SIGN) {
            throw new SignatureException("Not initialized");
        }

        var digested = digest.digest();
        digest.reset();

        // The key type is the signature type, except for RSA, where the signature type depends on the hash used.
        final String sigtype;
        if ("ssh-rsa".equals(identity.getKey().getSSHType())) {
            sigtype = hash == SSHSIG.Hash.SHA512 ? "rsa-sha2-512" : "rsa-sha2-256";
        } else {
            sigtype = identity.getKey().getSSHType();
        }
        log.fine("Signing algorithm: " + sigtype);

        try {
            return SSHSIG.sign_digest(signer(sigtype), params.namespace(), hash, digested).join().toBytes();
        } catch (CompletionException e) {
            throw new SignatureException("Could not sign: " + e.getCause().getMessage(), e.getCause());
        }
    }

    // Routes the signing through the sibling SSHSignatureSpi.
    private SSHSigner signer(String sigtype) {
        return new SSHSigner() {
            @Override
            public SSHIdentity identity() {
                return identity;
            }

            @Override
            public CompletableFuture<SSHSignature> sign(byte[] data) {
                try {
                    var sig = Signature.getInstance(sigtype, sshprovider);
                    // TODO: FIDO parameters for native keys?
                    sig.initSign(privateKey);
                    sig.update(data);
                    var ssig = SSHSignature.PARSER.fromBytes(sig.sign());
                    log.fine("SSHSignature: " + ssig);
                    return CompletableFuture.completedFuture(ssig);
                } catch (GeneralSecurityException e) {
                    return CompletableFuture.failedFuture(e);
                }
            }
        };
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (state != State.VERIFY) {
            throw new SignatureException("Not initialized");
        }

        log.info("SSHSignatureSpi: engineVerify %s with %s".formatted(publicKey.getSSHType(), publicKey.asString()));
        var digested = digest.digest();
        digest.reset();

        try {
            var sshsig = SSHSIG.PARSER.fromBytes(sigBytes);
            log.fine("SSHSIG type: " + sshsig.signature().type());

            var namespace = params == null ? sshsig.namespace() : params.namespace();

            if (identity instanceof SSHCertificate cert) {
                // NOTE: while the signature is given with the key, the blob payload may contain a certificate
                // If the Signature was initialized with a certificate, we need to check that the certificate matches
                if (!cert.equals(sshsig.signer())) {
                    throw new SignatureException("SSHSIG certificate mismatch: " + sshsig.signer() + " != " + cert);
                }
            } else {
                if (sshsig.signer().isCert()) {
                    log.warning("SSHSIG uses a certificate, but verification is done with a key");
                }
                if (!identity.getKey().equals(sshsig.signer().getKey())) {
                    throw new SignatureException("SSHSIG key mismatch: " + sshsig.signer() + " != " + identity.getKey());
                }
            }

            return sshsig.signature().verify(sshsig.dtbs(namespace, hash, digested), publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureException("Could not verify: " + e.getMessage(), e);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params instanceof SSHSIGAlgorithmParameterSpec spec) {
            this.params = spec;
            state = State.PARAMETERIZED;
        } else {
            throw new InvalidAlgorithmParameterException("Invalid parameter");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException("Not supported.");
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("Not supported.");
    }

    @SuppressWarnings("deprecation")
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("Not supported.");
    }
}

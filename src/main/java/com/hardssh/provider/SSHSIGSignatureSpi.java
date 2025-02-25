package com.hardssh.provider;

import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.openssh.SSHSIG;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.logging.Logger;

public final class SSHSIGSignatureSpi extends SignatureSpi {
    private static final Logger log = Logger.getLogger(SSHSIGSignatureSpi.class.getName());

    static final String DEFAULT_HASH = "SHA-512";

    static final Map<String, String> javahash2ssh = Map.of(
            "SHA-256", SSHSIG.SHA256,
            "SHA-512", SSHSIG.SHA512
    );

    private enum State {
        UNINITIALIZED,
        PARAMETERIZED,
        SIGN,
        VERIFY
    }

    private State state = State.UNINITIALIZED;
    private MessageDigest digest;
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
            digest = MessageDigest.getInstance(params == null ? DEFAULT_HASH : params.hash());
        } catch (IllegalArgumentException e) {
            throw new InvalidKeyException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256/SHA-512 not available", e);
        }
        state = State.VERIFY;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (state != State.PARAMETERIZED) {
            throw new InvalidKeyException("Namespace not set, call engineSetParameter first");
        }
        try {
            digest = MessageDigest.getInstance(params.hash());
            // TLC - make sure all is covered
            if (privateKey instanceof SSHAgentPrivateKey agentkey) {
                this.identity = agentkey.identity;
            } else if (params instanceof SSHSIGSigningParameters sigspec) {
                this.identity = sigspec.identity();
            } else {
                throw new InvalidKeyException("No identity provided");
            }
            this.privateKey = privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e);
        }
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

        // get and validate parameters
        SSHSIGSigningParameters sigspec = (SSHSIGSigningParameters) params;

        // hash data
        var hash = digest.digest();
        digest.reset();

        // The hash name in ssh lingo (tolower and remove -)
        var hash_algo = digest.getAlgorithm().toLowerCase().replace("-", "");

        try {
            // The key type is the signature type as well, unless it is RSA, when it depends on used hash.
            // UNLESS it is webauthn, when the signature type is unique
            final String sigtype;
            if ("ssh-rsa".equals(identity.getKey().getSSHType())) {
                sigtype = params.hash().equals("SHA-512") ? "rsa-sha2-512" : "rsa-sha2-256";
            } else {
                sigtype = identity.getKey().getSSHType();
            }

            log.fine("Signing algorithm: " + sigtype);

            // Construct SSHSignature
            var dtbs = SSHSIG.dtbs(sigspec.namespace(), hash_algo, hash);

            // We trigger our sibling SSHSignatureSpi here.
            Signature sig = Signature.getInstance(sigtype);
            // TODO: FIDO parameters for native keys ?
            sig.initSign(privateKey);
            sig.update(dtbs);
            var signature = sig.sign();

            // construct the SSHSIG from SSHSignature and parameters
            var ssig = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(signature));
            log.fine("SSHSignature: " + ssig);
            var sshsig = new SSHSIG(1, identity, sigspec.namespace(), new byte[0], hash_algo, ssig);
            return sshsig.toBytes();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (state != State.VERIFY) {
            throw new SignatureException("Not initialized");
        }

        log.info("SSHSignatureSpi: engineVerify %s with %s".formatted(publicKey.getSSHType(), publicKey.asString()));
        var hash = digest.digest();
        digest.reset();

        var hash_algo = digest.getAlgorithm().toLowerCase().replace("-", "");

        try {
            var sshsig = SSHSIG.PARSER.fromBytes(sigBytes);
            log.fine("SSHSIG type: " + sshsig.signature().type());

            var namespace = params == null ? sshsig.namespace() : params.namespace();

            if (params == null) {
                // verify that the hash in sshsig matches the default hash we use (SHA-512)
                if (!hash_algo.equals(sshsig.hash_algorithm())) {
                    throw new SignatureException("SSHSIG hash mismatch: " + sshsig.hash_algorithm() + " != " + hash_algo);
                }
            } else {
                // verify that the hash in sshsig matches the hash we use
                var paramhash = params.hash().toLowerCase().replace("-", "");
                if (!paramhash.equals(sshsig.hash_algorithm())) {
                    throw new SignatureException("SSHSIG hash mismatch: " + sshsig.hash_algorithm() + " != " + paramhash);
                }
            }

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

            // re-calculate the data to be signed
            var dtbs = SSHSIG.dtbs(namespace, hash_algo, hash);
            return sshsig.signature().verify(dtbs, publicKey);
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

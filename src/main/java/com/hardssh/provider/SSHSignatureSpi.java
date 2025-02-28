package com.hardssh.provider;

import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.agent.messages.AgentMessage;
import pro.javacard.ssh.agent.messages.SignRequest;
import pro.javacard.ssh.agent.messages.SignResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Logger;

import static pro.javacard.ssh.SSHSignature.SigConf.*;

public final class SSHSignatureSpi extends SignatureSpi {
    private static final Logger log = Logger.getLogger(SSHSignatureSpi.class.getName());
    static final Set<String> fidoAlgos = Set.of(FIDOED25519.sshsig, FIDOECDSA256.sshsig, WEBAUTHNECDSA256.sshsig);
    static final Set<String> sshAlgos = Set.of(RSA256.sshsig, RSA512.sshsig, ECDSA256.sshsig, ECDSA384.sshsig, ECDSA521.sshsig, ED25519.sshsig);
    static final Set<String> nativeAlgos = Set.of(RSA256.javasig, RSA512.javasig, ECDSA256.javasig, ECDSA384.javasig, ECDSA521.javasig, ED25519.javasig);

    enum State {
        UNINITIALIZED,
        PARAMETRIZED, // Includes FIDO parameters
        SIGN_AGENT_NATIVE, // generate a standard signature with agent private key
        SIGN_AGENT_SSH, // generate SSH signature with agent private key
        SIGN_SSH, // generate SSH signature with generic private key
        VERIFY // verify SSH signature with any public key
    }

    private State state = State.UNINITIALIZED;

    private final String algorithm;
    private Signature signature;
    private ByteArrayOutputStream bos;
    private SSHAgentPrivateKey keyref;
    private SSHPublicKey sshpub;
    private FIDOSignatureParameters fidoparams;

    SSHSignatureSpi(String algorith) {
        Objects.requireNonNull(algorith, "algorithm must not be null");
        log.fine("SSHSignatureSpi for " + algorith);
        this.algorithm = algorith;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        log.fine("SSHSignatureSpi: engineInitVerify with " + publicKey.getClass().getName());
        if (nativeAlgos.contains(algorithm)) {
            throw new InvalidKeyException("Use other provider to verify " + algorithm);
        }
        try {
            // Turn a plain public key into a SSHPublicKey, taking into account FIDO parameters
            sshpub = state == State.PARAMETRIZED ? SSHPublicKey.fromJavaKey(publicKey).toFIDO(fidoparams.appdata()) : SSHPublicKey.fromJavaKey(publicKey);
            bos = new ByteArrayOutputStream();
            state = State.VERIFY;
        } catch (IllegalArgumentException e) {
            throw new InvalidKeyException("Can not verify %s with %s: %s".formatted(algorithm, publicKey.getClass().getName(), e.getMessage()));
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        log.fine("SSHSignatureSpi engineInitSign: " + privateKey);
        Objects.requireNonNull(privateKey, "privateKey can not be null");
        try {
            if (privateKey instanceof SSHAgentPrivateKey sshpriv) {
                state = nativeAlgos.contains(algorithm) ? State.SIGN_AGENT_NATIVE : State.SIGN_AGENT_SSH;
                keyref = sshpriv;
            } else {
                if (nativeAlgos.contains(algorithm)) {
                    throw new InvalidKeyException("Use other provider to sign with " + algorithm);
                }
                state = State.SIGN_SSH;
                var sigconf = SSHSignature.SigConf.fromSSH(algorithm);
                signature = Signature.getInstance(sigconf.javasig);
                signature.initSign(privateKey);
            }
            bos = new ByteArrayOutputStream();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Can not init sign with private key for " + algorithm + ": " + e.getMessage());
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        switch (this.state) {
            case SIGN_AGENT_NATIVE, SIGN_AGENT_SSH, VERIFY, SIGN_SSH -> bos.write(b);
            default -> throw new SignatureException("Signature object not properly initialized: " + this.state);
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        Objects.requireNonNull(b, "bytes can not be null");
        switch (this.state) {
            case SIGN_AGENT_NATIVE, SIGN_AGENT_SSH, VERIFY, SIGN_SSH -> bos.write(b, off, len);
            default -> throw new SignatureException("Signature object not properly initialized: " + this.state);
        }
    }

    private SSHSignature agent_sign(byte[] dtbs, SSHAgentPrivateKey keyref) throws SignatureException {
        log.info("SSHSignatureSpi: agent_sign %s with %s".formatted(keyref, algorithm));
        try {
            int flags = switch (algorithm) {
                case "rsa-sha2-256", "SHA256withRSA" -> SignRequest.SSH_AGENT_RSA_SHA2_256;
                case "rsa-sha2-512", "SHA512withRSA" -> SignRequest.SSH_AGENT_RSA_SHA2_512;
                default -> 0;
            };
            var r = SSHKeyStoreSpi.runCommand(keyref.socket, new SignRequest(keyref.identity, dtbs, flags));
            var code = AgentMessage.identify(r);
            if (code == AgentMessage.SSH_AGENT_SIGN_RESPONSE) {
                var p = SignResponse.fromByteBuffer(r);
                return p.getSignature();
            } else {
                throw new SignatureException("Could not sign: " + AgentMessage.name(code));
            }
        } catch (IOException e) {
            throw new SignatureException("Can not transmit sign request: " + e.getMessage(), e);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        log.fine("SSHSignatureSpi: engineSign %s with %s".formatted(this.state, algorithm));
        try {
            return switch (this.state) {
                case SIGN_AGENT_NATIVE -> agent_sign(bos.toByteArray(), keyref).payload().toNative();
                case SIGN_AGENT_SSH -> agent_sign(bos.toByteArray(), keyref).toBytes();
                case SIGN_SSH -> {
                    signature.update(bos.toByteArray());
                    yield SSHSignature.java2ssh(signature.sign(), algorithm);
                }
                default -> throw new SignatureException("Signature object not in right state: " + this.state);
            };
        } finally {
            reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        Objects.requireNonNull(sigBytes, "signature can not be null");
        if (this.state != State.VERIFY) {
            throw new SignatureException("Signature object not properly initialized: " + this.state);
        }
        log.info("SSHSignatureSpi: engineVerify %s with %s".formatted(algorithm, sshpub.asString()));
        try {
            var sig = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sigBytes));
            return sig.verify(bos.toByteArray(), sshpub);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureException("Could not verify: " + e.getMessage(), e);
        } finally {
            reset();
        }
    }

    private void reset() {
        bos = new ByteArrayOutputStream();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("Not supported. Use engineSetParameter(AlgorithmParameterSpec params).");
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineGetParameter(String param) Not supported.");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (SSHSignature.SigConf.isNative(algorithm)) {
            throw new InvalidAlgorithmParameterException("Native algorithms do not support parameters");
        }
        if (!SSHSignature.SigConf.isFIDO(algorithm)) {
            throw new InvalidAlgorithmParameterException("Non-FIDO algorithms do not support parameters");
        }
        if (params == null) {
            this.fidoparams = null;
            this.state = State.UNINITIALIZED;
        } else if (params instanceof FIDOSignatureParameters fido) {
            this.fidoparams = fido;
            this.state = State.PARAMETRIZED;
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException("engineGetParameters not supported.");
    }
}

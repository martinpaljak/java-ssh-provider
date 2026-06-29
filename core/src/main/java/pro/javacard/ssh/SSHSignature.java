// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Logger;

@SuppressWarnings("ArrayRecordComponent")
public record SSHSignature(String type, SSHSignaturePayload<?> payload) implements SSHSerializable<SSHSignature> {

    private static final Logger log = Logger.getLogger(SSHSignature.class.getName());

    @SuppressWarnings("ImmutableEnumChecker")
    public enum SigConf {
        ED25519("ssh-ed25519", Ed25519Payload.PARSER, "Ed25519", KeyConf.ED25519),
        ECDSA256("ecdsa-sha2-nistp256", ECDSAPayload.PARSER, "SHA256withECDSA", KeyConf.SECP256R1),
        ECDSA384("ecdsa-sha2-nistp384", ECDSAPayload.PARSER, "SHA384withECDSA", KeyConf.SECP384R1),
        ECDSA521("ecdsa-sha2-nistp521", ECDSAPayload.PARSER, "SHA512withECDSA", KeyConf.SECP521R1),
        RSA256("rsa-sha2-256", RSAPayload.PARSER, "SHA256withRSA", KeyConf.RSA),
        RSA512("rsa-sha2-512", RSAPayload.PARSER, "SHA512withRSA", KeyConf.RSA),
        // FIDO signature types overlay the SSH signature types
        FIDOED25519("sk-ssh-ed25519@openssh.com", FIDOPayload.parser(Ed25519Payload.PARSER), ED25519.javasig, KeyConf.FIDO_ED25519),
        FIDOECDSA256("sk-ecdsa-sha2-nistp256@openssh.com", FIDOPayload.parser(ECDSAPayload.PARSER), ECDSA256.javasig, KeyConf.FIDO_SECP256R1),
        WEBAUTHNECDSA256("webauthn-sk-ecdsa-sha2-nistp256@openssh.com", WebAuthnPayload.parser(ECDSAPayload.PARSER), ECDSA256.javasig, KeyConf.FIDO_SECP256R1);

        public final String javasig;
        public final Parser<? extends SSHSignaturePayload<?>> parser;
        public final String sshsig;
        public final KeyConf key;

        SigConf(String sshsig, Parser<? extends SSHSignaturePayload<?>> parser, String javasig, KeyConf key) {
            this.javasig = javasig;
            this.parser = parser;
            this.sshsig = sshsig;
            this.key = key;
        }

        public static SigConf fromSSH(String sshsig) {
            for (SigConf sc : SigConf.values()) {
                if (sc.sshsig.equals(sshsig)) {
                    return sc;
                }
            }
            throw new IllegalArgumentException("Unknown SSH signature type: " + sshsig);
        }

        public static boolean isFIDO(String sshsig) {
            var e = fromSSH(sshsig);
            return Set.of(FIDOED25519, FIDOECDSA256, WEBAUTHNECDSA256).contains(e);
        }

        public static boolean isNative(String javasig) {
            return Set.of(ED25519.javasig, ECDSA256.javasig, ECDSA384.javasig, ECDSA521.javasig, RSA256.javasig, RSA512.javasig).contains(javasig);
        }
    }

    public static final Parser<SSHSignature> PARSER = src -> {
        var type = SSHWireFormat.get_safe_string(src);
        var conf = SigConf.fromSSH(type);
        return new SSHSignature(type, conf.parser.fromByteBuffer(src));
    };

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(type);
            bin.write(payload.toBytes());
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public sealed interface SSHSignaturePayload<T> extends SSHSerializable<T> permits ECDSAPayload, Ed25519Payload, FIDOPayload, RSAPayload, WebAuthnPayload {
        byte[] toNative();
    }

    public record Ed25519Payload(byte[] bytes) implements SSHSignaturePayload<Ed25519Payload> {
        public static final Parser<Ed25519Payload> PARSER = src -> new Ed25519Payload(SSHWireFormat.get_bytes(src));

        @Override
        public byte[] toBytes() {
            return SSHWireFormat.bytes(bytes);
        }

        @Override
        public byte[] toNative() {
            return bytes();
        }
    }

    public record RSAPayload(byte[] bytes) implements SSHSignaturePayload<RSAPayload> {
        public static final Parser<RSAPayload> PARSER = src -> new RSAPayload(SSHWireFormat.get_bytes(src));

        @Override
        public byte[] toBytes() {
            return SSHWireFormat.bytes(bytes);
        }

        @Override
        public byte[] toNative() {
            return bytes().clone();
        }
    }

    public record ECDSAPayload(byte[] r, byte[] s) implements SSHSignaturePayload<ECDSAPayload> {
        public static final Parser<ECDSAPayload> PARSER = src -> {
            byte[] rsbytes = SSHWireFormat.get_bytes(src);
            ByteBuffer rs = ByteBuffer.wrap(rsbytes);
            byte[] r = SSHWireFormat.get_bytes(rs);
            byte[] s = SSHWireFormat.get_bytes(rs);
            return new ECDSAPayload(r, s);
        };

        @Override
        public byte[] toBytes() {
            try (var bin = SSHWireFormat.create()) {
                bin.ssh_bytes(r);
                bin.ssh_bytes(s);
                return SSHWireFormat.bytes(bin.bytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] toNative() {
            return Helpers.rs2der(r, s);
        }
    }

    public record FIDOPayload<S extends SSHSignaturePayload<S>>(S signature, byte flags,
                                                                long counter) implements SSHSignaturePayload<FIDOPayload<S>> {

        public FIDOPayload {
            if (counter < 0 || counter > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("Counter must be a 32-bit unsigned integer: " + counter);
            }
        }

        public static <S extends SSHSignaturePayload<S>> Parser<FIDOPayload<S>> parser(Parser<S> signatureParser) {
            return new Parser<>() {
                @Override
                public FIDOPayload<S> fromByteBuffer(ByteBuffer src) {
                    var signature = signatureParser.fromByteBuffer(src);
                    if (!isValidSignature(signature)) {
                        throw new IllegalArgumentException("Invalid signature type for FIDO");
                    }
                    var flags = src.get();
                    var counter = Integer.toUnsignedLong(src.getInt());
                    return new FIDOPayload<>(signature, flags, counter);
                }

                private boolean isValidSignature(S signature) {
                    return signature instanceof ECDSAPayload ||
                            signature instanceof Ed25519Payload;
                }
            };
        }

        @Override
        public byte[] toBytes() {
            try (var bin = SSHWireFormat.create()) {
                bin.write(signature.toBytes());
                bin.write(flags);
                bin.ssh_uint32(counter);
                return bin.bytes();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] toNative() {
            return signature.toNative();
        }
    }

    // NOTE: no re-use of FIDOPayload because records can not be extended
    public record WebAuthnPayload<S extends SSHSignaturePayload<S>>(S signature, byte flags,
                                                                    long counter,
                                                                    String origin,
                                                                    String clientdata,
                                                                    byte[] extensions) implements SSHSignaturePayload<WebAuthnPayload<S>> {
        public WebAuthnPayload {
            if (counter < 0 || counter > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("Counter must be a 32-bit unsigned integer: " + counter);
            }
        }

        public static <S extends SSHSignaturePayload<S>> Parser<WebAuthnPayload<S>> parser(Parser<S> signatureParser) {
            return src -> {
                var signature = signatureParser.fromByteBuffer(src);
                if (!(signature instanceof ECDSAPayload)) {
                    throw new IllegalArgumentException("Invalid signature type for WebAuthn: " + signature);
                }
                var flags = src.get();
                var counter = Integer.toUnsignedLong(src.getInt());
                var origin = SSHWireFormat.get_safe_string(src);
                var clientDataJSON = SSHWireFormat.get_string(src);
                var extensions = SSHWireFormat.get_bytes(src);
                return new WebAuthnPayload<>(signature, flags, counter, origin, clientDataJSON, extensions);
            };
        }

        @Override
        public byte[] toBytes() {
            try (var bin = SSHWireFormat.create()) {
                bin.write(signature.toBytes());
                bin.write(flags);
                bin.ssh_uint32(counter);
                bin.ssh_string(origin);
                bin.ssh_string(clientdata);
                bin.ssh_bytes(extensions);
                return bin.bytes();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] toNative() {
            return signature.toNative();
        }
    }

    @Override
    public String toString() {
        return "SSHSignature[" + type + "=" + Helpers.toHex(payload.toNative()) + "]";
    }

    public static byte[] dtbs_fido(byte[] message, byte[] appdata, byte flags, long counter) {
        if (counter < 0 || counter > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("Counter must be a 32-bit unsigned integer: " + counter);
        }
        if ((flags & 0x80) != 0) {
            throw new IllegalArgumentException("ED bit is set in flags (implies extensions, which are not supported): 0x%02x".formatted(flags));
        }
        try (var bos = new ByteArrayOutputStream()) {
            bos.write(Helpers.sha256(appdata));
            bos.write(flags);
            bos.write(ByteBuffer.allocate(4).putInt((int) counter).array());
            bos.write(Helpers.sha256(message));
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] dtbs_webauthn(byte[] message, String origin, byte flags, long counter) {
        var appdata = Objects.requireNonNull(URI.create(origin).getHost(), "Could not parse origin for host").getBytes(StandardCharsets.UTF_8);
        var clientdata = webauthn_clientdata(message, origin).getBytes(StandardCharsets.UTF_8);
        return dtbs_fido(clientdata, appdata, flags, counter);
    }

    // Generates webauthn clientdata _prefix_ usable for checking the client data
    private static String webauthn_clientdata_(byte[] message, String origin) {
        var prefix = "{\"type\":\"webauthn.get\",\"challenge\":\"";
        var suffix = "\",\"origin\":\"";
        // NOTE: no closing bracket
        return prefix + Helpers.base64url(message) + suffix + origin + "\"";
    }

    // Generates webauthn clientdata in a simple format without additional fields
    public static String webauthn_clientdata(byte[] message, String origin) {
        return webauthn_clientdata_(message, origin) + "}"; // Add the closing bracket
    }

    private static boolean webauthn_clientdata_check(String clientdata, byte[] message, String origin) {
        return clientdata.startsWith(webauthn_clientdata_(message, origin));
    }

    public boolean verify(byte[] message, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final SSHPublicKey sshkey;
        try {
            sshkey = SSHPublicKey.fromJavaKey(key);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeyException("Unsupported key type: " + key);
        }
        log.info("Verifying %s with %s".formatted(type, sshkey));

        var dtbv = switch (payload) {
            case FIDOPayload<?> fidosig -> {
                switch (sshkey.getContainer()) {
                    case SSHPublicKey.SSHFIDOPublicKey fidopub -> {
                        yield dtbs_fido(message, fidopub.appdata(), fidosig.flags(), fidosig.counter());
                    }
                    default -> throw new InvalidKeyException("FIDO signatures require a FIDO public key");
                }
            }
            case WebAuthnPayload<?> webauthsig -> {
                switch (sshkey.getContainer()) {
                    case SSHPublicKey.SSHFIDOPublicKey fidopub when fidopub.key() instanceof SSHPublicKey.SSHECPublicKey -> {
                        if (!webauthn_clientdata_check(webauthsig.clientdata(), message, webauthsig.origin())) {
                            throw new SignatureException("Client data does not match message!");
                        }
                        yield dtbs_fido(webauthsig.clientdata().getBytes(StandardCharsets.UTF_8), fidopub.appdata(), webauthsig.flags(), webauthsig.counter());
                    }
                    default -> throw new InvalidKeyException("WebAuthn signatures require a P256 FIDO public key");
                }
            }
            default -> message;
        };

        var sig = Signature.getInstance(SigConf.fromSSH(type).javasig);
        // This avoids the otherwise given warning of lossy FIDO conversion
        sig.initVerify(sshkey.getContainer().pub());
        sig.update(dtbv);
        return sig.verify(payload.toNative());
    }

    // Convert the Java format to SSH format. Called from SSHSignatureSpi.engineSign
    public static byte[] java2ssh(byte[] signature, String type) {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(type);
            var sig = SigConf.fromSSH(type);
            switch (sig) {
                case ED25519, RSA256, RSA512 -> bin.ssh_bytes(signature);
                case ECDSA256, ECDSA384, ECDSA521 -> {
                    try (var tmp = SSHWireFormat.create()) {
                        var clen = sig.key.curvelen;
                        byte[] rs = Helpers.der2rs(signature, sig.key.curvelen);
                        byte[] r = Arrays.copyOfRange(rs, 0, clen);
                        byte[] s = Arrays.copyOfRange(rs, clen, rs.length);
                        tmp.ssh_bytes(new BigInteger(1, r).toByteArray());
                        tmp.ssh_bytes(new BigInteger(1, s).toByteArray());
                        bin.ssh_bytes(tmp.bytes());
                    }
                }
                default -> throw new IllegalStateException("Can not convert signature from Java to SSH: " + type);
            }
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

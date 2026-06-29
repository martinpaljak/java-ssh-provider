// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serial;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Set;
import java.util.logging.Logger;

// NOTE: keep in mind that public keys come from untrusted sources, so we need to be careful with parsing them
// TLC: this class could be shorter and simpler, refactoring the container and type handling
@SuppressWarnings("ArrayRecordComponent")
public final class SSHPublicKey implements PublicKey, SSHIdentity, SSHSerializable<SSHPublicKey> {
    @Serial
    private final static long serialVersionUID = 2463666226688795498L;

    private static final Logger log = Logger.getLogger(SSHPublicKey.class.getName());

    private final String type;
    private transient final PublicKeyContainer<?> container;
    private final byte[] objectHash;

    // Parses a given public key type
    public static SSHPublicKey parse(KeyConf type, ByteBuffer src) {
        PublicKeyContainer<?> r = type.parser.fromByteBuffer(src);
        log.fine("Public key: " + r);
        return new SSHPublicKey(type.sshType, r);
    }

    // Detects the public key type and parses it
    public static final Parser<SSHPublicKey> PARSER = src -> {
        var type = SSHWireFormat.get_safe_string(src);
        var conf = KeyConf.fromSSH(type);
        log.finer("Public key type: " + type);
        return parse(conf, src);
    };

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.ssh_string(type);
            bin.write(container.toBytes());
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private SSHPublicKey(String type, PublicKeyContainer<?> container) {
        // this.type = type.equals("sk-ecdsa-sha2-nistp256@openssh.com") ? "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" : type;
        this.type = type;
        this.container = container;
        this.objectHash = Helpers.sha256(toBytes());
    }

    // Encapsulates a Java public key with (de)serialization capability
    public sealed interface PublicKeyContainer<T> extends SSHSerializable<T> permits SSHECPublicKey, SSHEdECPublicKey, SSHRSAPublicKey, SSHFIDOPublicKey {
        PublicKey pub();

        String algorithm();
    }

    private static ECPublicKey ecdsa_bytes2pubkey(byte[] pubkey, KeyConf conf) {
        final int len = conf.curvelen;
        try {
            if (pubkey[0] != 0x04) {
                throw new IllegalArgumentException("Invalid EC public key format");
            }
            // get public key
            var x = new BigInteger(1, Arrays.copyOfRange(pubkey, 1, len + 1));
            var y = new BigInteger(1, Arrays.copyOfRange(pubkey, len + 1, pubkey.length));
            var w = new ECPoint(x, y);
            var ec = new ECPublicKeySpec(w, Helpers.getCurveParams(conf.javaCurve));
            var keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(ec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public record SSHECPublicKey(ECPublicKey pub, KeyConf curve) implements PublicKeyContainer<SSHECPublicKey> {
        public static final Parser<SSHECPublicKey> PARSER = src -> {
            var curve = SSHWireFormat.get_safe_string(src);
            var conf = KeyConf.fromSSHCurve(curve);
            log.finer("ECPublicKey key curve: " + curve);
            var key = SSHWireFormat.get_bytes(src);
            var pub = ecdsa_bytes2pubkey(key, conf);
            return new SSHECPublicKey(pub, conf);
        };

        @Override
        public byte[] toBytes() {
            try (var bin = SSHWireFormat.create()) {
                bin.ssh_string(curve.sshCurve);
                int len = curve.curvelen;
                var x = Helpers.positive(pub.getW().getAffineX().toByteArray());
                var y = Helpers.positive(pub.getW().getAffineY().toByteArray());
                var blob = Helpers.concatenate(new byte[]{0x04}, Helpers.leftpad(x, len), Helpers.leftpad(y, len));
                bin.ssh_bytes(blob);
                return bin.bytes();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String algorithm() {
            return "EC";
        }
    }

    public record SSHEdECPublicKey(EdECPublicKey pub) implements PublicKeyContainer<SSHEdECPublicKey> {
        public static final Parser<SSHEdECPublicKey> PARSER = src -> {
            var key = SSHWireFormat.get_bytes(src);
            var pub = Helpers.ed25519_bytes2pubkey(key);
            return new SSHEdECPublicKey(pub);
        };

        @Override
        public byte[] toBytes() {
            var y = Helpers.reverse(pub.getPoint().getY().toByteArray());
            if (pub.getPoint().isXOdd()) {
                y[y.length - 1] |= (byte) 0x80;
            }
            return SSHWireFormat.bytes(y);
        }

        @Override
        public String algorithm() {
            return "EdDSA";
        }
    }

    public record SSHRSAPublicKey(RSAPublicKey pub) implements PublicKeyContainer<SSHRSAPublicKey> {
        public static final Parser<SSHRSAPublicKey> PARSER = src -> {
            try {
                var exponent = SSHWireFormat.get_bytes(src);
                var modulus = SSHWireFormat.get_bytes(src);
                var key = new RSAPublicKeySpec(new java.math.BigInteger(1, modulus), new java.math.BigInteger(1, exponent));
                var kf = KeyFactory.getInstance("RSA");
                return new SSHRSAPublicKey((RSAPublicKey) kf.generatePublic(key));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException("RSA key error", e);
            }
        };

        @Override
        public byte[] toBytes() {
            try (var bin = SSHWireFormat.create()) {
                var exponent = pub.getPublicExponent().toByteArray();
                var modulus = pub.getModulus().toByteArray();
                bin.ssh_bytes(exponent);
                bin.ssh_bytes(modulus);
                return bin.bytes();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String algorithm() {
            return "RSA";
        }
    }

    public record SSHFIDOPublicKey(PublicKeyContainer<?> key, byte[] appdata)
            implements PublicKeyContainer<SSHFIDOPublicKey> {

        @Override
        public PublicKey pub() {
            return key.pub();
        }

        public static <S extends PublicKeyContainer<S>> Parser<SSHFIDOPublicKey> parser(Parser<S> pubkeyParser) {
            return src -> {
                var key = pubkeyParser.fromByteBuffer(src);
                var appdata = SSHWireFormat.get_bytes(src);
                return new SSHFIDOPublicKey(key, appdata);
            };
        }

        @Override
        public byte[] toBytes() {
            try (var bin = SSHWireFormat.create()) {
                bin.write(key.toBytes());
                bin.ssh_bytes(appdata);
                return bin.bytes();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String algorithm() {
            return key.algorithm();
        }
    }

    public static SSHPublicKey fromJavaKey(PublicKey publicKey) throws IllegalArgumentException {
        return switch (publicKey) {
            case SSHPublicKey sshpub -> sshpub;
            case ECPublicKey ecpub -> {
                var conf = detect_curve(ecpub);
                yield new SSHPublicKey(conf.sshType, new SSHECPublicKey(ecpub, conf));
            }
            case EdECPublicKey edpub -> {
                yield new SSHPublicKey(KeyConf.ED25519.sshType, new SSHEdECPublicKey(edpub));
            }
            case RSAPublicKey rsapub -> {
                yield new SSHPublicKey(KeyConf.RSA.sshType, new SSHRSAPublicKey(rsapub));
            }
            default -> throw new IllegalArgumentException("Unsupported key type: " + publicKey.getClass().getName());
        };
    }


    public SSHPublicKey toFIDO(String appdata) {
        return toFIDO(appdata.getBytes(StandardCharsets.US_ASCII));
    }

    public SSHPublicKey toFIDO(byte[] bytes) {
        return switch (container) {
            case SSHFIDOPublicKey fidopub -> {
                if (!Arrays.equals(bytes, fidopub.appdata)) {
                    log.warning("Changing already present FIDO appdata for a public key.");
                }
                yield new SSHPublicKey(type, new SSHFIDOPublicKey(fidopub.key, bytes));
            }
            case SSHEdECPublicKey edpub ->
                    new SSHPublicKey(KeyConf.FIDO_ED25519.sshType, new SSHFIDOPublicKey(edpub, bytes));
            case SSHECPublicKey(ECPublicKey pub, KeyConf curve) -> {
                if (curve.equals(KeyConf.SECP256R1)) {
                    yield new SSHPublicKey(KeyConf.FIDO_SECP256R1.sshType, new SSHFIDOPublicKey(new SSHECPublicKey(pub, curve), bytes));
                } else {
                    throw new IllegalArgumentException("Unsupported curve for FIDO key: " + curve);
                }
            }
            default -> throw new IllegalArgumentException("Unsupported key type for FIDO: " + type);
        };
    }

    // Return the curve name of the given public key or null if not a known curve
    public static KeyConf detect_curve(ECKey publicKey) {
        // Get the key's parameter spec
        ECParameterSpec keySpec = publicKey.getParams();
        // Try each NIST curve
        for (var conf : Set.of(KeyConf.SECP256R1, KeyConf.SECP384R1, KeyConf.SECP521R1)) {
            var curveSpec = Helpers.getCurveParams(conf.javaCurve);
            // Compare all fields of the parameter spec. There is no .equals() method :(
            if (keySpec.getCurve().equals(curveSpec.getCurve()) &&
                    keySpec.getGenerator().equals(curveSpec.getGenerator()) &&
                    keySpec.getOrder().equals(curveSpec.getOrder()) &&
                    keySpec.getCofactor() == curveSpec.getCofactor()) {
                return conf;
            }
        }
        throw new IllegalArgumentException("Unknown curve for EC key");
    }


    public PublicKey getJavaKey() {
        if (container instanceof SSHFIDOPublicKey) {
            var sp = new StringWriter();
            new Exception().printStackTrace(new PrintWriter(sp));
            log.warning("Converting a FIDO public key to Java key is lossy: " + sp);
        }
        return container.pub();
    }

    public PublicKeyContainer<?> getContainer() {
        return container;
    }

    // Called from string parsing methods
    public static SSHPublicKey ofTypeFromBytes(String type, byte[] buffer) {
        try {
            var k = PARSER.fromByteBuffer(ByteBuffer.wrap(buffer));
            if (!k.getSSHType().equals(type)) {
                throw new IllegalArgumentException(String.format("mismatching key type: %s vs %s", type, k.getSSHType()));
            }
            return k;
        } catch (BufferUnderflowException e) {
            throw new IllegalArgumentException("could not parse key: " + type + " from " + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "SSHPublicKey[%s %s]".formatted(type, getFingerprint());
    }

    @Override
    public byte[] getHash() {
        return objectHash.clone();
    }

    @Override
    public SSHPublicKey getKey() {
        return this;
    }

    @Override
    public String getSSHType() {
        return this.type;
    }

    // Part of the PublicKey interface
    @Override
    public String getAlgorithm() {
        return container.algorithm();
    }

    @Override
    public String getFormat() {
        return "SSH";
    }

    @Override
    public byte[] getEncoded() {
        return toBytes();
    }

    // Parth of Object
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

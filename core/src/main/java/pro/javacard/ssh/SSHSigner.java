// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

public interface SSHSigner {
    // Some payloads embed the signer identity in the signed data
    SSHIdentity identity();

    CompletableFuture<SSHSignature> sign(byte[] data);

    static SSHSigner softsign(KeyPair kp) {

        var k = KeyConf.forKey(kp.getPrivate());
        var s = switch (k) {
            case RSA -> SSHSignature.SigConf.RSA512;
            case SECP256R1 -> SSHSignature.SigConf.ECDSA256;
            case SECP384R1 -> SSHSignature.SigConf.ECDSA384;
            case SECP521R1 -> SSHSignature.SigConf.ECDSA521;
            case ED25519 -> SSHSignature.SigConf.ED25519;
            default -> throw new IllegalArgumentException("Unsupported key type: " + k);
        };

        return signer(SSHPublicKey.fromJavaKey(kp.getPublic()), data -> softsigner(kp.getPrivate(), s, data));
    }

    static SSHSigner softsign_fido(KeyPair kp, byte[] appdata, byte flags, long counter) {
        var k = KeyConf.forKey(kp.getPrivate());
        var s = switch (k) {
            case SECP256R1 -> SSHSignature.SigConf.FIDOECDSA256;
            case ED25519 -> SSHSignature.SigConf.FIDOED25519;
            default -> throw new IllegalArgumentException("Unsupported key type: " + k);
        };

        return signer(SSHPublicKey.fromJavaKey(kp.getPublic()).toFIDO(appdata), data -> {
            var data2 = SSHSignature.dtbs_fido(data, appdata, flags, counter);
            var rrsig = switch (s) {
                case FIDOECDSA256 -> {
                    var ss = softsigner(kp.getPrivate(), SSHSignature.SigConf.ECDSA256, data2);
                    yield new SSHSignature.FIDOPayload<>((SSHSignature.ECDSAPayload) ss.payload(), flags, counter);
                }
                case FIDOED25519 -> {
                    var ss = softsigner(kp.getPrivate(), SSHSignature.SigConf.ED25519, data2);
                    yield new SSHSignature.FIDOPayload<>((SSHSignature.Ed25519Payload) ss.payload(), flags, counter);
                }
                default -> throw new IllegalArgumentException("Unsupported key type: " + s);
            };

            return new SSHSignature(s.sshsig, rrsig);
        });
    }

    static SSHSigner softsign_webauthn(KeyPair kp, String origin, byte flags, long counter) {
        var k = KeyConf.forKey(kp.getPrivate());
        var s = switch (k) {
            case SECP256R1 -> SSHSignature.SigConf.WEBAUTHNECDSA256;
            default -> throw new IllegalArgumentException("Unsupported key type: " + k);
        };
        var identity = SSHPublicKey.fromJavaKey(kp.getPublic()).toFIDO(SSHSignature.webauthn_appdata(origin));
        return signer(identity, data -> {
            var data2 = SSHSignature.dtbs_webauthn(data, origin, flags, counter);
            var ss = softsigner(kp.getPrivate(), SSHSignature.SigConf.ECDSA256, data2);
            var pload = new SSHSignature.WebAuthnPayload<>((SSHSignature.ECDSAPayload) ss.payload(), flags, counter, origin, SSHSignature.webauthn_clientdata(data, origin), new byte[0]);
            return new SSHSignature(s.sshsig, pload);
        });
    }

    static SSHSigner signer(SSHIdentity identity, Function<byte[], SSHSignature> f) {
        return new SSHSigner() {
            @Override
            public SSHIdentity identity() {
                return identity;
            }

            @Override
            public CompletableFuture<SSHSignature> sign(byte[] data) {
                return CompletableFuture.completedFuture(f.apply(data));
            }
        };
    }

    private static SSHSignature softsigner(PrivateKey key, SSHSignature.SigConf s, byte[] data) {
        try {
            var sig = Signature.getInstance(s.javasig);
            sig.initSign(key);
            sig.update(data);
            var sigbytes = sig.sign();
            var sshsig = SSHSignature.java2ssh(sigbytes, s.sshsig);
            return SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sshsig));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}

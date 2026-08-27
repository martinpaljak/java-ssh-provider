// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.SSHSigner;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@SuppressWarnings("ArrayRecordComponent")
public record SSHSIG(int version, SSHIdentity signer, String namespace, byte[] reserved, SSHSIG.Hash hash_algorithm,
                     SSHSignature signature) implements SSHSerializable<SSHSIG> {

    private static final Logger log = Logger.getLogger(SSHSIG.class.getName());

    public static final int VERSION = 1; // Only supported version

    public enum Hash {
        SHA256("sha256", "SHA-256"),
        SHA512("sha512", "SHA-512");

        public final String sshhash;
        public final String javahash;

        Hash(String sshhash, String javahash) {
            this.sshhash = sshhash;
            this.javahash = javahash;
        }

        public static Hash fromSSH(String sshhash) {
            for (var h : Hash.values()) {
                if (h.sshhash.equals(sshhash)) {
                    return h;
                }
            }
            throw new IllegalArgumentException("Unsupported hash algorithm: " + sshhash);
        }

        public static Hash fromJava(String javahash) {
            for (var h : Hash.values()) {
                if (h.javahash.equals(javahash)) {
                    return h;
                }
            }
            throw new IllegalArgumentException("Unsupported hash algorithm: " + javahash);
        }

        public MessageDigest digest() {
            try {
                return MessageDigest.getInstance(javahash);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("No " + javahash, e);
            }
        }
    }

    // 2. Blob format
    //
    //#define MAGIC_PREAMBLE "SSHSIG"
    //#define SIG_VERSION    0x01
    //
    //        byte[6]   MAGIC_PREAMBLE
    //        uint32    SIG_VERSION
    //        string    publickey
    //        string    namespace
    //        string    reserved
    //        string    hash_algorithm
    //        string    signature
    private static final byte[] MAGIC = "SSHSIG".getBytes(StandardCharsets.US_ASCII);
    public static final int MAGIC_LEN = MAGIC.length;

    public static byte[] MAGIC() {
        return MAGIC.clone();
    }

    // Standard MIME encoder would use \r\n, but we want to use \n
    private static final Base64.Encoder base64 = Base64.getMimeEncoder(76, new byte[]{'\n'});

    private static final String BEGIN = "-----BEGIN SSH SIGNATURE-----";
    private static final String END = "-----END SSH SIGNATURE-----";

    public static byte[] fromArmored(String armored) {
        var toRemove = Set.of(BEGIN, END);
        var s = armored.trim().lines().map(String::trim).filter(i -> !toRemove.contains(i)).collect(Collectors.joining());
        return Base64.getMimeDecoder().decode(s);
    }

    public static byte[] fromArmored(Object object) throws IOException {
        return switch (object) {
            case String s -> fromArmored(s);
            case Path p -> fromArmored(Files.readString(p));
            case byte[] b -> fromArmored(new String(b, StandardCharsets.US_ASCII));
            case InputStream in -> fromArmored(new String(in.readAllBytes(), StandardCharsets.US_ASCII));
            default -> throw new IllegalArgumentException("Unsupported type: " + object.getClass().getName());
        };
    }

    public static String toArmored(byte[] signature) {
        return String.join("\n", BEGIN, base64.encodeToString(signature), END);
    }

    public String toArmored() {
        return toArmored(toBytes());
    }

    public static SSHSIG from(Object armored) throws IOException {
        return fromByteBuffer(ByteBuffer.wrap(fromArmored(armored)));
    }

    public static final Parser<SSHSIG> PARSER = SSHSIG::fromByteBuffer;

    public static SSHSIG fromByteBuffer(ByteBuffer buffer) {
        var mgc = new byte[MAGIC_LEN];
        buffer.get(mgc);
        if (!Arrays.equals(MAGIC(), mgc)) {
            throw new IllegalArgumentException("Invalid SSHSIG magic: " + Helpers.toHex(mgc));
        }
        var version = buffer.getInt();
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported SSHSIG version: " + version);
        }
        var pubkey = SSHWireFormat.get_bytes(buffer);
        var identity = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(pubkey));
        var namespace = SSHWireFormat.get_string(buffer);
        if (namespace.isEmpty()) {
            throw new IllegalArgumentException("Empty namespace");
        }
        var reserved = SSHWireFormat.get_bytes(buffer);
        if (reserved.length != 0) {
            log.warning("Reserved field is not empty: " + Helpers.toHex(reserved));
        }
        var hash_algorithm = Hash.fromSSH(SSHWireFormat.get_string(buffer));
        var sigbytes = SSHWireFormat.get_bytes(buffer);
        var signature = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sigbytes));
        return new SSHSIG(version, identity, namespace, reserved, hash_algorithm, signature);
    }

    @Override
    public byte[] toBytes() {
        try (var bin = SSHWireFormat.create()) {
            bin.write(MAGIC());
            bin.ssh_uint32(version);
            bin.ssh_bytes(signer.toBytes());
            bin.ssh_string(namespace);
            bin.ssh_bytes(reserved);
            bin.ssh_string(hash_algorithm.sshhash);
            bin.ssh_bytes(signature.toBytes());
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // The blob this signature must have signed for the given namespace and hash.
    public byte[] dtbs(String namespace, Hash hash, byte[] digest) throws SignatureException {
        if (!this.namespace.equals(namespace)) {
            throw new SignatureException("Signature is for namespace \"%s\", not \"%s\"".formatted(this.namespace, namespace));
        }
        if (hash_algorithm != hash) {
            throw new SignatureException("Signature uses %s, not %s".formatted(hash_algorithm.sshhash, hash.sshhash));
        }
        return blob(namespace, hash, digest);
    }

    // Reserved is always empty in the signed blob, whatever the parsed signature carries.
    private static byte[] blob(String namespace, Hash hash, byte[] digest) {
        try (var bin = SSHWireFormat.create()) {
            bin.write(MAGIC());
            bin.ssh_string(namespace);
            bin.ssh_bytes(new byte[0]);
            bin.ssh_string(hash.sshhash);
            bin.ssh_bytes(digest);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Returns the signer for the caller to judge. Passing namespace() and hash_algorithm() back in
    // accepts whatever the signature says, like "ssh-keygen -Y verify" without -n.
    public SSHIdentity verify(String namespace, Hash hash, byte[] message) throws GeneralSecurityException {
        return check(dtbs(namespace, hash, hash.digest().digest(message)));
    }

    public SSHIdentity verify(String namespace, Hash hash, InputStream message) throws IOException, GeneralSecurityException {
        return check(dtbs(namespace, hash, digest(hash, message)));
    }

    private SSHIdentity check(byte[] dtbs) throws GeneralSecurityException {
        if (!signature.verify(dtbs, signer.getKey())) {
            throw new SignatureException("Signature does not verify with " + signer);
        }
        return signer;
    }

    public static CompletableFuture<SSHSIG> sign(SSHSigner signer, String namespace, Hash hash, byte[] message) {
        return sign_digest(signer, namespace, hash, hash.digest().digest(message));
    }

    public static CompletableFuture<SSHSIG> sign(SSHSigner signer, String namespace, Hash hash, InputStream message) throws IOException {
        return sign_digest(signer, namespace, hash, digest(hash, message));
    }

    public static CompletableFuture<SSHSIG> sign_digest(SSHSigner signer, String namespace, Hash hash, byte[] digest) {
        return signer.sign(blob(namespace, hash, digest))
                .thenApply(sig -> new SSHSIG(VERSION, signer.identity(), namespace, new byte[0], hash, sig));
    }

    // Digests the rest of the stream, leaving it open. A read of nothing is not the end of the stream.
    private static byte[] digest(Hash hash, InputStream in) throws IOException {
        var md = hash.digest();
        var buf = new byte[64 * 1024];
        int n;
        while ((n = in.read(buf)) != -1) {
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    @Override
    public String toString() {
        return "[SSHSIG \"%s\" (%s) with %s]".formatted(namespace, hash_algorithm.sshhash, signer);
    }
}

// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHSerializable;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@SuppressWarnings("ArrayRecordComponent")
public record SSHSIG(int version, SSHIdentity signer, String namespace, byte[] reserved, String hash_algorithm,
                     SSHSignature signature) implements SSHSerializable<SSHSIG> {

    private static final Logger log = Logger.getLogger(SSHSIG.class.getName());

    public static final String SHA256 = "sha256";
    public static final String SHA512 = "sha512";
    public static final int VERSION = 1; // Only supported version

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

    public static final Parser<SSHSIG> PARSER = SSHSIG::fromByteBuffer;

    public static SSHSIG fromByteBuffer(ByteBuffer buffer) {
        byte[] mgc = new byte[MAGIC_LEN];
        buffer.get(mgc);
        if (!Arrays.equals(MAGIC(), mgc)) {
            throw new IllegalArgumentException("Invalid SSHSIG magic: " + Helpers.toHex(mgc));
        }
        int version = buffer.getInt();
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported SSHSIG version: " + version);
        }
        byte[] pubkey = SSHWireFormat.get_bytes(buffer);
        SSHIdentity identity = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(pubkey));
        String namespace = SSHWireFormat.get_string(buffer);
        if (namespace.isEmpty()) {
            throw new IllegalArgumentException("Empty namespace");
        }
        byte[] reserved = SSHWireFormat.get_bytes(buffer);
        if (reserved.length != 0) {
            log.warning("Reserved field is not empty: " + Helpers.toHex(reserved));
        }
        String hash_algorithm = SSHWireFormat.get_string(buffer);
        if (!SHA256.equals(hash_algorithm) && !SHA512.equals(hash_algorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hash_algorithm);
        }
        byte[] sigbytes = SSHWireFormat.get_bytes(buffer);
        SSHSignature signature = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(sigbytes));
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
            bin.ssh_string(hash_algorithm);
            bin.ssh_bytes(signature.toBytes());
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Constructs the DTBS blob
    public static byte[] dtbs(String namespace, String hash_algorithm, byte[] hash) {
        return dtbs(namespace, hash_algorithm, hash, new byte[0]);
    }

    public static byte[] dtbs(String namespace, String hash_algorithm, byte[] hash, byte[] reserved) {
        if (!Set.of(SHA256, SHA512).contains(hash_algorithm)) {
            throw new IllegalArgumentException("Invalid hash: " + hash_algorithm);
        }
        if (reserved.length != 0) {
            log.info("Reserved field is not empty? Has %d bytes.".formatted(reserved.length));
        }
        try (var bin = SSHWireFormat.create()) {
            bin.write(SSHSIG.MAGIC());
            bin.ssh_string(namespace);
            bin.ssh_bytes(reserved);
            bin.ssh_string(hash_algorithm);
            bin.ssh_bytes(hash);
            return bin.bytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "[SSHSIG \"%s\" (%s) with %s]".formatted(namespace, hash_algorithm, signer);
    }
}

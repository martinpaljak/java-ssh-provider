package com.hardssh.provider;

import pro.javacard.ssh.SSHIdentity;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.EncodedKeySpec;

public final class OpenSSHPublicKeySpec extends EncodedKeySpec {

    private OpenSSHPublicKeySpec(byte[] encoded) {
        super(encoded);
    }

    public static OpenSSHPublicKeySpec fromStream(InputStream in) throws IOException {
        var s = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        return fromString(s);
    }

    public static OpenSSHPublicKeySpec fromString(String s) {
        var blob = SSHIdentity.fromString(s).toBytes();
        return new OpenSSHPublicKeySpec(blob);
    }

    public static OpenSSHPublicKeySpec fromPath(Path p) throws IOException {
        return fromString(Files.readString(p));
    }

    @Override
    public String getFormat() {
        return "OpenSSH";
    }
}

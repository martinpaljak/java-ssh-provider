// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.tests;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHSigner;
import pro.javacard.ssh.openssh.SSHSIG;
import pro.javacard.ssh.testing.TestUtils;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.security.SignatureException;

public class SSHSIGTests {

    private static final String NS = "file";

    private static SSHSIG sign(KeyPair kp, String namespace, SSHSIG.Hash hash, byte[] message) throws Exception {
        return SSHSIG.sign(SSHSigner.softsign(kp), namespace, hash, message).get();
    }

    // Returns zero on the first two reads, then delegates to the real data
    static final class StutteringStream extends FilterInputStream {
        private int stutters = 2;

        StutteringStream(byte[] data) {
            super(new ByteArrayInputStream(data));
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (stutters > 0) {
                stutters--;
                return 0;
            }
            return super.read(b, off, len);
        }
    }

    static final class BrokenStream extends InputStream {
        private int left = 1000;

        @Override
        public int read() {
            return 0;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (left <= 0) {
                throw new IOException("disk on fire");
            }
            var n = Math.min(len, left);
            left -= n;
            return n;
        }
    }

    @Test
    public void testSignVerifyRoundTrip() throws Exception {
        // Core must work with the JDK providers alone
        Assert.assertNull(Security.getProvider("SSH"));

        var message = "Hello SSHSIG".getBytes(StandardCharsets.UTF_8);
        for (var algo : new String[]{"Ed25519", "secp256r1"}) {
            var kp = TestUtils.makeKeyPair(algo);
            var signer = SSHSigner.softsign(kp);
            for (var hash : SSHSIG.Hash.values()) {
                var sig = SSHSIG.sign(signer, NS, hash, message).get();
                Assert.assertEquals(sig.hash_algorithm(), hash);
                Assert.assertEquals(sig.namespace(), NS);

                var parsed = SSHSIG.from(sig.toArmored());
                Assert.assertEquals(parsed.toBytes(), sig.toBytes());
                Assert.assertEquals(parsed.verify(NS, hash, message), signer.identity());
                // A caller that accepts whatever the signature says
                Assert.assertEquals(parsed.verify(parsed.namespace(), parsed.hash_algorithm(), message), signer.identity());
            }
        }
    }

    @Test
    public void testNamespaceAndHashBinding() throws Exception {
        var message = TestUtils.randomBytes(100);
        var kp = TestUtils.makeKeyPair("Ed25519");
        var sig = sign(kp, "a", SSHSIG.Hash.SHA512, message);

        var wrongNamespace = Assert.expectThrows(SignatureException.class, () -> sig.verify("b", SSHSIG.Hash.SHA512, message));
        Assert.assertTrue(wrongNamespace.getMessage().contains("a") && wrongNamespace.getMessage().contains("b"), wrongNamespace.getMessage());
        Assert.expectThrows(SignatureException.class, () -> sig.verify("a", SSHSIG.Hash.SHA256, message));
        Assert.assertEquals(sig.verify("a", SSHSIG.Hash.SHA512, message), SSHSigner.softsign(kp).identity());
    }

    @Test
    public void testRejectsTamperedInput() throws Exception {
        var message = TestUtils.randomBytes(100);
        var kp = TestUtils.makeKeyPair("secp256r1");
        var sig = sign(kp, NS, SSHSIG.Hash.SHA256, message);

        var tampered = message.clone();
        tampered[42] ^= 1;
        Assert.expectThrows(SignatureException.class, () -> sig.verify(NS, SSHSIG.Hash.SHA256, tampered));

        var armored = sig.toArmored();
        var lines = armored.split("\n");
        lines[1] = "AAAA" + lines[1].substring(4);
        Assert.expectThrows(IllegalArgumentException.class, () -> SSHSIG.from(String.join("\n", lines)));
    }

    @Test
    public void testStreaming() throws Exception {
        var kp = TestUtils.makeKeyPair("Ed25519");
        var signer = SSHSigner.softsign(kp);

        for (var size : new int[]{65535, 65536, 65537}) {
            var message = TestUtils.randomBytes(size);
            var streamed = SSHSIG.sign(signer, NS, SSHSIG.Hash.SHA256, new ByteArrayInputStream(message)).get();
            Assert.assertEquals(streamed.toBytes(), sign(kp, NS, SSHSIG.Hash.SHA256, message).toBytes());
            Assert.assertEquals(streamed.verify(NS, SSHSIG.Hash.SHA256, new ByteArrayInputStream(message)), signer.identity());
            // A stream that hands back nothing is not at its end
            Assert.assertEquals(streamed.verify(NS, SSHSIG.Hash.SHA256, new StutteringStream(message)), signer.identity());
        }

        var sig = sign(kp, NS, SSHSIG.Hash.SHA256, TestUtils.randomBytes(10));
        Assert.expectThrows(IOException.class, () -> sig.verify(NS, SSHSIG.Hash.SHA256, new BrokenStream()));
        Assert.expectThrows(IOException.class, () -> SSHSIG.sign(signer, NS, SSHSIG.Hash.SHA256, new BrokenStream()));
    }

    // "ssh-keygen -Y sign" output from the OpenSSH test suite
    @Test
    public void testOpenSSHTestData() throws Exception {
        var payload = TestUtils.resource("/openssh-testdata/signed-data").readAllBytes();
        var namespace = TestUtils.resourceString("/openssh-testdata/namespace").trim();
        var count = 0;
        try (var sigfiles = Files.newDirectoryStream(Paths.get(getClass().getResource("/openssh-testdata").toURI()), "*.sig")) {
            for (var sigfile : sigfiles) {
                // ssh-dss is not supported
                if ("dsa.sig".equals(sigfile.getFileName().toString())) {
                    continue;
                }
                var pubkey = SSHIdentity.from(Path.of(sigfile.toString().replaceFirst("\\.\\w+$", ".pub")));
                var sig = SSHSIG.from(sigfile);
                Assert.assertEquals(sig.verify(namespace, SSHSIG.Hash.SHA512, payload).getKey(), pubkey.getKey(), sigfile.toString());
                count++;
            }
        }
        Assert.assertEquals(count, 6);
    }
}

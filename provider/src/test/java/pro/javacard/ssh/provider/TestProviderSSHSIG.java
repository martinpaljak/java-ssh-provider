// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.SSHSigner;
import pro.javacard.ssh.openssh.SSHSIG;
import pro.javacard.ssh.testing.TestUtils;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static pro.javacard.ssh.testing.TestUtils.makeKeyPair;

public class TestProviderSSHSIG {
    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    private static final Logger log = LoggerFactory.getLogger(TestProviderSSHSIG.class);

    @Test(expectedExceptions = SignatureException.class)
    public void testNotInititalized() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("SSHSIG");
        s.update((byte) 42);
    }

    @Test(expectedExceptions = SignatureException.class)
    public void testSignNotInitialized() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("SSHSIG");
        s.sign();
    }

    @Test(expectedExceptions = SignatureException.class)
    public void testVerifyNotInitialized() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("SSHSIG");
        s.verify(TestUtils.randomBytes(32));
    }

    @Test(expectedExceptions = InvalidAlgorithmParameterException.class)
    public void testSetParameterNotSupported() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("SSHSIG");
        s.setParameter(new DSAParameterSpec(BigInteger.ONE, BigInteger.TWO, BigInteger.TEN));
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testGetParameterNotSupported() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("SSHSIG");
        s.getParameters();
    }


    @SuppressWarnings("deprecation")
    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testSetParameterNotSupported1() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        s.setParameter("foo", "bar");
        s.sign();
    }


    @SuppressWarnings("deprecation")
    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testGetParameterNotSupported1() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        s.getParameter("foo");
    }

    @Test(expectedExceptions = NoSuchAlgorithmException.class)
    public void testBadAlgorithm() throws Exception {
        var s = Signature.getInstance("foobar", new SSHProvider());
    }

    @Test(expectedExceptions = InvalidKeyException.class)
    public void testBadAlgorithm2() throws Exception {
        var s = Signature.getInstance("SHA256withECDSA", new SSHProvider());
        s.initVerify(makeKeyPair("secp256r1").getPublic());
    }

    @Test(expectedExceptions = InvalidKeyException.class)
    public void testBadAlgorithm3() throws Exception {
        var s = Signature.getInstance("SHA256withECDSA", new SSHProvider());
        s.initSign(makeKeyPair("secp256r1").getPrivate());
    }

    @Test
    public void testAllSamples() throws Exception {
        Security.addProvider(new SSHProvider());
        var types = List.of("rsa4k", "ed25519", "p256", "p384", "p521");
        for (var k : types) {
            var pub = TestUtils.resourceString("/k/%s.pub".formatted(k));
            var sigbytes = SSHSIG.fromArmored(TestUtils.resource("/k/%s.pub.sig".formatted(k)));
            verifyOne(pub, sigbytes);

            // And with all CA types
            for (var ca : types) {
                var pub2 = TestUtils.resourceString("/k/%s_ca_%s-cert.pub".formatted(k, ca));
                var sigbytes2 = SSHSIG.fromArmored(TestUtils.resource("/k/%s_ca_%s.pub.sig".formatted(k, ca)));
                verifyOne(pub2, sigbytes2);
            }
        }
    }

    void verifyOne(String pub, byte[] sshsig) throws Exception {
        var payload = TestUtils.resource("/k/payload.txt").readAllBytes();

        Signature signature = Signature.getInstance("SSHSIG");
        signature.setParameter(new SSHSIGVerificationParameters("file"));

        SSHIdentity i = SSHIdentity.fromString(pub);
        log.info("Verifying signature with " + i);

        if (i.real() instanceof SSHCertificate cert) {
            log.info("Certificate: {}", cert);
            // NOTE: this is a hack. SSHCertificate implements PublicKey just to be able to
            // fit into the Java API. Cryptographic verification is done with the key.
            signature.initVerify((PublicKey) cert);
        } else {
            signature.initVerify(i.getKey());
        }
        signature.update(payload);
        Assert.assertTrue(signature.verify(sshsig));
    }

    @Test
    public void testSignatureWithFido() throws Exception {
        Security.addProvider(new SSHProvider());
        var payload = TestUtils.resource("/k/payload.txt").readAllBytes();

        var i = SSHIdentity.fromString(TestUtils.resourceString("/k/id_ed25519_sk.pub"));
        log.info("fidokey: {}", i);
        var sshsig = SSHSIG.from(TestUtils.resource("/k/id_ed25519_sk.pub.sig"));
        // Accepts whatever the signature says, like "ssh-keygen -Y verify" without -n
        Assert.assertEquals(sshsig.verify(sshsig.namespace(), sshsig.hash_algorithm(), payload).getKey(), i.getKey());
    }

    @Test
    public void testProviderSSHSIG() throws Exception {
        Security.addProvider(new SSHProvider());
        var payload = TestUtils.resource("/k/payload.txt").readAllBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var kp = kpg.generateKeyPair();
        testKeypairSSHSIG(kp, payload);

        kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        kp = kpg.generateKeyPair();
        testKeypairSSHSIG(kp, payload);

        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        kp = kpg.generateKeyPair();
        testKeypairSSHSIG(kp, payload);

        kpg.initialize(new ECGenParameterSpec("secp521r1"));
        kp = kpg.generateKeyPair();
        testKeypairSSHSIG(kp, payload);

        kpg = KeyPairGenerator.getInstance("Ed25519");
        kp = kpg.generateKeyPair();
        testKeypairSSHSIG(kp, payload);
    }

    void testKeypairSSHSIG(KeyPair kp, byte[] payload) throws Exception {
        log.info("Creating signature... with " + SSHPublicKey.fromJavaKey(kp.getPublic()));
        var sshsig = Signature.getInstance("SSHSIG");
        sshsig.setParameter(new SSHSIGSigningParameters(kp.getPublic(), "file"));
        sshsig.initSign(kp.getPrivate());
        sshsig.update(payload);
        var signature = sshsig.sign();

        log.info("Verifying signature...");
        sshsig.setParameter(new SSHSIGVerificationParameters("file"));
        sshsig.initVerify(kp.getPublic());
        sshsig.update(payload);
        Assert.assertTrue(sshsig.verify(signature));

        // What the SPI signs, core verifies
        Assert.assertEquals(SSHSIG.from(SSHSIG.toArmored(signature)).verify("file", SSHSIG.Hash.SHA512, payload), SSHPublicKey.fromJavaKey(kp.getPublic()));

        // What core signs, the SPI verifies
        var fromcore = SSHSIG.sign(SSHSigner.softsign(kp), "file", SSHSIG.Hash.SHA512, payload).get().toBytes();
        sshsig.initVerify(kp.getPublic());
        sshsig.update(payload);
        Assert.assertTrue(sshsig.verify(fromcore));

        sshsig.setParameter(new SSHSIGVerificationParameters("file", "SHA-256"));
        sshsig.initVerify(kp.getPublic());
        sshsig.update(payload);
        var mismatch = Assert.expectThrows(SignatureException.class, () -> sshsig.verify(signature));
        Assert.assertTrue(mismatch.getMessage().contains("sha512") && mismatch.getMessage().contains("sha256"), mismatch.getMessage());
    }

    @Test
    void testInvalidParameterBlank() throws Exception {
        var s1 = new SSHSIGSigningParameters(TestUtils.makeKeyPair("secp256r1").getPublic(), "foobar");
        Assert.assertEquals(s1.hash(), "SHA-512");
        var p = TestUtils.makeKeyPair("secp256r1").getPublic();
        Assert.assertThrows(IllegalArgumentException.class, () -> new SSHSIGSigningParameters(p, ""));
        Assert.assertThrows(IllegalArgumentException.class, () -> new SSHSIGSigningParameters("foo", SSHPublicKey.fromJavaKey(p), "SHA-384"));
        Assert.assertThrows(NullPointerException.class, () -> new SSHSIGSigningParameters(p, null));
    }
}

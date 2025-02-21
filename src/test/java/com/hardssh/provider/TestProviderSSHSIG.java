package com.hardssh.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.openssh.SSHSIG;
import pro.javacard.testing.TestUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static pro.javacard.testing.TestUtils.makeKeyPair;

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
            var pub = new String(getClass().getResourceAsStream("/k/%s.pub".formatted(k)).readAllBytes(), StandardCharsets.UTF_8);
            var sigbytes = SSHSIG.fromArmored(getClass().getResourceAsStream("/k/%s.pub.sig".formatted(k)));
            verifyOne(pub, sigbytes);

            // And with all CA types
            for (var ca : types) {
                var pub2 = new String(getClass().getResourceAsStream("/k/%s_ca_%s-cert.pub".formatted(k, ca)).readAllBytes(), StandardCharsets.UTF_8);
                var sigbytes2 = SSHSIG.fromArmored(getClass().getResourceAsStream("/k/%s_ca_%s.pub.sig".formatted(k, ca)));
                verifyOne(pub2, sigbytes2);
            }
        }
    }

    void verifyOne(String pub, byte[] sshsig) throws Exception {
        var payload = getClass().getResourceAsStream("/k/payload.txt").readAllBytes();

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

    //@Ignore
    @Test
    public void testSignatureWithFido() throws Exception {
        Security.addProvider(new SSHProvider());
        var payload = getClass().getResourceAsStream("/k/payload.txt").readAllBytes();

        var i = SSHIdentity.fromString(new String(getClass().getResourceAsStream("/k/id_ed25519_sk.pub").readAllBytes(), StandardCharsets.UTF_8));
        log.info("fidokey: {}", i);
        var sig = SSHSIG.fromArmored(getClass().getResourceAsStream("/k/id_ed25519_sk.pub.sig"));
        var sshsig = SSHSIG.PARSER.fromBytes(sig);
        log.info("Verifying signature... with " + sshsig.signer());
    }

    @Test
    public void testProviderSSHSIG() throws Exception {
        Security.addProvider(new SSHProvider());
        var payload = getClass().getResourceAsStream("/k/payload.txt").readAllBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
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
        byte[] signature = sshsig.sign();

        log.info("Verifying signature...");
        sshsig.setParameter(new SSHSIGVerificationParameters("file"));
        sshsig.initVerify(kp.getPublic());
        sshsig.update(payload);
        Assert.assertTrue(sshsig.verify(signature));
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

    @Test
    void testOpenSSHTestData() throws Exception {
        Security.addProvider(new SSHProvider());
        var payload = getClass().getResourceAsStream("/openssh-testdata/signed-data").readAllBytes();
        var namespace = new String(getClass().getResourceAsStream("/openssh-testdata/namespace").readAllBytes(), StandardCharsets.UTF_8).trim();
        Path dir = Paths.get(getClass().getResource("/openssh-testdata").toURI());
        try (var stream = Files.newDirectoryStream(dir, "*.sig")) {
            for (var sigfile : stream) {
                log.info("Test signature: {}", sigfile);
                if (sigfile.toString().endsWith("dsa.sig"))
                    continue;
                var pub = Path.of(sigfile.toString().replaceFirst("\\.\\w+$", ".pub"));
                var sigbytes = SSHSIG.fromArmored(sigfile);
                SSHSIG signature = SSHSIG.PARSER.fromBytes(sigbytes);
                SSHIdentity pubkey = SSHIdentity.from(pub);

                var sshsig = Signature.getInstance("SSHSIG");
                sshsig.setParameter(new SSHSIGVerificationParameters(namespace));
                sshsig.initVerify(pubkey.getKey());
                sshsig.update(payload);
                Assert.assertTrue(sshsig.verify(sigbytes));
            }
        }
    }
}

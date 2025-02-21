package com.hardssh.provider;

import org.slf4j.bridge.SLF4JBridgeHandler;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.KeyConf;
import pro.javacard.ssh.SSHSignature;
import pro.javacard.testing.TestUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static pro.javacard.testing.TestUtils.makeKeyPair;

public class TestProviderSignature {

    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    @Test(expectedExceptions = SignatureException.class)
    public void testNotInititalized() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        Assert.assertEquals(s.getProvider().getName(), "SSHProvider");
        Assert.assertEquals(s.getAlgorithm(), "ecdsa-sha2-nistp256");
        s.update((byte) 42);
    }


    @Test
    public void testInitializeNull() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        Assert.assertEquals(s.getProvider().getName(), "SSHProvider");
        Assert.assertEquals(s.getAlgorithm(), "ecdsa-sha2-nistp256");
        Assert.assertThrows(NullPointerException.class, () -> s.initVerify((PublicKey) null));
    }


    @Test(expectedExceptions = SignatureException.class)
    public void testSignNotInitialized() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        s.sign();
    }

    @Test(expectedExceptions = SignatureException.class)
    public void testVerifyNotInitialized() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        s.verify(new byte[0]);
    }

    @Test(expectedExceptions = InvalidAlgorithmParameterException.class)
    public void testSetParameterNotSupported() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance(SSHSignature.SigConf.FIDOECDSA256.sshsig);
        s.setParameter(new DSAParameterSpec(BigInteger.ONE, BigInteger.TWO, BigInteger.TEN));
    }


    @Test
    public void testSetParameterResets() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("sk-ecdsa-sha2-nistp256@openssh.com");
        s.initVerify(TestUtils.makeKeyPair("secp256r1").getPublic());
        s.update((byte) 42);
        s.setParameter(null);
        Assert.assertThrows(SignatureException.class, () -> s.update((byte) 42));
    }

    @Test
    public void testSetParameterNotSuported() throws Exception {
        var p = new SSHProvider();
        Security.addProvider(p);
        var s1 = Signature.getInstance("ecdsa-sha2-nistp256");
        Assert.assertThrows(InvalidAlgorithmParameterException.class, () -> s1.setParameter(null));
        var s2 = Signature.getInstance("SHA256withECDSA", p);
        Assert.assertThrows(InvalidAlgorithmParameterException.class, () -> s2.setParameter(null));
        Assert.assertThrows(InvalidKeyException.class, () -> s2.initVerify(makeKeyPair("secp256r1").getPublic()));
    }


    @SuppressWarnings("deprecation")
    @Test
    public void testGetParameterNotSupported() throws Exception {
        Security.addProvider(new SSHProvider());
        var s = Signature.getInstance("ecdsa-sha2-nistp256");
        Assert.assertThrows(UnsupportedOperationException.class, () -> s.getParameter("foobar"));
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
        s.initVerify(makeKeyPair("RSA").getPublic());
    }

    @Test
    public void testBadAlgorithm3() throws Exception {
        var s = Signature.getInstance("SHA256withECDSA", new SSHProvider());
        Assert.assertThrows(InvalidKeyException.class, () -> s.initSign(makeKeyPair("Ed25519").getPrivate()));
    }


    void testEC(SSHSignature.SigConf alg) throws Exception {


        // Generate a key pair
        var kpg = KeyPairGenerator.getInstance("EC");
        var ecSpec = new ECGenParameterSpec(KeyConf.fromSSH(alg.sshsig).javaCurve);
        kpg.initialize(ecSpec);
        var keyPair = kpg.generateKeyPair();
    }

    void testKeyPair(KeyPair keyPair, SSHSignature.SigConf alg) throws Exception {

        var payload = "Hello, world!".getBytes(StandardCharsets.UTF_8);

        var s = Signature.getInstance(alg.sshsig);
        Assert.assertEquals(s.getProvider().getName(), "SSHProvider");
        Assert.assertEquals(s.getAlgorithm(), alg.sshsig);
        s.initSign(keyPair.getPrivate());
        s.update(payload);
        var result = s.sign();

        // Verify via SSHSignature
        var sshsig = SSHSignature.PARSER.fromByteBuffer(ByteBuffer.wrap(result));
        var valid = sshsig.verify(payload, keyPair.getPublic());
        Assert.assertTrue(valid, "SSHSignature verification failed");

        // Verify via provider
        var verify = Signature.getInstance(alg.sshsig);
        verify.initVerify(keyPair.getPublic());
        verify.update(payload);
        Assert.assertTrue(verify.verify(result), "SSHProvider verification failed");
    }


    @Test
    public void testSignatureProvider() throws Exception {
        Security.addProvider(new SSHProvider());

        for (var alg : List.of(SSHSignature.SigConf.ECDSA256, SSHSignature.SigConf.ECDSA384, SSHSignature.SigConf.ECDSA521)) {
            testEC(alg);
        }

        // RSA
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var kp = kpg.generateKeyPair();

        testKeyPair(kp, SSHSignature.SigConf.RSA256);
        testKeyPair(kp, SSHSignature.SigConf.RSA512);

        // Ed25519
        kpg = KeyPairGenerator.getInstance("Ed25519");
        kp = kpg.generateKeyPair();
        testKeyPair(kp, SSHSignature.SigConf.ED25519);

    }

}

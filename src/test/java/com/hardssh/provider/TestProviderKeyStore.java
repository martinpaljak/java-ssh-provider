package com.hardssh.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;
import org.testng.Assert;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.SSHSignature;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class TestProviderKeyStore {
    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    private static final Logger log = LoggerFactory.getLogger(TestProviderKeyStore.class);

    static boolean run_agent_crypto() {
        return System.getenv("YAUSA_TEST") != null;
    }

    @Test
    public void testKeyStore() throws Exception {

        var p = new SSHProvider();
        Assert.assertEquals(p.getName(), "SSHProvider");
        Assert.assertEquals(p.getVersionStr(), "1.0");
        Assert.assertEquals(p.getInfo(), "SSH Provider");

        var position = Security.addProvider(p);
        log.info("Added SSHProvider to: {}", position);
        var ks = KeyStore.getInstance("SSH");
        Assert.assertEquals(ks.getType(), "SSH");

        ks.load(null, "test".toCharArray());

        log.info("Keystore size: {}", ks.size());

        var aliases = Map.of("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLh2w1Q8jfitWPTzUwINX71d5KGEkvFXrN3G/G7+mxLgSBBhBYenX0sl+I6GAfBt/CsOCRsTIwKykb/CGZchtiY= yausa-test@secretive.sisalik.local", "SHA256:ZX2HY96jlguBWyXYk4591X8xL6YU5TnywM30nqJuYMU",
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMU5Gbxjfp/3rjztwBKYoaWuCfUPoewEqLT5e2nbZxA5yfzctlmo4sVx6kx42LWzr5O9I0NvETv0kQRThezn0/Y= yausa-test@secretive.winter.local", "SHA256:OJgQl1REdFwXEfNfCddEkx/uldUjsAyFpMy1VpUXUy4");

        var payload = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        Assert.assertNull(ks.getEntry("nonexistent", null));

        for (var kse : aliases.entrySet()) {
            var alias = kse.getValue();
            var entry = ks.getEntry(alias, null);
            if (entry instanceof SSHProvider.KeyPairEntry keypair) {
                // Check that the key is also present
                var key = (PrivateKey) ks.getKey(alias, null);
                Assert.assertNotNull(key);

                // Check that full fetch also works
                var key2 = (PrivateKey) ks.getKey(kse.getKey(), null);
                Assert.assertNotNull(key2);

                // test native sign
                var s = Signature.getInstance("SHA256withECDSA", p);
                s.initSign(key);
                s.update(payload);
                var result = s.sign();

                var verify = Signature.getInstance("SHA256withECDSA");
                // XXX: this should not trigger.
                Assert.assertNotEquals(verify.getProvider().getName(), SSHProvider.NAME, "unexpected provider for native verification");
                verify.initVerify(((SSHPublicKey) keypair.publicKey()).getJavaKey()); // FIXME: the types in entries need clarification
                verify.update(payload);
                Assert.assertTrue(verify.verify(result), "Native verification failed");

                // test ssh sign
                s = Signature.getInstance("ecdsa-sha2-nistp256", p);
                Assert.assertEquals(s.getProvider().getName(), SSHProvider.NAME);

                s.initSign(key);
                s.update(payload);
                var result2 = s.sign();

                // Verify via provider
                verify = Signature.getInstance("ecdsa-sha2-nistp256");
                verify.initVerify(keypair.publicKey());
                verify.update(payload);
                Assert.assertTrue(verify.verify(result2), "Provider SSH verification failed");
            } else if (entry == null) {
                log.info("Known agent key not found: {}", kse.getValue());
            } else {
                Assert.fail("Invalid entry type: " + entry.getClass().getSimpleName());
            }
        }
    }

    @Test
    public void testKeyStoreEntries() throws Exception {
        Security.addProvider(new SSHProvider());
        var ks = KeyStore.getInstance("SSH");
        Assert.assertEquals(ks.getType(), "SSH");

        ks.load(null, "test".toCharArray());

        log.info("Keystore size: {}", ks.size());

        var entries = new HashMap<String, KeyStore.Entry>();

        for (String alias : Collections.list(ks.aliases())) {
            var entry = ks.getEntry(alias, null);
            log.info("{}: {}", alias, entry);
            entries.put(alias, entry);
        }

        for (var e : entries.entrySet()) {
            testKeyStoreEntry(e.getValue(), e.getKey(), ks);
        }
    }


    public void testKeyStoreEntry(KeyStore.Entry entry, String alias, KeyStore ks) throws Exception {
        var payload = "Hello, world!".getBytes(StandardCharsets.UTF_8);

        if (entry instanceof SSHProvider.KeyPairEntry keypair) {
            log.info("Keypair entry {}", keypair);

            // Check that the key is also present
            var key = (PrivateKey) ks.getKey(alias, null);
            Assert.assertNotNull(key);
            Assert.assertEquals(key, keypair.privateKey());

            var entrytype = SSHPublicKey.fromJavaKey(keypair.publicKey()).getSSHType();
            var signaturetype = entrytype.equals("ssh-rsa") ? "rsa-sha2-512" : entrytype;
            var nativesignaturetype = SSHSignature.SigConf.fromSSH(signaturetype).javasig;
            log.info("Key type: " + entrytype);
            log.info("Native signature: " + nativesignaturetype);
            log.info("SSH signature: " + signaturetype);

            if (run_agent_crypto()) {
                // test native sign
                var s = Signature.getInstance(nativesignaturetype, SSHProvider.NAME);
                Assert.assertEquals(s.getProvider().getName(), SSHProvider.NAME);
                s.initSign(key);
                s.update(payload);
                var result = s.sign();

                var verify = Signature.getInstance(nativesignaturetype);
                verify.initVerify(keypair.publicKey());
                verify.update(payload);
                Assert.assertTrue(verify.verify(result), "Native verification failed");

                // test ssh sign
                s = Signature.getInstance(signaturetype);
                s.initSign(key);
                s.update(payload);
                var result2 = s.sign();

                // Verify via provider
                verify = Signature.getInstance(signaturetype);
                verify.initVerify(keypair.publicKey());
                verify.update(payload);
                Assert.assertTrue(verify.verify(result2), "Provider SSH verification failed");
            }
        } else if (entry instanceof KeyStore.PrivateKeyEntry pk) {
            log.info("Certificate entry: " + pk.getCertificate());
            // We can only have one certificate in chain
            Assert.assertEquals(pk.getCertificateChain().length, 1);
            Assert.assertEquals(pk.getCertificate().getPublicKey().getAlgorithm(), pk.getPrivateKey().getAlgorithm());
            // check that certificate is present
            var cert = ks.getCertificate(alias);
            Assert.assertNotNull(cert);
            Assert.assertEquals(cert, pk.getCertificate());

            // Make SSHSIG

            if (run_agent_crypto()) {
                log.info("Generating signature...");
                var sshsig = Signature.getInstance("SSHSIG");
                // FIXME - we want the full identity there.
                sshsig.setParameter(new SSHSIGSigningParameters(pk.getCertificate().getPublicKey(), "file"));
                sshsig.initSign(pk.getPrivateKey());
                sshsig.update(payload);
                byte[] signature = sshsig.sign();

                System.err.println("Verifying signature...");
                sshsig.setParameter(new SSHSIGVerificationParameters("file"));
                sshsig.initVerify(pk.getCertificate().getPublicKey());
                sshsig.update(payload);
                Assert.assertTrue(sshsig.verify(signature));
            }
        } else {
            Assert.fail("Invalid entry type: " + entry.getClass().getSimpleName());
        }
    }


    @Test
    @Ignore
    public void listAllProviders() throws Exception {
        Security.addProvider(new SSHProvider());
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName());
            for (String key : provider.stringPropertyNames())
                System.out.println("\t" + key + "\t" + provider.getProperty(key));
        }
    }
}

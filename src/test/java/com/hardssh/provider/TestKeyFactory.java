package com.hardssh.provider;

import org.slf4j.bridge.SLF4JBridgeHandler;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHIdentity;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;

public class TestKeyFactory {

    static {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    @Test
    public void testFactory() throws Exception {
        Security.addProvider(new SSHProvider());
        KeyFactory factory = KeyFactory.getInstance("SSH");
        var spec = OpenSSHPublicKeySpec.fromStream(getClass().getResourceAsStream("/k/ed25519.pub"));
        PublicKey pub = factory.generatePublic(spec);
        Assert.assertEquals(pub.getAlgorithm(), "EdDSA");
        Assert.assertEquals(pub.getFormat(), "SSH");
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testFactoryGeneratePrivate() throws Exception {
        Security.addProvider(new SSHProvider());
        var factory = KeyFactory.getInstance("SSH");
        var spec = OpenSSHPublicKeySpec.fromStream(getClass().getResourceAsStream("/k/ed25519.pub"));
        factory.generatePrivate(spec);
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testFactoryGenerateCRLs() throws Exception {
        Security.addProvider(new SSHProvider());
        var factory = KeyFactory.getInstance("SSH");
        var i = SSHIdentity.from(getClass().getResourceAsStream("/k/ed25519.pub"));
        factory.translateKey(i.getKey());
    }
}

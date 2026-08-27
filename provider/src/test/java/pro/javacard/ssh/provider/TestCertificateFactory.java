// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.provider;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.testing.TestUtils;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class TestCertificateFactory {

    @Test
    public void testFactory() throws Exception {
        Security.addProvider(new SSHProvider());
        CertificateFactory factory = CertificateFactory.getInstance("SSH");

        var i = SSHIdentity.from(TestUtils.resource("/k/ed25519_ca_ed25519-cert.pub"));
        var b = i.toBytes();
        var cert = factory.generateCertificate(new ByteArrayInputStream(b));
        Assert.assertEquals(i, cert);

        var il = factory.generateCertificates(new ByteArrayInputStream(b));
        Assert.assertEquals(il.size(), 1);
        Assert.assertEquals(il.iterator().next(), cert);
    }

    @Test(expectedExceptions = CertificateException.class)
    public void testReadPubkey() throws Exception {
        Security.addProvider(new SSHProvider());
        CertificateFactory factory = CertificateFactory.getInstance("SSH");

        var i = SSHIdentity.from(TestUtils.resource("/k/ed25519.pub"));
        var b = i.toBytes();
        factory.generateCertificate(new ByteArrayInputStream(b));
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testFactoryGenerateCRL() throws Exception {
        Security.addProvider(new SSHProvider());
        CertificateFactory factory = CertificateFactory.getInstance("SSH");
        factory.generateCRL(new ByteArrayInputStream(new byte[0]));
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testFactoryGenerateCRLs() throws Exception {
        Security.addProvider(new SSHProvider());
        CertificateFactory factory = CertificateFactory.getInstance("SSH");
        factory.generateCRLs(new ByteArrayInputStream(new byte[0]));
    }
}

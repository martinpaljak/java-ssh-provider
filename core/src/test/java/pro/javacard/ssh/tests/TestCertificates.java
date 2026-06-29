// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.tests;

import org.slf4j.bridge.SLF4JBridgeHandler;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.SSHSigner;
import pro.javacard.ssh.dtbs.CertificatePayload;
import pro.javacard.ssh.dtbs.CertificatePayloadBuilder;
import pro.javacard.ssh.testing.TestUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public class TestCertificates {

    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    //@Ignore
    @Test
    public void testGenerateAndSign() throws Exception {
        var ca = TestUtils.makeKeyPair("secp256r1");
        var client = TestUtils.makeKeyPair("Ed25519");

        var capub = SSHPublicKey.fromJavaKey(ca.getPublic());
        var fidoca = capub.toFIDO("example.com");
        var builder = new CertificatePayloadBuilder()
                .publicKey(SSHPublicKey.fromJavaKey(client.getPublic()))
                .serial(BigInteger.ONE)
                .certType(SSHCertificate.Type.USER)
                .id("Good Client")
                .principals(List.of("client"))
                .after(Instant.now())
                .before(Instant.now().plusSeconds(3600))
                .options(Map.of("force-command", "echo 'Hello, world!'".getBytes()))
                .signKey(fidoca);

        var payload = builder.build();
        var reparsed = CertificatePayload.PARSER.fromBytes(payload.dtbs());
        Assert.assertEquals(payload, reparsed);
        //var certfu = builder.sign(SSHSigner.softsign_webauthn(ca.getPrivate(), "https://example.com", (byte) 0, 0));
        var certfu = builder.sign(SSHSigner.softsign_fido(ca.getPrivate(), "example.com".getBytes(StandardCharsets.US_ASCII), (byte) 0x05, 0));
        //var certfu = builder.sign(SSHSigner.softsign(ca.getPrivate()));
        var cert = certfu.get();
        cert.verify(fidoca);
        //Assert.assertThrows(SignatureException.class, () -> cert.verify(fidoca));
        System.out.println(payload);
        System.out.println(cert.asString());
    }
}

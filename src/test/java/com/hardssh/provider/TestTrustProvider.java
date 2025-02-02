package com.hardssh.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.openssh.SSHAllowedSigners;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;

public class TestTrustProvider {
    private static final Logger log = LoggerFactory.getLogger(TestTrustProvider.class);

    static Instant atDate(String date) {
        return Clock.fixed(LocalDate.parse(date).atStartOfDay(ZoneOffset.UTC).toInstant(), ZoneOffset.UTC).instant();
    }

    @Test
    public void testTrustProvider1() throws Exception {
        var sample = """
                u:fine@*.example.com namespaces="r:root@*",valid-before="20251231",valid-after="20210101Z",cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLh2w1Q8jfitWPTzUwINX71d5KGEkvFXrN3G/G7+mxLgSBBhBYenX0sl+I6GAfBt/CsOCRsTIwKykb/CGZchtiY=
                g:admin@* namespaces="r:root@google.com",valid-before="20251231",valid-after="20210101Z" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLh2w1Q8jfitWPTzUwINX71d5KGEkvFXrN3G/G7+mxLgSBBhBYenX0sl+I6GAfBt/CsOCRsTIwKykb/CGZchtiY=
                """;

        var allowed = SSHAllowedSigners.parse(sample);
        var trust = new TrustProvider(allowed);

        var who = trust.whoCan("r:root@*", atDate("2022-02-14"));
        Assert.assertEquals(who.size(), 1);
        Assert.assertEquals(who.getFirst(), "u:fine@*.example.com");

        who = trust.whoCan("notexisting", atDate("2022-02-14"));
        Assert.assertEquals(who.size(), 0);

        who = trust.whoCan("r:root@google.com", atDate("2020-02-14"));
        Assert.assertEquals(who.size(), 0);


        who = trust.whoCan("r:root@google.com", atDate("2023-02-14"));
        Assert.assertEquals(who.size(), 2);

        who = trust.whoCan("r:root@google.com", atDate("2021-01-01").minusSeconds(1));
        Assert.assertEquals(who.size(), 0);
    }
}

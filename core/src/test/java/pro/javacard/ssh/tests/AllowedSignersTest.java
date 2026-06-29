// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.tests;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.openssh.SSHAllowedSigners;
import pro.javacard.ssh.openssh.SSHAllowedSigners.Option.CertAuthority;
import pro.javacard.ssh.openssh.SSHAllowedSigners.Option.Namespaces;
import pro.javacard.ssh.openssh.SSHAllowedSigners.Option.ValidAfter;

import java.io.IOException;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static pro.javacard.ssh.openssh.SSHAllowedSigners.parseTimestamp;

public class AllowedSignersTest {

    @Test
    public void test() throws IOException {

        var s = """
                # sisalik
                martin@martinpaljak.net namespaces="!git",cert-authority,valid-after=20240101Z ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOsP/jQTKqOZ0ZHyH0IU3NKL3MsTfYj16SMX4WuCleJu+6eQVw7k8XSGNTHK81jdtxkAsk8jOknHNBd9aHu20ic= this is comment
                # winter
                martin@martinpaljak.net namespaces="foo,*@blah.com" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIowfYjnsqKTC8+H5Nhp8Yaw7C2COsEk6x11O4x71tFIrf/oM5SHakHWO7hhAlpeFNz2wMND4m1fBVrebmyY/z8=
                *@example.com,martin@* namespaces="git,cert" ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIszmO6fLhCz1uHsYWBl+Ei+RKPWUBCre7FD+DuX1H0DjlOOt2ytYF19y9nA1oGkPKrFEKoumExGL8kgKTZtMEg1VTZ/faIxhGYwEBGsBmxTeMpSnYwuuNarwq9tes9JJw==
                """;

        var f = SSHAllowedSigners.parse(s);
        var r = f.getConfig().entries().toList();
        Assert.assertEquals(r.size(), 3);
        var e1 = r.getFirst();
        Assert.assertEquals(e1.principals(), List.of("martin@martinpaljak.net"));
        Assert.assertEquals(e1.getOption(Namespaces.class), Optional.of(new Namespaces(List.of("!git"))));
        Assert.assertEquals(e1.getOption(CertAuthority.class), Optional.of(new CertAuthority()));
        Assert.assertEquals(e1.getOption(ValidAfter.class), Optional.of(new ValidAfter(parseTimestamp("20240101Z"))));
        Assert.assertEquals(e1.options().size(), 3);
        Assert.assertEquals(e1.key().getKey().getFingerprint(), "SHA256:azTQzOChoLuaCk7G0oQNfzoT0/jUFeV6GqrzlDQVDLg");
        //Assert.assertEquals(e1.key().getComment(), Optional.of("this is comment"));

        var e3 = r.get(2);
        Assert.assertEquals(e3.principals(), List.of("*@example.com", "martin@*"));
        Assert.assertTrue(e3.options().contains(new Namespaces(List.of("git", "cert"))));

        var time = Clock.fixed(LocalDate.parse("2024-01-23").atStartOfDay().atZone(ZoneId.systemDefault()).toInstant(), ZoneId.systemDefault());
        var found = f.validEntries("martin@martinpaljak.net", "git", time);
        Assert.assertEquals(found.size(), 1);
        found.forEach(System.out::println);
        f.getConfig().forEach(System.out::println);
    }

    @Test
    public void testTimestamps() {
        Assert.assertEquals(parseTimestamp("20240123"), LocalDate.parse("2024-01-23").atStartOfDay().atZone(ZoneId.systemDefault()));
        Assert.assertEquals(parseTimestamp("20240123Z"), LocalDate.parse("2024-01-23").atStartOfDay().atZone(ZoneOffset.UTC));
    }
}

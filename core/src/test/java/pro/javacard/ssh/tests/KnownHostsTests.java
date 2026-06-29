// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.tests;

import org.testng.Assert;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.openssh.SSHKnownHosts;
import pro.javacard.ssh.utils.Helpers;

import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class KnownHostsTests {

    @Test
    public void testKnownHosts() throws Exception {
        String sample = new String(getClass().getResourceAsStream("known_hosts1.txt").readAllBytes());
        var r = SSHKnownHosts.parse(sample);
        //Assert.assertEquals(r.size(), 10);
        Assert.assertEquals(r.getConfig().size(), 26);
        //Assert.assertEquals(r.getConfig().toString().trim(), sample.trim()); // NOTE: will fail on windows.

        r.getConfig().forEach(e -> System.out.println(e.getClass().getSimpleName()));
        var match = r.matchByName("172.16.51.130");
        Assert.assertFalse(match.isEmpty());
        System.out.println(match);

        System.out.println(r.tidy());
        System.out.println(r);
    }

    @Test
    public void testOpenSSHKnownHosts() throws Exception {
        String sample = new String(getClass().getResourceAsStream("openssh_known_hosts.txt").readAllBytes());
        var r = SSHKnownHosts.parse(sample);
        var result = r.toString();
        //Assert.assertEquals(r.getKnownHosts().size(), 35);
        //Assert.assertEquals(r.getAllEntries().size(), 50);
        //Assert.assertEquals(r.getConfig().toString().trim(), sample.trim());

        r.getConfig().forEach(System.out::println);
        System.out.println("Comments etc");
        System.out.println(r.tidy());
    }

    @Test
    public void testOpenSSHKnownHostsWithComments() throws Exception {
        SSHIdentity k = SSHIdentity.fromString(" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1Jvql7tFqz/To7sqJXyRTr30TIaE0glAqFDNhBl3kl");
        try {
            SSHKnownHosts kh = SSHKnownHosts.load(Paths.get(System.getProperty("user.home"), ".ssh", "known_hosts"));
            System.out.println(kh.findNames(k));
        } catch (Exception e) {
            // Do nothing
        }
    }

    @Test
    public void testWindowsNamedPipe() throws Exception {
        if (!System.getProperty("os.name").toLowerCase().contains("win"))
            return;
        var name = "\\\\.\\pipe\\openssh-ssh-agent";
        Path p = Paths.get(name);
        System.out.println(Files.exists(p));
        System.out.println(Files.isRegularFile(p));
        RandomAccessFile pipe = new RandomAccessFile("\\\\.\\pipe\\openssh-ssh-agent", "rw");
        System.out.println(pipe);
        pipe.write(Helpers.fromHex("000000010b"));
        var all = new byte[9];
        pipe.read(all);
        System.out.println(Helpers.toHex(all));
        pipe.close();
    }
}

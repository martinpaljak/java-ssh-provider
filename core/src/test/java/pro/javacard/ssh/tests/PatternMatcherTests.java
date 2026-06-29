// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.tests;

import org.testng.Assert;
import org.testng.annotations.Test;

import static pro.javacard.ssh.openssh.SSHPatternMatcher.matches;
import static pro.javacard.ssh.openssh.SSHPatternMatcher.matchesRange;

public class PatternMatcherTests {

    @Test
    public void testPatternMatcher() {
        Assert.assertTrue(matches("192.168.0.1", "192.168.0.?"));
        Assert.assertFalse(matches("host3.dialup.example.com", "!*.dialup.example.com,*.example.com"));
        Assert.assertFalse(matches("host3", "!host1,!host2"));
        Assert.assertTrue(matches("host3", "!host1,!host2,*"));
        Assert.assertTrue(matches("127.0.0.1", "localhost,127.*"));
        Assert.assertTrue(matches("192.168.34.1", "localhost,192.168.*.?"));
        Assert.assertFalse(matches("192.168.34.12", "localhost,192.168.*.?"));
        Assert.assertTrue(matches("john@example.com", "*@example.com"));
        Assert.assertTrue(matches("john@test.example.com", "*@*.example.com"));
        Assert.assertTrue(matches("john@example.com", "*@*.com"));
        Assert.assertFalse(matches("john@example.com", "!*@example.org,!*.ee"));
    }

    @Test
    public void testNetworkMatcher() {
        // IPv4 examples
        Assert.assertTrue(matchesRange("192.168.1.1", "192.168.0.0/16"));    // true
        Assert.assertTrue(matchesRange("192.168.1.1", "192.168.1.0/24"));    // true
        Assert.assertFalse(matchesRange("192.168.2.1", "192.168.1.0/24"));    // false

        // IPv6 examples
        Assert.assertTrue(matchesRange("2001:db8:1:2::1", "2001:db8:1::/48"));  // true
        Assert.assertFalse(matchesRange("2001:db8:2:2::1", "2001:db8:1::/48"));  // false
    }
}

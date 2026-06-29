// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// See https://man.openbsd.org/ssh_config.5#PATTERNS
// https://man.openbsd.org/sshd.8#from=_pattern-list_
public final class SSHPatternMatcher {

    private static final Logger log = Logger.getLogger(SSHPatternMatcher.class.getName());

    private SSHPatternMatcher() {
    }

    static final Pattern CIDR_PATTERN = Pattern.compile("^(?:\\d+\\.\\d+\\.\\d+\\.\\d+|[0-9a-fA-F:]+)/\\d+$");

    public static boolean possiblyCIDR(String cidr) {
        return CIDR_PATTERN.matcher(cidr).matches();
    }

    @SuppressWarnings("StringSplitter")
    public static boolean matchesRange(String input, String netblock) {
        try {
            var parts = netblock.split("/");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid CIDR format: " + netblock);
            }

            // Parse the network address and mask length
            var network = InetAddress.getByName(parts[0]).getAddress();
            var maskBits = Integer.parseInt(parts[1]);

            // Validate maskBits
            if (maskBits < 0 || maskBits > (network.length * 8)) {
                throw new IllegalArgumentException("Invalid mask length: " + maskBits);
            }

            // Parse the input IP
            var ip = InetAddress.getByName(input).getAddress();

            // Ensure same IP version
            if (network.length != ip.length) {
                return false;
            }

            // Compare the network bits
            var maskFullBytes = maskBits / 8;
            var remainingBits = maskBits % 8;

            // Check full bytes
            for (var i = 0; i < maskFullBytes; i++) {
                if (network[i] != ip[i]) {
                    return false;
                }
            }

            // Check remaining bits if any
            if (remainingBits > 0) {
                var mask = -1 << (8 - remainingBits);
                return (network[maskFullBytes] & mask) == (ip[maskFullBytes] & mask);
            }

            return true;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address format", e);
        }
    }

    public static String unquoteIfNeeded(String s) {
        if (s != null && s.startsWith("\"") && s.endsWith("\"")) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    public static String quote(String s) {
        return "\"" + s + "\"";
    }

    private record PatternEntry(boolean isNegated, String pattern) {
        static PatternEntry of(String pattern) {
            return new PatternEntry(pattern.startsWith("!"),
                    pattern.startsWith("!") ? pattern.substring(1) : pattern);
        }

        @Override
        public String toString() {
            return "PatternEntry[%s%s]".formatted(isNegated ? "not " : "", pattern);
        }
    }

    /**
     * Converts SSH wildcard pattern to regex pattern
     */
    private static String convertToRegex(String pattern) {
        return "^" + pattern.chars()
                .mapToObj(c -> switch ((char) c) {
                    case '*' -> ".*";
                    case '?' -> ".";
                    case '.' -> "\\.";
                    default -> Pattern.quote(String.valueOf((char) c));
                })
                .reduce(String::concat)
                .orElse("") + "$";
    }

    private static boolean matchesPattern(String input, String pattern) {
        return Pattern.compile(convertToRegex(pattern)).matcher(input).matches();
    }

    public static boolean matches(String input, String patterns) {
        var parsed = Arrays.stream(patterns.split(","))
                .map(String::trim)
                .toList();
        return matches(input, parsed);
    }

    public static boolean matches(String input, List<String> patterns) {
        return matches(input, patterns, true);
    }

    public static boolean matches(String input, List<String> list, boolean strict) {
        var patterns = list.stream()
                .map(PatternEntry::of)
                .collect(Collectors.toCollection(ArrayList::new));

        log.finer("Matching %s %s against %s".formatted(strict ? "strict" : "simple", input, patterns));

        // If no positive patterns exist, implicitly add "*"
        if (!strict && patterns.stream().allMatch(PatternEntry::isNegated)) {
            patterns.add(new PatternEntry(false, "*"));
        }

        // Check if any negated patterns match
        if (patterns.stream()
                .filter(PatternEntry::isNegated)
                .anyMatch(entry -> matchesPattern(input, entry.pattern()))) {
            log.finer("Rejected by negated pattern");
            return false;
        }

        // Check if any positive patterns match
        var result = patterns.stream()
                .filter(p -> !p.isNegated())
                .anyMatch(entry -> matchesPattern(input, entry.pattern()));
        log.finer("Matched: " + result);
        return result;
    }
}
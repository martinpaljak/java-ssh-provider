// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.utils.Helpers;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// See https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT
// See https://man.openbsd.org/ssh.1#VERIFYING_HOST_KEYS
@SuppressWarnings({"StringSplitter", "ArrayRecordComponent"})
public final class SSHKnownHosts {

    static final String CERT_AUTHORITY = "cert-authority";
    static final String REVOKED = "revoked";

    private static final Pattern PATTERN = Pattern.compile(
            "^(?:@(?<marker>\\S+)\\s+)?" +
                    "(?<hostnames>(?:\"[^\"\\s]+\"|\\S+)(?:,(?:\"[^\"\\s]+\"|\\S+))*)" +
                    "\\s+(?<keyType>\\S+)\\s+" +
                    "(?<key>\\S+)" +
                    "(?:\\s+(?<comment>.*))?$"
    );

    final LinedConfigFile<HostsFileEntry> config;

    public SSHKnownHosts(List<String> lines) {
        config = new LinedConfigFile<>(lines, SSHKnownHosts::parseLine);
    }

    public interface HostsFileEntry {
        String toNormalizedString();

        boolean matches(String name);

        SSHIdentity key();
    }

    public List<HostsFileEntry> matchByName(String name) {
        return config.entries().filter(e -> e.matches(name)).toList();
    }

    public static SSHKnownHosts parse(String s) throws IOException {
        return new SSHKnownHosts(s.lines().toList());
    }

    public static SSHKnownHosts load(Path p) throws IOException {
        return new SSHKnownHosts(Files.readAllLines(p));
    }


    public static HostsFileEntry parseLine(String line) {
        var matcher = PATTERN.matcher(line.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("does not match pattern: " + line);
        }

        var marker = matcher.group("marker");
        // Parse hostnames, handling quoted entries
        var hostnamesStr = matcher.group("hostnames");
        var keyTypeStr = matcher.group("keyType");
        var keyStr = matcher.group("key");

        if (hostnamesStr == null || keyTypeStr == null || keyStr == null) {
            throw new IllegalArgumentException("host/type/key is null: " + line);
        }

        var commentStr = matcher.group("comment");
        var k = SSHPublicKey.ofTypeFromBytes(keyTypeStr, Helpers.base64(keyStr)).withComment(commentStr);

        if (hostnamesStr.startsWith("|1|")) {
            var parts = hostnamesStr.split("\\|");
            if (parts.length == 4) {  // Format: |1|salt|hash
                var salt = Base64.getDecoder().decode(parts[2]);
                var hash = Base64.getDecoder().decode(parts[3]);
                return new HashedHostEntry(line, 1, salt, hash, k);
            } else {
                throw new IllegalArgumentException("invalid number of parts in hashed hostname");
            }
        } else {
            var hosts = Arrays.stream(hostnamesStr.split(","))
                    .map(SSHPatternMatcher::unquoteIfNeeded)
                    .toList();

            if (marker != null) {
                return switch (marker) {
                    case CERT_AUTHORITY -> new CertAuthorityEntry(line, hosts, k);
                    case REVOKED -> new RevokedKeyEntry(line, hosts, k);
                    default -> throw new IllegalArgumentException("unknown marker " + marker);
                };
            } else {
                return new KnownHostsEntry(line, hosts, k);
            }
        }
    }

    record HashedHostEntry(String line, int version, byte[] salt, byte[] hash,
                           SSHIdentity key) implements HostsFileEntry {
        @Override
        public boolean matches(String host) {
            try {
                var mac = Mac.getInstance("HmacSHA1");
                mac.init(new SecretKeySpec(salt, "HmacSHA1"));
                var computedHash = mac.doFinal(host.getBytes(StandardCharsets.US_ASCII));
                return Arrays.equals(hash, computedHash);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String toNormalizedString() {
            return "|%d|%s|%s %s".formatted(version, Helpers.base64(salt), Helpers.base64(hash), key.asString());
        }
    }

    public record KnownHostsEntry(String line, List<String> hosts,
                                  SSHIdentity key) implements HostsFileEntry {

        @Override
        public String toNormalizedString() {
            return String.join(",", hosts) +
                    " " + key.asString();
        }

        @Override
        public boolean matches(String name) {
            return SSHPatternMatcher.matches(name, hosts());
        }
    }

    public record RevokedKeyEntry(String line, List<String> hosts,
                                  SSHIdentity key) implements HostsFileEntry {
        @Override
        public String toNormalizedString() {
            return "@" + REVOKED + " " +
                    String.join(",", hosts) +
                    " " + key.asString();
        }

        @Override
        public boolean matches(String name) {
            // TODO: implement
            return SSHPatternMatcher.matches(name, hosts());
        }
    }

    public record CertAuthorityEntry(String line, List<String> hosts,
                                     SSHIdentity key) implements HostsFileEntry {
        @Override
        public String toNormalizedString() {
            return "@" + CERT_AUTHORITY + " " +
                    String.join(",", hosts) +
                    " " + key.asString();
        }

        @Override
        public boolean matches(String name) {
            // TODO: implement
            return SSHPatternMatcher.matches(name, hosts());
        }
    }

    // Return a tidy version of the config file.
    public String tidy() {
        return String.join("\n", config.entries().map(HostsFileEntry::toNormalizedString).toList());
    }

    public boolean isPattern(String s) {
        return s.contains("*") || s.contains("?");
    }

    public boolean isIP(String s) {
        return s.matches("^[0-9a-fA-F:.]+$");
    }

    public Set<String> findNames(SSHIdentity identity) {
        return config.entries().filter(KnownHostsEntry.class::isInstance)
                .map(KnownHostsEntry.class::cast)
                .filter(h -> h.key().equals(identity))
                .map(KnownHostsEntry::hosts)
                .flatMap(List::stream).sorted((h1, h2) -> {
                    int t1 = isIP(h1) ? 1 : isPattern(h1) ? 2 : 0;
                    int t2 = isIP(h2) ? 1 : isPattern(h2) ? 2 : 0;
                    return t1 != t2 ? t1 - t2 : h2.length() - h1.length();
                }).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public Set<String> reverseHostNames(SSHIdentity identity) {
        return Set.of("NOTIMPLEMENTED");
    }

    public LinedConfigFile<HostsFileEntry> getConfig() {
        return config;
    }

    @Override
    public String toString() {
        // TLC: this .count() approach is not very efficient
        return "[known_hosts file with %d entries]".formatted(config.entries().count());
    }
}

// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.utils.Helpers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static pro.javacard.ssh.openssh.SSHPatternMatcher.quote;
import static pro.javacard.ssh.openssh.SSHPatternMatcher.unquoteIfNeeded;

// See https://man.openbsd.org/ssh-keygen.1#ALLOWED_SIGNERS
@SuppressWarnings("StringSplitter")
public final class SSHAllowedSigners {

    private static final Logger log = Logger.getLogger(SSHAllowedSigners.class.getName());

    // NOTE: proprietary options are actively rejected by OpenSSH tools
    static final String NAMESPACES = "namespaces";
    static final String VALID_AFTER = "valid-after";
    static final String VALID_BEFORE = "valid-before";
    static final String CERT_AUTHORITY = "cert-authority";

    final LinedConfigFile<AllowedSignersEntry> config;

    public LinedConfigFile<AllowedSignersEntry> getConfig() {
        return config;
    }

    public sealed interface AllowedSignersEntry permits KeyEntry, CertAuthorityEntry {
        List<String> principals();

        Set<Option<?>> options();

        SSHIdentity key();

        default <T extends Option<V>, V> Optional<T> getOption(Class<T> cls) {
            return options().stream()
                    .filter(cls::isInstance)
                    .map(cls::cast)
                    .findFirst();
        }
    }

    public record KeyEntry(
            List<String> principals,
            Set<Option<?>> options,
            SSHIdentity key) implements AllowedSignersEntry {
    }

    public record CertAuthorityEntry(
            List<String> principals,
            Set<Option<?>> options,
            SSHIdentity key) implements AllowedSignersEntry {
    }

    public sealed interface Option<T> permits
            Option.CertAuthority,
            Option.Namespaces,
            Option.ValidAfter,
            Option.ValidBefore,
            Option.Unknown {

        String name();

        default Optional<T> getValue() {
            return Optional.empty();
        }

        record CertAuthority() implements Option<Void> {
            @Override
            public String name() {
                return CERT_AUTHORITY;
            }

            @Override
            public String toString() {
                return name();
            }
        }

        record Namespaces(List<String> values) implements Option<List<String>> {
            @Override
            public String name() {
                return NAMESPACES;
            }

            @Override
            public Optional<List<String>> getValue() {
                return Optional.of(values);
            }

            public static Namespaces parse(String value) {
                return new Namespaces(Arrays.stream(value.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isBlank()) // NOTE: this should be invalid.
                        .toList());
            }

            @Override
            public String toString() {
                return String.format("%s=%s", NAMESPACES, quote(String.join(",", values)));
            }
        }

        record ValidAfter(ZonedDateTime timestamp) implements Option<ZonedDateTime> {
            @Override
            public String name() {
                return VALID_AFTER;
            }

            @Override
            public Optional<ZonedDateTime> getValue() {
                return Optional.of(timestamp);
            }

            @Override
            public String toString() {
                return String.format("%s=%s", VALID_AFTER, quote(formatTimestamp(timestamp)));
            }
        }

        record ValidBefore(ZonedDateTime timestamp) implements Option<ZonedDateTime> {
            @Override
            public String name() {
                return VALID_BEFORE;
            }

            @Override
            public Optional<ZonedDateTime> getValue() {
                return Optional.of(timestamp);
            }

            @Override
            public String toString() {
                return String.format("%s=%s", VALID_BEFORE, quote(formatTimestamp(timestamp)));
            }
        }

        // NOTE: not really a possibility, as noted above
        record Unknown(String name, String value) implements Option<String> {
            @Override
            public String name() {
                return name;
            }

            @Override
            public Optional<String> getValue() {
                return Optional.ofNullable(value);
            }

            @Override
            public String toString() {
                return getValue().map(value -> name + "=" + quote(value)).orElse(name);
            }
        }

        static Option<?> parse(String name, String value) {
            // NOTE: options are case-insensitive
            return switch (name.toLowerCase(Locale.ENGLISH)) {
                case CERT_AUTHORITY -> new CertAuthority();
                case NAMESPACES -> Namespaces.parse(value);
                case VALID_AFTER -> new ValidAfter(parseTimestamp(value));
                case VALID_BEFORE -> new ValidBefore(parseTimestamp(value));
                default -> new Unknown(name, value); // NOTE: could throw, for compatibility with OpenSSH
            };
        }
    }

    private SSHAllowedSigners(List<String> lines) {
        config = new LinedConfigFile<>(lines, SSHAllowedSigners::parseLine);
    }

    public static SSHAllowedSigners parse(String s) throws IOException {
        return new SSHAllowedSigners(s.lines().toList());
    }

    public static SSHAllowedSigners load(Path p) throws IOException {
        return new SSHAllowedSigners(Files.readAllLines(p));
    }

    private static boolean possiblyOptions(String s) {
        s = s.toLowerCase(Locale.ENGLISH);
        for (var p : Set.of(CERT_AUTHORITY, NAMESPACES, VALID_BEFORE, VALID_AFTER)) {
            if (s.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    public static AllowedSignersEntry parseLine(String line) {
        // Split preserving quoted strings
        var PARTS_PATTERN = Pattern.compile("\"[^\"]*\"|\\S+");
        var matcher = PARTS_PATTERN.matcher(line);
        var parts = new ArrayList<String>();

        while (matcher.find()) {
            var part = matcher.group();
            parts.add(unquoteIfNeeded(part));
        }

        if (parts.size() < 3) {
            throw new IllegalArgumentException("Line must contain at least principals, key type, and key");
        }

        var principals = Arrays.stream(parts.get(0).split(","))
                .map(String::trim)
                .filter(Predicate.not(String::isEmpty))
                .toList();

        if (principals.isEmpty()) {
            throw new IllegalArgumentException("At least one principal must be specified");
        }


        var offset = 1;
        final Set<Option<?>> options;
        // If next part isn't a key type, it must be options
        if (possiblyOptions(parts.get(1))) {
            options = parseOptions(parts.get(1));
            offset = 2;
        } else {
            options = Set.of();
        }

        var type = parts.get(offset);
        var b64 = parts.get(offset + 1);
        var k = SSHPublicKey.ofTypeFromBytes(type, Helpers.base64(b64));

        // XXX: spec does not allow comments, and we would mangle the format by removing whitespace.
        if (parts.size() > offset + 2) {
            log.warning("Comments are not supported in allowed signers file: " + line);
        }
        if (options.contains(new Option.CertAuthority()))
            return new CertAuthorityEntry(principals, options, k);
        return new KeyEntry(principals, options, k);
    }

    private static Set<Option<?>> parseOptions(String optStr) {
        var options = new LinkedHashSet<Option<?>>();
        var optParts = optStr.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
        //System.out.println("optParts: " + String.join(",", optParts));
        for (var opt : optParts) {
            var parts = opt.split("=", 2);
            var name = parts[0].trim();
            var value = parts.length > 1 ? parts[1].trim() : null;
            options.add(Option.parse(name, unquoteIfNeeded(value)));
        }
        return options;
    }

    public static ZonedDateTime parseTimestamp(String timestamp) {

        var isUtc = timestamp.endsWith("Z");
        var zone = isUtc ? ZoneOffset.UTC : ZoneId.systemDefault();

        // Strip Z if present
        var cleanTimestamp = isUtc ? timestamp.substring(0, timestamp.length() - 1) : timestamp;

        var format = switch (cleanTimestamp.length()) {
            case 8 -> DateTimeFormatter.ofPattern("yyyyMMdd");
            case 12 -> DateTimeFormatter.ofPattern("yyyyMMddHHmm");
            case 14 -> DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
            default -> throw new IllegalArgumentException("Invalid timestamp format: " + timestamp);
        };

        try {
            var dateTime = switch (cleanTimestamp.length()) {
                // NOTE: LocalTime.MIN implies that any now().isAfter() matches the after date
                // and now().isBefore() never matches the before date
                case 8 -> LocalDateTime.of(LocalDate.parse(cleanTimestamp, format), LocalTime.MIN);
                default -> LocalDateTime.parse(cleanTimestamp, format);
            };
            return dateTime.atZone(zone);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Failed to parse timestamp: " + timestamp, e);
        }
    }

    public static String formatTimestamp(ZonedDateTime timestamp) {
        String pattern;
        if (timestamp.getSecond() == 0 && timestamp.getHour() == 0 && timestamp.getMinute() == 0) {
            pattern = timestamp.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        } else if (timestamp.getSecond() == 0) {
            pattern = timestamp.format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));
        } else {
            pattern = timestamp.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        }

        if (timestamp.getZone().equals(ZoneOffset.UTC)) {
            pattern = pattern + "'Z'";
        }
        return timestamp.format(DateTimeFormatter.ofPattern(pattern));
    }

    // Get all valid entries at a given time, matching both principal and namespace
    public List<AllowedSignersEntry> validEntries(String principal, String namespace, Clock clock) {
        var now = clock.instant().atZone(clock.getZone());
        return config.entries()
                .filter(e -> principal == null || SSHPatternMatcher.matches(principal, e.principals()))
                .filter(e -> e.getOption(Option.Namespaces.class)
                        .map(ns -> SSHPatternMatcher.matches(namespace, ns.values()))
                        .orElse(true))
                .filter(e -> e.getOption(Option.ValidAfter.class)
                        .map(t -> t.timestamp().isBefore(now))
                        .orElse(true))
                .filter(e -> e.getOption(Option.ValidBefore.class)
                        .map(t -> t.timestamp().isAfter(now))
                        .orElse(true))
                .collect(Collectors.toList());
    }

    public List<AllowedSignersEntry> validEntries(String namespace, Clock clock) {
        return validEntries(null, namespace, clock);
    }
}
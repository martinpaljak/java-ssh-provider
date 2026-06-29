// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import pro.javacard.ssh.openssh.LinedConfigFile.ParseResult.Comment;
import pro.javacard.ssh.openssh.LinedConfigFile.ParseResult.Invalid;
import pro.javacard.ssh.openssh.LinedConfigFile.ParseResult.Valid;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

// Like ~/.ssh/known_keys or allowed_signers, that has one element per line
// This class helps to have two-way lossless interactions with it.
public final class LinedConfigFile<T> implements Collection<LinedConfigFile.ParseResult<T>> {

    @FunctionalInterface
    public interface LineParser<T> {
        T parse(String line);
    }

    // Sealed interface for parse results
    public sealed interface ParseResult<T> {

        String line();

        record Valid<T>(T value, String line) implements ParseResult<T> {
            @Override
            public String toString() {
                return String.format("%s[%s]", value.getClass().getSimpleName(), line);
            }
        }

        record Comment<T>(String line) implements ParseResult<T> {
            @Override
            public String toString() {
                return String.format("%s[%s]", this.getClass().getSimpleName(), line);
            }
        }

        record Invalid<T>(String reason, String line) implements ParseResult<T> {
            @Override
            public String toString() {
                return String.format("%s[reason=%s, %s]", this.getClass().getSimpleName(), reason, line);
            }
        }
    }

    public LinedConfigFile(List<String> lines, LineParser<T> lineParser) {
        for (String line : lines) {
            if (line.trim().isEmpty() || line.trim().startsWith("#")) {
                add(new Comment<>(line));
            } else {
                try {
                    add(new Valid<>(lineParser.parse(line), line));
                } catch (IllegalArgumentException e) {
                    add(new Invalid<>(e.getMessage(), line));
                }
            }
        }
    }

    private final List<ParseResult<T>> lines = new ArrayList<>();

    @Override
    public int size() {
        return lines.size();
    }

    @Override
    public boolean isEmpty() {
        return lines.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return lines.contains(o);
    }

    @Override
    public Iterator<ParseResult<T>> iterator() {
        return lines.iterator();
    }

    @Override
    public Object[] toArray() {
        return lines.toArray();
    }

    @Override
    public <T1> T1[] toArray(T1[] a) {
        return lines.toArray(a);
    }

    @Override
    public boolean add(ParseResult<T> t) {
        return lines.add(t);
    }

    @Override
    public boolean remove(Object o) {
        return lines.remove(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return lines.containsAll(c);
    }

    @Override
    public boolean addAll(Collection<? extends ParseResult<T>> c) {
        return lines.addAll(c);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return lines.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return lines.retainAll(c);
    }

    @Override
    public void clear() {
        lines.clear();
    }

    @Override
    public String toString() {
        // NOTE: we append the final newline.
        return String.join("\n", lines.stream().map(ParseResult::line).toList()) + "\n";
    }


    public Stream<T> entries() {
        return lines.stream()
                .filter(Valid.class::isInstance)
                .map(line -> ((Valid<T>) line).value());
    }

}

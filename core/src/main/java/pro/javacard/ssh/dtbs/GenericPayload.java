// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.dtbs;

@SuppressWarnings("ArrayRecordComponent")
public record GenericPayload(byte[] dtbs) implements DTBSPayload<GenericPayload> {

    public static final Parser<GenericPayload> PARSER = src -> {
        byte[] dtbs = new byte[src.remaining()];
        src.get(dtbs);
        return new GenericPayload(dtbs);
    };

    @Override
    public String pattern() {
        return "generic";
    }
}

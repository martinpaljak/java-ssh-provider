// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
module pro.javacard.ssh.provider {
    provides java.security.Provider with pro.javacard.ssh.provider.SSHProvider;
    exports pro.javacard.ssh.provider;

    requires transitive pro.javacard.ssh;
    requires java.logging;
}